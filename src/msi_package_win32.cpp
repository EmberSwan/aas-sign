#include "msi_package.hpp"
#include "platform.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <fdi.h>
#include <fci.h>
#include <rpc.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>

namespace platform {
namespace {
std::wstring wide(const std::string &s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), int(s.size()), nullptr, 0);
    if (!n) throw std::runtime_error("invalid UTF-8 MSI path or identifier");
    std::wstring result(n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), int(s.size()), result.data(), n);
    return result;
}
std::string utf8(const std::wstring &s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0, nullptr, nullptr);
    std::string result(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), int(s.size()), result.data(), n, nullptr, nullptr);
    return result;
}
void check(UINT result, const std::string &op) {
    if (result == ERROR_SUCCESS) return;
    LPWSTR message = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, result, 0, reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    std::string reason = message ? utf8(message) : "error " + std::to_string(result);
    if (message) LocalFree(message);
    throw std::runtime_error(op + ": " + reason);
}
struct Handle {
    MSIHANDLE value = 0;
    Handle() = default;
    explicit Handle(MSIHANDLE h) : value(h) {}
    Handle(const Handle &) = delete;
    Handle(Handle &&other) noexcept : value(other.value) { other.value = 0; }
    ~Handle() { if (value) MsiCloseHandle(value); }
};
MSIHANDLE database(void *impl) { return static_cast<Handle *>(impl)->value; }
Handle parameters(const std::vector<MsiValue> &params) {
    Handle record(MsiCreateRecord(unsigned(params.size())));
    if (!record.value) throw std::runtime_error("allocate MSI record");
    for (size_t i = 0; i < params.size(); ++i) {
        UINT result;
        if (auto v = std::get_if<int32_t>(&params[i])) result = MsiRecordSetInteger(record.value, unsigned(i + 1), *v);
        else if (auto v = std::get_if<std::string>(&params[i])) result = MsiRecordSetStringW(record.value, unsigned(i + 1), wide(*v).c_str());
        else result = MsiRecordSetStreamW(record.value, unsigned(i + 1), wide(std::get<MsiStreamPath>(params[i]).path).c_str());
        check(result, "set MSI query parameter");
    }
    return record;
}
Handle prepare(void *impl, const std::string &sql, const std::vector<MsiValue> &params) {
    Handle view;
    check(MsiDatabaseOpenViewW(database(impl), wide(sql).c_str(), &view.value), "MSI query " + sql);
    auto record = parameters(params);
    check(MsiViewExecute(view.value, record.value), "MSI execute " + sql);
    return view;
}
std::string field(MSIHANDLE record, UINT index) {
    DWORD length = 0; wchar_t empty = 0;
    auto result = MsiRecordGetStringW(record, index, &empty, &length);
    if (result != ERROR_MORE_DATA) check(result, "read MSI field");
    std::wstring value(size_t(length) + 1, L'\0'); ++length;
    check(MsiRecordGetStringW(record, index, value.data(), &length), "read MSI field");
    value.resize(length);
    return utf8(value);
}
Handle summary(void *impl, UINT updates = 0) {
    Handle si;
    check(MsiGetSummaryInformationW(database(impl), nullptr, updates, &si.value), "read MSI summary information");
    return si;
}

struct CabinetContext {
    std::string cabinet;
    std::string directory;
    std::string error;
    std::map<std::string, const CabinetMember *> members;
    std::map<int, uint64_t> remaining;
    std::set<std::string> extracted;
    std::set<int> handles;
    std::map<std::string, std::string> aliases;
    size_t temporary = 0;
    explicit CabinetContext(const std::string &path) : cabinet(path), directory(path.substr(0, path.find_last_of("/\\") + 1)) {}
    ~CabinetContext() {
        for (int fd : handles) _close(fd);
        for (const auto &[name, path] : aliases) if (name.starts_with("tmp-")) {
            try { DeleteFileW(wide(path).c_str()); } catch (...) {}
        }
    }
    int open(const char *name, int flags, int mode) {
        auto it = aliases.find(name);
        const auto path = it == aliases.end() ? std::string(name) : it->second;
        const int fd = _wopen(wide(path).c_str(), flags | _O_BINARY, mode);
        if (fd >= 0) handles.insert(fd);
        else error = "open cabinet file " + path + ": " + std::strerror(errno);
        return fd;
    }
    int close(int fd) { remaining.erase(fd); handles.erase(fd); return _close(fd); }
};
// FDI's low-level callbacks do not carry a context. A scoped thread-local pointer
// keeps independent top-level signing workers isolated; callbacks are synchronous.
thread_local CabinetContext *fdi_context = nullptr;
struct FdiScope {
    CabinetContext *previous;
    explicit FdiScope(CabinetContext &context) : previous(fdi_context) { fdi_context = &context; }
    ~FdiScope() { fdi_context = previous; }
};
void *DIAMONDAPI alloc(ULONG size) { return std::malloc(size); }
void DIAMONDAPI release(void *p) { std::free(p); }
INT_PTR DIAMONDAPI fdi_open(char *name, int flags, int mode) {
    try { return fdi_context->open(name, flags, mode); }
    catch (const std::exception &e) { fdi_context->error = e.what(); return -1; }
}
UINT DIAMONDAPI cab_read(INT_PTR fd, void *buffer, UINT size) { return UINT(_read(int(fd), buffer, size)); }
UINT DIAMONDAPI fdi_write(INT_PTR fd, void *buffer, UINT size) {
    auto it = fdi_context->remaining.find(int(fd));
    if (it == fdi_context->remaining.end() || size > it->second) {
        fdi_context->error = "cabinet member exceeds declared size"; return UINT(-1);
    }
    const int n = _write(int(fd), buffer, size);
    if (n > 0) it->second -= unsigned(n);
    return UINT(n);
}
int DIAMONDAPI fdi_close(INT_PTR fd) { return fdi_context->close(int(fd)); }
long DIAMONDAPI cab_seek(INT_PTR fd, long offset, int origin) { return _lseek(int(fd), offset, origin); }
INT_PTR DIAMONDAPI notify(FDINOTIFICATIONTYPE type, PFDINOTIFICATION info) {
    auto &ctx = *static_cast<CabinetContext *>(info->pv);
    try {
        if (type == fdintCOPY_FILE) {
            auto it = ctx.members.find(info->psz1);
            if (it == ctx.members.end() || !ctx.extracted.insert(info->psz1).second || info->cb != long(it->second->size))
                throw std::runtime_error("cabinet member mapping mismatch");
            const int fd = ctx.open(it->second->path.c_str(), _O_CREAT | _O_EXCL | _O_WRONLY, _S_IREAD | _S_IWRITE);
            if (fd < 0) return -1;
            ctx.remaining.emplace(fd, it->second->size);
            return fd;
        }
        if (type == fdintCLOSE_FILE_INFO) {
            auto it = ctx.remaining.find(int(info->hf));
            if (it == ctx.remaining.end() || it->second) throw std::runtime_error("truncated cabinet member");
            return ctx.close(int(info->hf)) == 0;
        }
        if (type == fdintNEXT_CABINET || type == fdintPARTIAL_FILE) throw std::runtime_error("spanning cabinet is unsupported");
        return 0;
    } catch (const std::exception &e) { ctx.error = e.what(); return -1; }
}
INT_PTR DIAMONDAPI fci_open(char *name, int flags, int mode, int *error, void *pv) {
    auto &ctx = *static_cast<CabinetContext *>(pv);
    try { const int fd = ctx.open(name, flags, mode); if (fd < 0) *error = errno; return fd; }
    catch (const std::exception &e) { ctx.error = e.what(); *error = EIO; return -1; }
}
UINT DIAMONDAPI fci_read(INT_PTR fd, void *buffer, UINT size, int *error, void *) {
    const int result = _read(int(fd), buffer, size); if (result < 0) *error = errno; return UINT(result);
}
UINT DIAMONDAPI fci_write(INT_PTR fd, void *buffer, UINT size, int *error, void *) {
    const int result = _write(int(fd), buffer, size); if (result < 0) *error = errno; return UINT(result);
}
int DIAMONDAPI fci_close(INT_PTR fd, int *error, void *pv) {
    const int result = static_cast<CabinetContext *>(pv)->close(int(fd)); if (result < 0) *error = errno; return result;
}
long DIAMONDAPI fci_seek(INT_PTR fd, long offset, int origin, int *error, void *) {
    const long result = _lseek(int(fd), offset, origin); if (result < 0) *error = errno; return result;
}
int DIAMONDAPI fci_delete(char *name, int *error, void *pv) {
    auto &ctx = *static_cast<CabinetContext *>(pv);
    try {
        auto it = ctx.aliases.find(name);
        const int result = _wremove(wide(it == ctx.aliases.end() ? name : it->second).c_str());
        if (result < 0) *error = errno;
        return result;
    } catch (const std::exception &e) { ctx.error = e.what(); *error = EIO; return -1; }
}
BOOL DIAMONDAPI temporary(char *name, int capacity, void *pv) {
    auto &ctx = *static_cast<CabinetContext *>(pv);
    try {
        const auto alias = "tmp-" + std::to_string(ctx.temporary++);
        if (alias.size() >= size_t(capacity)) return FALSE;
        ctx.aliases.emplace(alias, ctx.directory + alias);
        std::memcpy(name, alias.c_str(), alias.size() + 1); return TRUE;
    } catch (const std::exception &e) { ctx.error = e.what(); return FALSE; }
}
int DIAMONDAPI placed(PCCAB, char *, long, BOOL, void *) { return 0; }
BOOL DIAMONDAPI next_cabinet(PCCAB, ULONG, void *pv) {
    static_cast<CabinetContext *>(pv)->error = "reconstructed cabinet would span multiple files"; return FALSE;
}
long DIAMONDAPI status(UINT, ULONG, ULONG, void *) { return 0; }
INT_PTR DIAMONDAPI open_info(char *name, USHORT *date, USHORT *time, USHORT *attributes, int *error, void *pv) {
    auto &ctx = *static_cast<CabinetContext *>(pv);
    auto it = ctx.members.find(name);
    if (it == ctx.members.end()) { *error = EINVAL; return -1; }
    *date = it->second->date; *time = it->second->time; *attributes = it->second->attributes;
    return fci_open(name, _O_RDONLY, 0, error, pv);
}
} // namespace

MsiDatabase::MsiDatabase(const std::string &path) : impl_(nullptr), path_(path) {
    auto handle = std::make_unique<Handle>();
    check(MsiOpenDatabaseW(wide(path).c_str(), reinterpret_cast<LPCWSTR>(1), &handle->value), "open MSI database " + path);
    impl_ = handle.release();
}
MsiDatabase::~MsiDatabase() { delete static_cast<Handle *>(impl_); }
MsiRows MsiDatabase::query(const std::string &sql, const std::vector<MsiValue> &params) {
    auto view = prepare(impl_, sql, params); MsiRows rows;
    for (;;) {
        Handle record; const auto result = MsiViewFetch(view.value, &record.value);
        if (result == ERROR_NO_MORE_ITEMS) break;
        check(result, "fetch MSI row: " + sql);
        if (rows.size() >= 65535) throw std::runtime_error("MSI query exceeds 65535 rows: " + sql);
        std::vector<std::string> row;
        for (unsigned i = 1; i <= MsiRecordGetFieldCount(record.value); ++i) row.push_back(field(record.value, i));
        rows.push_back(std::move(row));
    }
    return rows;
}
void MsiDatabase::execute(const std::string &sql, const std::vector<MsiValue> &params) { prepare(impl_, sql, params); }
uint64_t MsiDatabase::extract_stream(const std::string &sql, const std::string &key, const std::string &output, uint64_t limit) {
    auto view = prepare(impl_, sql, {key}); Handle record;
    check(MsiViewFetch(view.value, &record.value), "read MSI stream " + key);
    write_whole_file(output, nullptr, 0); File out(output);
    std::array<char, 65536> buffer; uint64_t total = 0;
    for (;;) {
        DWORD size = DWORD(buffer.size());
        check(MsiRecordReadStream(record.value, 1, buffer.data(), &size), "read MSI stream " + key);
        if (!size) break;
        if (size > limit - total) throw std::runtime_error("MSI stream exceeds extraction limit: " + key);
        out.write_at(total, buffer.data(), size); total += size;
    }
    out.flush(); Handle duplicate;
    const auto result = MsiViewFetch(view.value, &duplicate.value);
    if (result != ERROR_NO_MORE_ITEMS) { check(result, "read MSI stream " + key); throw std::runtime_error("ambiguous MSI stream " + key); }
    return total;
}
int32_t MsiDatabase::word_count() {
    auto si = summary(impl_); UINT type; INT value = 0;
    check(MsiSummaryInfoGetPropertyW(si.value, 15, &type, &value, nullptr, nullptr, nullptr), "read MSI compression flags");
    if (type != VT_I4 && type != VT_I2) throw std::runtime_error("MSI has no source compression flags");
    return value;
}
std::string MsiDatabase::package_code() {
    auto si = summary(impl_); UINT type; DWORD length = 0; wchar_t empty = 0;
    auto result = MsiSummaryInfoGetPropertyW(si.value, 9, &type, nullptr, nullptr, &empty, &length);
    if (result != ERROR_MORE_DATA) check(result, "read MSI PackageCode");
    std::wstring value(size_t(length) + 1, L'\0'); ++length;
    check(MsiSummaryInfoGetPropertyW(si.value, 9, &type, nullptr, nullptr, value.data(), &length), "read MSI PackageCode");
    value.resize(length); return utf8(value);
}
void MsiDatabase::renew_package_code() {
    auto si = summary(impl_, 1); UUID uuid;
    auto result = UuidCreate(&uuid);
    if (result != RPC_S_UUID_LOCAL_ONLY) check(result, "generate MSI PackageCode");
    RPC_WSTR value = nullptr; check(UuidToStringW(&uuid, &value), "format MSI PackageCode");
    std::wstring code = L"{" + std::wstring(reinterpret_cast<wchar_t *>(value)) + L"}";
    RpcStringFreeW(&value); CharUpperBuffW(code.data(), DWORD(code.size()));
    check(MsiSummaryInfoSetPropertyW(si.value, 9, VT_LPSTR, 0, nullptr, code.c_str()), "set MSI PackageCode");
    check(MsiSummaryInfoPersist(si.value), "persist MSI summary information");
}
void MsiDatabase::commit() { check(MsiDatabaseCommit(database(impl_)), "commit MSI database " + path_); }

void extract_cabinet(const std::string &path, const std::vector<CabinetMember> &members) {
    CabinetContext context(path); FdiScope scope(context);
    context.aliases.emplace("input.cab", path);
    for (const auto &member : members) context.members.emplace(member.name, &member);
    ERF error{};
    HFDI fdi = FDICreate(alloc, release, fdi_open, cab_read, fdi_write, fdi_close, cab_seek, cpuUNKNOWN, &error);
    if (!fdi) throw std::runtime_error("FDICreate: " + std::to_string(error.erfOper));
    char name[] = "input.cab", directory[] = "";
    const auto result = FDICopy(fdi, name, directory, 0, notify, nullptr, &context);
    FDIDestroy(fdi);
    if (!result || context.extracted.size() != members.size())
        throw std::runtime_error("extract cabinet " + path + ": " + (context.error.empty() ? "FDI error " + std::to_string(error.erfOper) : context.error));
}
void create_cabinet(const std::string &path, const std::vector<CabinetMember> &members) {
    CabinetContext context(path); context.aliases.emplace("output.cab", path);
    for (const auto &member : members) context.members.emplace(member.path, &member);
    CCAB config{}; config.cb = 0x7fffffff; config.cbFolderThresh = 0x7fffffff;
    std::strcpy(config.szCab, "output.cab");
    ERF error{};
    HFCI fci = FCICreate(&error, placed, alloc, release, fci_open, fci_read, fci_write, fci_close,
                         fci_seek, fci_delete, temporary, &config, &context);
    if (!fci) throw std::runtime_error("FCICreate: " + std::to_string(error.erfOper));
    bool success = true;
    for (const auto &member : members) {
        auto source = member.path, name = member.name;
        if (!FCIAddFile(fci, source.data(), name.data(), FALSE, next_cabinet, status, open_info, tcompTYPE_MSZIP)) { success = false; break; }
    }
    if (success) success = FCIFlushCabinet(fci, FALSE, next_cabinet, status);
    FCIDestroy(fci);
    if (!success) throw std::runtime_error("rebuild cabinet " + path + ": " + (context.error.empty() ? "FCI error " + std::to_string(error.erfOper) : context.error));
}
std::array<int32_t, 4> msi_file_hash(const std::string &path) {
    MSIFILEHASHINFO hash{}; hash.dwFileHashInfoSize = sizeof(hash);
    check(MsiGetFileHashW(wide(path).c_str(), 0, &hash), "hash MSI payload " + path);
    std::array<int32_t, 4> result;
    std::memcpy(result.data(), hash.dwData, sizeof(hash.dwData));
    return result;
}
} // namespace platform
