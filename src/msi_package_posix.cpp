#include "msi_package.hpp"
#include "platform.hpp"

#include <libmsi.h>
#include <libgcab.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <unordered_map>

namespace platform {
namespace {
struct Unref { void operator()(void *p) const { if (p) g_object_unref(p); } };
template<class T> using Object = std::unique_ptr<T, Unref>;
struct Error {
    GError *value = nullptr;
    ~Error() { if (value) g_error_free(value); }
    operator GError **() { return &value; }
    void check(bool success, const std::string &op) const {
        if (!success) throw std::runtime_error(op + ": " + (value ? value->message : "operation failed"));
    }
};
Object<LibmsiRecord> parameters(const std::vector<MsiValue> &params) {
    Object<LibmsiRecord> record(libmsi_record_new(unsigned(params.size())));
    if (!record) throw std::runtime_error("allocate MSI record");
    for (size_t i = 0; i < params.size(); ++i) {
        bool ok;
        if (auto v = std::get_if<int32_t>(&params[i])) ok = libmsi_record_set_int(record.get(), unsigned(i + 1), *v);
        else if (auto v = std::get_if<std::string>(&params[i])) ok = libmsi_record_set_string(record.get(), unsigned(i + 1), v->c_str());
        else ok = libmsi_record_load_stream(record.get(), unsigned(i + 1), std::get<MsiStreamPath>(params[i]).path.c_str());
        if (!ok) throw std::runtime_error("set MSI query parameter " + std::to_string(i + 1));
    }
    return record;
}
Object<LibmsiQuery> prepare(void *db, const std::string &sql, const std::vector<MsiValue> &params) {
    Error error;
    Object<LibmsiQuery> query(libmsi_query_new(static_cast<LibmsiDatabase *>(db), sql.c_str(), error));
    error.check(bool(query), "MSI query " + sql);
    auto record = parameters(params);
    error.check(libmsi_query_execute(query.get(), record.get(), error), "MSI execute " + sql);
    return query;
}
Object<LibmsiSummaryInfo> summary(void *db, unsigned updates = 0) {
    Error error;
    Object<LibmsiSummaryInfo> si(libmsi_summary_info_new(static_cast<LibmsiDatabase *>(db), updates, error));
    error.check(bool(si), "read MSI summary information");
    return si;
}
Object<GFileInputStream> open_input(const std::string &path) {
    Object<GFile> file(g_file_new_for_path(path.c_str()));
    Error error;
    Object<GFileInputStream> input(g_file_read(file.get(), nullptr, error));
    error.check(bool(input), "read " + path);
    return input;
}
Object<GFileOutputStream> open_output(const std::string &path) {
    Object<GFile> file(g_file_new_for_path(path.c_str()));
    Error error;
    Object<GFileOutputStream> output(g_file_replace(file.get(), nullptr, false, G_FILE_CREATE_PRIVATE, nullptr, error));
    error.check(bool(output), "write " + path);
    return output;
}
} // namespace

MsiDatabase::MsiDatabase(const std::string &path) : path_(path) {
    Error error;
    impl_ = libmsi_database_new(path.c_str(), LIBMSI_DB_FLAGS_TRANSACT, nullptr, error);
    error.check(impl_ != nullptr, "open MSI database " + path);
}
MsiDatabase::~MsiDatabase() { g_object_unref(impl_); }
MsiRows MsiDatabase::query(const std::string &sql, const std::vector<MsiValue> &params) {
    auto view = prepare(impl_, sql, params);
    Error error;
    MsiRows rows;
    for (;;) {
        Object<LibmsiRecord> record(libmsi_query_fetch(view.get(), error));
        error.check(!error.value, "fetch MSI row: " + sql);
        if (!record) break;
        if (rows.size() >= 65535) throw std::runtime_error("MSI query exceeds 65535 rows: " + sql);
        std::vector<std::string> row;
        for (unsigned i = 1; i <= libmsi_record_get_field_count(record.get()); ++i) {
            char *text = libmsi_record_get_string(record.get(), i);
            row.emplace_back(text ? text : ""); g_free(text);
        }
        rows.push_back(std::move(row));
    }
    return rows;
}
void MsiDatabase::execute(const std::string &sql, const std::vector<MsiValue> &params) { prepare(impl_, sql, params); }
uint64_t MsiDatabase::extract_stream(const std::string &sql, const std::string &key, const std::string &output, uint64_t limit) {
    auto view = prepare(impl_, sql, {key});
    Error error;
    Object<LibmsiRecord> record(libmsi_query_fetch(view.get(), error));
    error.check(bool(record), "read MSI stream " + key);
    Object<GInputStream> input(libmsi_record_get_stream(record.get(), 1));
    error.check(bool(input), "open MSI stream " + key);
    auto out = open_output(output);
    uint64_t total = 0;
    std::array<uint8_t, 65536> buffer;
    for (;;) {
        const auto n = g_input_stream_read(input.get(), buffer.data(), buffer.size(), nullptr, error);
        error.check(n >= 0, "read MSI stream " + key);
        if (!n) break;
        if (uint64_t(n) > limit - total) throw std::runtime_error("MSI stream exceeds extraction limit: " + key);
        total += uint64_t(n);
        error.check(g_output_stream_write_all(G_OUTPUT_STREAM(out.get()), buffer.data(), size_t(n), nullptr, nullptr, error), "extract MSI stream " + key);
    }
    error.check(g_output_stream_close(G_OUTPUT_STREAM(out.get()), nullptr, error), "close " + output);
    Object<LibmsiRecord> duplicate(libmsi_query_fetch(view.get(), error));
    error.check(!duplicate && !error.value, "ambiguous MSI stream " + key);
    return total;
}
int32_t MsiDatabase::word_count() {
    auto si = summary(impl_); Error error;
    const auto value = libmsi_summary_info_get_int(si.get(), LIBMSI_PROPERTY_SOURCE, error);
    error.check(!error.value, "read MSI source compression flags");
    return value;
}
std::string MsiDatabase::package_code() {
    auto si = summary(impl_); Error error;
    const auto value = libmsi_summary_info_get_string(si.get(), LIBMSI_PROPERTY_UUID, error);
    error.check(value != nullptr, "read MSI PackageCode");
    return value;
}
void MsiDatabase::renew_package_code() {
    auto si = summary(impl_, 1); Error error;
    char *uuid = g_uuid_string_random();
    char *upper = g_ascii_strup(uuid, -1); g_free(uuid);
    const std::string value = "{" + std::string(upper) + "}"; g_free(upper);
    error.check(libmsi_summary_info_set_string(si.get(), LIBMSI_PROPERTY_UUID, value.c_str(), error), "set MSI PackageCode");
    error.check(libmsi_summary_info_persist(si.get(), error), "persist MSI summary information");
}
void MsiDatabase::commit() {
    Error error;
    error.check(libmsi_database_commit(static_cast<LibmsiDatabase *>(impl_), error), "commit MSI database " + path_);
}

void extract_cabinet(const std::string &path, const std::vector<CabinetMember> &members) {
    auto input = open_input(path);
    Object<GCabCabinet> cab(gcab_cabinet_new()); Error error;
    gcab_cabinet_add_allowed_compression(cab.get(), GCAB_COMPRESSION_NONE);
    gcab_cabinet_add_allowed_compression(cab.get(), GCAB_COMPRESSION_MSZIP);
    gcab_cabinet_add_allowed_compression(cab.get(), GCAB_COMPRESSION_LZX);
    error.check(gcab_cabinet_load(cab.get(), G_INPUT_STREAM(input.get()), nullptr, error), "load cabinet " + path);
    std::unordered_map<std::string, const CabinetMember *> expected;
    for (const auto &member : members) expected.emplace(member.name, &member);
    auto folders = gcab_cabinet_get_folders(cab.get());
    size_t count = 0;
    for (unsigned i = 0; i < folders->len; ++i) {
        auto folder = GCAB_FOLDER(g_ptr_array_index(folders, i));
        for (auto item = gcab_folder_get_files(folder); item; item = item->next) {
            auto file = GCAB_FILE(item->data);
            auto it = expected.find(gcab_file_get_name(file));
            if (it == expected.end() || gcab_file_get_size(file) != it->second->size)
                throw std::runtime_error("cabinet metadata mismatch: " + path);
            // Absolute generated filenames ensure the library never interprets
            // an untrusted archive name as a destination filesystem path.
            gcab_file_set_extract_name(file, it->second->path.c_str());
            expected.erase(it); ++count;
        }
    }
    if (!expected.empty() || count != members.size()) throw std::runtime_error("missing cabinet member: " + path);
    Object<GFile> root(g_file_new_for_path("/"));
    error.check(gcab_cabinet_extract_simple(cab.get(), root.get(), nullptr, nullptr, nullptr, error), "extract cabinet " + path);
}
void create_cabinet(const std::string &path, const std::vector<CabinetMember> &members) {
    Object<GCabCabinet> cab(gcab_cabinet_new());
    Object<GCabFolder> folder(gcab_folder_new(GCAB_COMPRESSION_MSZIP)); Error error;
    for (const auto &member : members) {
        Object<GFile> input(g_file_new_for_path(member.path.c_str()));
        Object<GCabFile> file(gcab_file_new_with_file(member.name.c_str(), input.get()));
        error.check(bool(file), "create cabinet member " + member.name);
        error.check(gcab_folder_add_file(folder.get(), file.get(), false, nullptr, error), "add cabinet member " + member.name);
        gcab_file_set_attributes(file.get(), member.attributes);
        auto date = g_date_time_new_utc(1980 + (member.date >> 9), (member.date >> 5) & 15, member.date & 31,
                                       member.time >> 11, (member.time >> 5) & 63, (member.time & 31) * 2);
        if (date) { gcab_file_set_date_time(file.get(), date); g_date_time_unref(date); }
    }
    error.check(gcab_cabinet_add_folder(cab.get(), folder.get(), error), "add cabinet folder");
    auto out = open_output(path);
    error.check(gcab_cabinet_write_simple(cab.get(), G_OUTPUT_STREAM(out.get()), nullptr, nullptr, nullptr, error), "rebuild cabinet " + path);
    error.check(g_output_stream_close(G_OUTPUT_STREAM(out.get()), nullptr, error), "close cabinet " + path);
}
std::array<int32_t, 4> msi_file_hash(const std::string &path) {
    // Windows Installer's whole-file MD5, interpreted as four little-endian
    // DWORDs. Empty files are the MSI-specific all-zero hash, not MD5(empty).
    File file(path); const auto length = file.size();
    if (!length) return {};
    std::unique_ptr<GChecksum, decltype(&g_checksum_free)> hash(g_checksum_new(G_CHECKSUM_MD5), g_checksum_free);
    std::array<uint8_t, 65536> buffer;
    for (uint64_t offset = 0; offset < length;) {
        const auto n = size_t(std::min<uint64_t>(buffer.size(), length - offset));
        file.read_at(offset, buffer.data(), n); offset += n;
        g_checksum_update(hash.get(), buffer.data(), n);
    }
    std::array<uint8_t, 16> digest; gsize size = digest.size();
    g_checksum_get_digest(hash.get(), digest.data(), &size);
    std::array<int32_t, 4> result;
    for (size_t i = 0; i < 4; ++i) {
        const auto *p = digest.data() + i * 4;
        uint32_t value = uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
        std::memcpy(&result[i], &value, sizeof(value));
    }
    return result;
}
} // namespace platform
