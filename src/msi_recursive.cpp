#include "msi_recursive.hpp"
#include "msi_package.hpp"
#include "platform.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>

namespace {
// Bounds apply across the entire installer, not independently to each cabinet.
constexpr uint64_t expansion_limit = 1024ULL * 1024 * 1024;
constexpr size_t member_limit = 65535;

[[noreturn]] void invalid(const std::string &reason) {
    throw std::runtime_error("recursive MSI: " + reason);
}
int32_t integer(const std::string &value) {
    if (value.empty()) return 0;
    int32_t result;
    auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), result);
    if (ec != std::errc{} || end != value.data() + value.size()) invalid("invalid integer in database");
    return result;
}
uint16_t u16(const uint8_t *p) { return uint16_t(p[0]) | uint16_t(p[1]) << 8; }
uint32_t u32(const uint8_t *p) { return uint32_t(u16(p)) | uint32_t(u16(p + 2)) << 16; }
bool safe_name(const std::string &name) {
    // CAB payload names are File table identifiers, never destination paths.
    return !name.empty() && name != "." && name != ".." &&
        name.find_first_of("/\\:") == std::string::npos &&
        std::none_of(name.begin(), name.end(), [](unsigned char c) { return c < 32 || c == 127; });
}
bool pe_candidate(const std::string &path) {
    platform::File file(path);
    if (file.size() < 2) return false;
    uint8_t magic[2]; file.read_at(0, magic, 2);
    return magic[0] == 'M' && magic[1] == 'Z';
}
struct Cabinet {
    std::string name, path;
    int64_t first;
    int32_t last;
    std::vector<platform::CabinetMember> members;
    bool changed = false;
};
void inspect_cabinet(Cabinet &cab, const std::string &workspace,
                     uint64_t &total, size_t &count) {
    platform::File file(cab.path);
    const uint64_t length = file.size();
    if (length < 36 || length > expansion_limit) invalid("invalid cabinet size: " + cab.name);
    uint8_t h[40]{}; file.read_at(0, h, 36);
    if (std::memcmp(h, "MSCF", 4) || u32(h + 8) != length) invalid("invalid cabinet header: " + cab.name);
    const auto flags = u16(h + 30), folders = u16(h + 26), files = u16(h + 28);
    if (flags & 3) invalid("spanning cabinets are unsupported: " + cab.name);
    if (flags & ~uint16_t(7)) invalid("unsupported cabinet flags: " + cab.name);
    uint64_t pos = 36;
    uint8_t folder_reserve = 0, data_reserve = 0;
    if (flags & 4) {
        if (length < 40) invalid("truncated cabinet reserve header");
        file.read_at(36, h + 36, 4);
        pos = 40 + u16(h + 36); folder_reserve = h[38]; data_reserve = h[39];
    }
    if (pos + uint64_t(folders) * (8 + folder_reserve) > length) invalid("truncated cabinet folders");
    struct Folder { uint64_t start, end, expanded; std::vector<std::pair<uint64_t, uint64_t>> files; };
    std::vector<Folder> folder_info;
    uint64_t cabinet_expanded = 0;
    for (uint16_t i = 0; i < folders; ++i) {
        uint8_t f[8]; file.read_at(pos, f, 8); pos += 8 + folder_reserve;
        const auto compression = u16(f + 6) & 15;
        if (compression != 0 && compression != 1 && compression != 3)
            invalid("unsupported cabinet compression: " + cab.name);
        if (u32(f) > length) invalid("cabinet folder lies outside file");
        Folder folder{u32(f), u32(f), 0, {}};
        for (uint16_t j = 0; j < u16(f + 4); ++j) {
            if (length - folder.end < uint64_t(8 + data_reserve)) invalid("truncated cabinet data block");
            uint8_t data[8]; file.read_at(folder.end, data, 8);
            const auto packed = u16(data + 4), unpacked = u16(data + 6);
            if (!unpacked || unpacked > 32768 || !packed) invalid("invalid or spanning cabinet data block");
            const uint64_t block = uint64_t(8 + data_reserve) + packed;
            if (block > length - folder.end) invalid("truncated cabinet data");
            folder.end += block; folder.expanded += unpacked;
        }
        if (folder.expanded > expansion_limit - cabinet_expanded) invalid("expanded cabinet exceeds 1 GiB");
        cabinet_expanded += folder.expanded;
        folder_info.push_back(std::move(folder));
    }
    uint64_t cursor = u32(h + 16);
    if (cursor < pos || cursor > length) invalid("invalid cabinet file table");
    if (files > member_limit - count) invalid("more than 65535 payload members");
    std::set<std::string> names;
    for (uint16_t i = 0; i < files; ++i) {
        if (length - cursor < 17) invalid("truncated cabinet file record");
        uint8_t f[16]; file.read_at(cursor, f, 16); cursor += 16;
        if (u16(f + 8) >= folders) invalid("spanning or invalid cabinet member");
        platform::CabinetMember member;
        member.size = u32(f); member.date = u16(f + 10);
        member.time = u16(f + 12); member.attributes = u16(f + 14);
        auto &folder = folder_info[u16(f + 8)];
        const uint64_t offset = u32(f + 4);
        if (offset > folder.expanded || member.size > folder.expanded - offset) invalid("cabinet member exceeds folder data");
        folder.files.emplace_back(offset, offset + member.size);
        for (;;) {
            if (cursor >= length || member.name.size() > 255) invalid("invalid cabinet member name");
            uint8_t ch; file.read_at(cursor++, &ch, 1);
            if (!ch) break;
            member.name += char(ch);
        }
        if (!safe_name(member.name) || !names.insert(member.name).second)
            invalid("unsafe or duplicate cabinet member name: " + member.name);
        member.path = workspace + "/payload-" + std::to_string(count++);
        cab.members.push_back(std::move(member));
    }
    if (cabinet_expanded > expansion_limit - total) invalid("expanded payload exceeds 1 GiB");
    total += cabinet_expanded;
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    for (auto &folder : folder_info) {
        if (folder.start < cursor) invalid("cabinet data overlaps metadata");
        ranges.emplace_back(folder.start, folder.end);
        std::sort(folder.files.begin(), folder.files.end());
        uint64_t end = 0;
        for (const auto &range : folder.files) {
            if (range.first < end) invalid("overlapping cabinet members");
            end = range.second;
        }
    }
    std::sort(ranges.begin(), ranges.end());
    uint64_t end = cursor;
    for (const auto &range : ranges) {
        if (range.first < end) invalid("overlapping cabinet folders");
        end = range.second;
    }
}
void preserve_cabinet_metadata(const std::string &path, const std::vector<platform::CabinetMember> &members) {
    // FCI and GCab may normalize attributes or invalid DOS dates. Restore the
    // original raw metadata after compression, and verify the emitted ordering.
    platform::File file(path); const uint64_t size = file.size();
    uint8_t h[36];
    if (size < sizeof(h)) invalid("truncated rebuilt cabinet");
    file.read_at(0, h, sizeof(h));
    if (std::memcmp(h, "MSCF", 4) || u16(h + 28) != members.size()) invalid("rebuilt cabinet member count mismatch");
    uint64_t cursor = u32(h + 16);
    for (const auto &member : members) {
        if (cursor > size || size - cursor < 17) invalid("truncated rebuilt cabinet file record");
        uint8_t f[16]; file.read_at(cursor, f, 16);
        platform::File payload(member.path);
        if (u32(f) != payload.size()) invalid("rebuilt cabinet member size mismatch");
        const uint64_t metadata = cursor + 10;
        cursor += 16; std::string name;
        for (;;) {
            if (cursor >= size || name.size() > 255) invalid("invalid rebuilt cabinet name");
            uint8_t ch; file.read_at(cursor++, &ch, 1);
            if (!ch) break;
            name += char(ch);
        }
        if (name != member.name) invalid("rebuilt cabinet member order mismatch");
        uint8_t bytes[6] = {uint8_t(member.date), uint8_t(member.date >> 8),
            uint8_t(member.time), uint8_t(member.time >> 8), uint8_t(member.attributes), uint8_t(member.attributes >> 8)};
        file.write_at(metadata, bytes, sizeof(bytes));
    }
    file.flush();
}
} // namespace

MsiRewriteResult rewrite_msi_payload(const std::string &staged_msi,
    const std::function<bool(const std::string &, const std::string &)> &sign_if_unsigned) {
    platform::TempDir workspace;
    platform::MsiDatabase db(staged_msi);
    if (!db.query("SELECT `Name` FROM `_Storages`").empty())
        invalid("embedded transforms or nested database storages are unsupported");
    std::set<std::string> tables;
    for (const auto &row : db.query("SELECT `Name` FROM `_Tables`")) tables.insert(row[0]);
    const bool compressed = (db.word_count() & 2) != 0;
    std::vector<Cabinet> cabinets;
    std::set<std::string> cabinet_names;
    int32_t previous = 0;
    if (tables.contains("Media")) {
        for (const auto &row : db.query("SELECT `DiskId`, `LastSequence`, `Cabinet` FROM `Media` ORDER BY `DiskId`")) {
            const int32_t last = integer(row[1]);
            if (last < previous) invalid("Media sequence ranges are not ordered");
            if (row[2].empty() || row[2][0] != '#' || row[2].size() == 1)
                invalid("external cabinets and loose source media are unsupported");
            const auto name = row[2].substr(1);
            if (!cabinet_names.insert(name).second) invalid("duplicate Media cabinet reference");
            cabinets.push_back({name, workspace.path() + "/cab-" + std::to_string(cabinets.size()), int64_t(previous) + 1, last, {}, false});
            previous = last;
        }
    }
    struct FileRow { int32_t size, sequence; std::string version; bool found = false; };
    std::map<std::string, FileRow> files;
    std::set<int32_t> sequences;
    if (tables.contains("File")) {
        for (const auto &row : db.query("SELECT `File`, `FileSize`, `Version`, `Attributes`, `Sequence` FROM `File`")) {
            const auto attr = integer(row[3]);
            if ((attr & 0x2000) || (!(attr & 0x4000) && !compressed))
                invalid("loose source file is unsupported: " + row[0]);
            const auto seq = integer(row[4]), size = integer(row[1]);
            if (seq <= 0 || size < 0 || !sequences.insert(seq).second)
                invalid("invalid or duplicate File sequence/size");
            if (!files.emplace(row[0], FileRow{size, seq, row[2]}).second) invalid("duplicate File identifier");
        }
    }
    uint64_t expanded = 0;
    size_t count = 0;
    for (auto &cab : cabinets) {
        db.extract_stream("SELECT `Data` FROM `_Streams` WHERE `Name` = ?", cab.name, cab.path, expansion_limit);
        inspect_cabinet(cab, workspace.path(), expanded, count);
        for (const auto &member : cab.members) {
            auto it = files.find(member.name);
            if (it == files.end() || it->second.found || it->second.sequence < cab.first || it->second.sequence > cab.last ||
                uint32_t(it->second.size) != member.size) invalid("CAB/File table mapping mismatch: " + member.name);
            it->second.found = true;
        }
        platform::extract_cabinet(cab.path, cab.members);
        for (const auto &member : cab.members) {
            platform::File file(member.path);
            if (file.size() != member.size) invalid("extracted cabinet member size mismatch: " + member.name);
        }
    }
    for (const auto &[name, row] : files) if (!row.found) invalid("File row has no embedded cabinet member: " + name);
    std::vector<std::pair<std::string, std::string>> binaries;
    if (tables.contains("Binary")) {
        for (const auto &row : db.query("SELECT `Name` FROM `Binary`")) {
            if (count >= member_limit) invalid("more than 65535 payload members");
            const auto path = workspace.path() + "/payload-" + std::to_string(count++);
            expanded += db.extract_stream("SELECT `Data` FROM `Binary` WHERE `Name` = ?", row[0], path, expansion_limit - expanded);
            binaries.emplace_back(row[0], path);
        }
    }
    std::set<std::string> hash_rows;
    if (tables.contains("MsiFileHash")) {
        for (const auto &row : db.query("SELECT `File_`, `Options` FROM `MsiFileHash`")) {
            if (integer(row[1]) != 0) invalid("unsupported MsiFileHash options");
            hash_rows.insert(row[0]);
        }
    }
    MsiRewriteResult result;
    auto sign = [&](const std::string &path, const std::string &name) {
        if (!pe_candidate(path)) return false;
        uint64_t before;
        { platform::File file(path); before = file.size(); }
        if (!sign_if_unsigned(path, name)) { ++result.preserved_files; return false; }
        { platform::File file(path);
          if (file.size() > expansion_limit - (expanded - before)) invalid("signed payload exceeds 1 GiB expansion limit");
          expanded = expanded - before + file.size(); }
        ++result.signed_files; return true;
    };
    for (auto &cab : cabinets) {
        for (auto &member : cab.members) {
            if (!sign(member.path, "CAB " + cab.name + "/" + member.name)) continue;
            cab.changed = true;
            platform::File file(member.path);
            const auto size = file.size();
            if (size > uint64_t(std::numeric_limits<int32_t>::max())) invalid("signed payload exceeds MSI FileSize range");
            db.execute("UPDATE `File` SET `FileSize` = ? WHERE `File` = ?", {int32_t(size), member.name});
            if (hash_rows.contains(member.name) && files.at(member.name).version.empty()) {
                const auto hash = platform::msi_file_hash(member.path);
                db.execute("UPDATE `MsiFileHash` SET `HashPart1` = ?, `HashPart2` = ?, `HashPart3` = ?, `HashPart4` = ? WHERE `File_` = ?",
                           {hash[0], hash[1], hash[2], hash[3], member.name});
            }
        }
        if (cab.changed) {
            const auto output = cab.path + ".rebuilt";
            platform::create_cabinet(output, cab.members);
            preserve_cabinet_metadata(output, cab.members);
            db.execute("UPDATE `_Streams` SET `Data` = ? WHERE `Name` = ?", {platform::MsiStreamPath{output}, cab.name});
        }
    }
    for (const auto &[name, path] : binaries) {
        if (sign(path, "Binary/" + name))
            db.execute("UPDATE `Binary` SET `Data` = ? WHERE `Name` = ?", {platform::MsiStreamPath{path}, name});
    }
    if (result.signed_files) { db.renew_package_code(); db.commit(); }
    return result;
}
