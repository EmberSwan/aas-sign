#include "msi_recursive.hpp"
#include "msi_package.hpp"
#include "platform.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <stdexcept>

namespace {
std::string fixture_source() {
    const auto *source = std::getenv("AAS_SIGN_TEST_SOURCE_DIR");
    return std::string(source && *source ? source : AAS_SIGN_SOURCE_DIR) + "/tests/fixtures/recursive.msi";
}
void require(bool ok, const std::string &message) { if (!ok) throw std::runtime_error(message); }
std::vector<uint8_t> read(const std::string &path) {
    platform::File file(path); std::vector<uint8_t> bytes(size_t(file.size()));
    file.read_at(0, bytes.data(), bytes.size()); return bytes;
}
std::string fixture(platform::TempDir &dir, const std::string &name) {
    const auto path = dir.path() + "/" + name + ".msi";
    platform::copy_file(fixture_source(), path);
    return path;
}
struct CabinetSnapshot {
    std::vector<std::string> order;
    std::vector<uint8_t> metadata;
    std::map<std::string, std::vector<uint8_t>> payloads;
};
CabinetSnapshot snapshot(const std::string &path) {
    platform::TempDir work;
    platform::MsiDatabase db(path);
    CabinetSnapshot result;
    size_t index = 0;
    auto word = [](const uint8_t *p) { return unsigned(p[0]) | unsigned(p[1]) << 8; };
    auto dword = [&](const uint8_t *p) { return word(p) | word(p + 2) << 16; };
    for (const auto &name : {"first.cab", "second.cab"}) {
        const auto cab = work.path() + "/" + name;
        db.extract_stream("SELECT `Data` FROM `_Streams` WHERE `Name` = ?", name, cab, 1024 * 1024);
        auto bytes = read(cab);
        size_t cursor = dword(bytes.data() + 16);
        std::vector<platform::CabinetMember> members;
        for (unsigned i = 0; i < word(bytes.data() + 28); ++i) {
            platform::CabinetMember member;
            member.size = dword(bytes.data() + cursor);
            result.metadata.insert(result.metadata.end(), bytes.begin() + cursor + 10, bytes.begin() + cursor + 16);
            cursor += 16;
            while (bytes.at(cursor)) member.name += char(bytes.at(cursor++));
            ++cursor; result.order.push_back(member.name);
            member.path = work.path() + "/member-" + std::to_string(index++);
            members.push_back(std::move(member));
        }
        platform::extract_cabinet(cab, members);
        for (const auto &member : members) result.payloads[member.name] = read(member.path);
    }
    return result;
}
void rejected(const std::string &path, const std::function<void(platform::MsiDatabase &)> &mutate, const std::string &message) {
    { platform::MsiDatabase db(path); mutate(db); db.commit(); }
    const auto before = read(path); size_t calls = 0;
    try {
        rewrite_msi_payload(path, [&](const auto &, const auto &) { ++calls; return false; });
        throw std::runtime_error("accepted " + message);
    } catch (const std::runtime_error &error) {
        require(std::string(error.what()).find("recursive MSI:") != std::string::npos, message + ": " + error.what());
    }
    require(calls == 0, "called signer before rejecting " + message);
    require(read(path) == before, "modified rejected " + message);
}
} // namespace

int aas_sign_main(int argc, char **argv) {
    try {
        if (argc == 5 && std::string(argv[1]) == "--create-fixture") {
            platform::copy_file(fixture_source(), argv[2]);
            rewrite_msi_payload(argv[2], [&](const auto &payload, const auto &name) {
                const auto bytes = read(name.find("PreservedDll") != std::string::npos ? argv[4] : argv[3]);
                platform::write_whole_file(payload, bytes.data(), bytes.size()); return true;
            });
            return 0;
        }
        if (argc == 4 && std::string(argv[1]) == "--extract-fixture") {
            rewrite_msi_payload(argv[2], [&](const auto &payload, const auto &name) {
                auto key = name.substr(name.find_last_of('/') + 1);
                if (name.starts_with("Binary/")) key = "Binary." + key;
                platform::copy_file(payload, std::string(argv[3]) + "/" + key);
                return false;
            });
            return 0;
        }
        if (argc != 1) throw std::runtime_error("usage: msi_recursive_test [--create-fixture OUTPUT UNSIGNED_PE SIGNED_PE | --extract-fixture MSI DIRECTORY]");
        platform::TempDir dir;
        const auto path = fixture(dir, "recursive installation");
        const auto original_cabinets = snapshot(path);
        platform::MsiRows before_files, before_media, before_properties, before_directories;
        std::string old_code;
        { platform::MsiDatabase db(path);
          before_files = db.query("SELECT `File`, `Version`, `Language`, `Attributes`, `Sequence`, `Component_` FROM `File`");
          before_media = db.query("SELECT * FROM `Media`");
          before_properties = db.query("SELECT * FROM `Property`");
          before_directories = db.query("SELECT * FROM `Directory`"); old_code = db.package_code(); }
        std::map<std::string, std::vector<uint8_t>> expected;
        const auto result = rewrite_msi_payload(path, [&](const std::string &payload, const std::string &name) {
            auto bytes = read(payload);
            if (name.find("PreservedDll") != std::string::npos) { expected[name] = bytes; return false; }
            bytes.insert(bytes.end(), {0x41, 0x41, 0x53, 0x53, 0x49, 0x47, 0x4e});
            expected[name] = bytes;
            platform::write_whole_file(payload, bytes.data(), bytes.size()); return true;
        });
        require(result.signed_files == 3 && result.preserved_files == 1, "incorrect recursive signing counts");
        require(expected.size() == 4, "non-PE or nested MSI was passed to signer");
        const auto rebuilt_cabinets = snapshot(path);
        require(rebuilt_cabinets.order == original_cabinets.order, "cabinet member order changed");
        require(rebuilt_cabinets.metadata == original_cabinets.metadata, "cabinet timestamps or attributes changed");
        for (const auto &key : {"TextFile", "NestedMsi", "PreservedDll"})
            require(rebuilt_cabinets.payloads.at(key) == original_cabinets.payloads.at(key), "preserved cabinet payload changed");
        { platform::MsiDatabase db(path);
          require(db.query("SELECT `File`, `Version`, `Language`, `Attributes`, `Sequence`, `Component_` FROM `File`") == before_files, "File metadata changed");
          require(db.query("SELECT * FROM `Media`") == before_media, "Media changed");
          require(db.query("SELECT * FROM `Property`") == before_properties, "properties changed");
          require(db.query("SELECT * FROM `Directory`") == before_directories, "directories changed");
          const auto code = db.package_code();
          require(code != old_code && code.size() == 38 && code.front() == '{' && code.back() == '}', "PackageCode did not change");
          require(std::none_of(code.begin(), code.end(), [](char c) { return c >= 'a' && c <= 'f'; }), "PackageCode is not uppercase");
          for (const auto &key : {"UnsignedExe", "SecondExe"}) {
              auto rows = db.query("SELECT `FileSize` FROM `File` WHERE `File` = ?", {std::string(key)});
              require(rows.size() == 1 && rows[0][0] == "247", "changed FileSize not updated");
          }
          const auto binary = dir.path() + "/binary-unchanged";
          db.extract_stream("SELECT `Data` FROM `Binary` WHERE `Name` = ?", "NonPe", binary, 1024);
          const auto data = read(binary);
          require(std::string(data.begin(), data.end()) == "Unchanged non-PE payload\n", "non-PE Binary stream changed");
        }
        const auto after = read(path);
        std::map<std::string, std::vector<std::string>> saved_hashes;
        {
            platform::MsiDatabase db(path);
            for (const auto &row : db.query("SELECT `File_`, `HashPart1`, `HashPart2`, `HashPart3`, `HashPart4` FROM `MsiFileHash`"))
                saved_hashes.emplace(row[0], std::vector<std::string>(row.begin() + 1, row.end()));
        }
        size_t count = 0;
        const auto second = rewrite_msi_payload(path, [&](const auto &payload, const auto &name) {
            require(read(payload) == expected.at(name), "reconstructed bytes differ: " + name);
            if (name.find("UnsignedExe") != std::string::npos || name.find("SecondExe") != std::string::npos) {
                const auto key = name.substr(name.find_last_of('/') + 1);
                auto hash = platform::msi_file_hash(payload);
                for (size_t i = 0; i < 4; ++i) require(saved_hashes.at(key)[i] == std::to_string(hash[i]), "MSI hash was not updated");
            }
            ++count; return false;
        });
        require(count == 4 && second.signed_files == 0 && second.preserved_files == 4, "preservation counts wrong");
        require(read(path) == after, "no-op reconstruction changed installer bytes");

        rejected(fixture(dir, "external"), [](auto &db) {
            db.execute("UPDATE `Media` SET `Cabinet` = ? WHERE `DiskId` = 1", {std::string("external.cab")});
        }, "external cabinet");
        rejected(fixture(dir, "loose"), [](auto &db) {
            db.execute("UPDATE `File` SET `Attributes` = ? WHERE `File` = ?", {int32_t(8192), std::string("UnsignedExe")});
        }, "loose source file");
        rejected(fixture(dir, "mapping"), [](auto &db) {
            db.execute("UPDATE `File` SET `FileSize` = ? WHERE `File` = ?", {int32_t(99), std::string("UnsignedExe")});
        }, "cabinet mapping mismatch");
        rejected(fixture(dir, "transform"), [&](auto &db) {
            db.execute("INSERT INTO `_Storages` (`Name`, `Data`) VALUES (?, ?)",
                       {std::string("EmbeddedTransform"), platform::MsiStreamPath{fixture_source()}});
        }, "embedded transform");
        rejected(fixture(dir, "spanning"), [&](auto &db) {
            const auto cab = dir.path() + "/spanning.cab";
            db.extract_stream("SELECT `Data` FROM `_Streams` WHERE `Name` = ?", "first.cab", cab, 1024 * 1024);
            { platform::File file(cab); uint8_t flags = 1; file.write_at(30, &flags, 1); }
            db.execute("UPDATE `_Streams` SET `Data` = ? WHERE `Name` = ?", {platform::MsiStreamPath{cab}, std::string("first.cab")});
        }, "spanning cabinet");
        rejected(fixture(dir, "compression"), [&](auto &db) {
            const auto cab = dir.path() + "/quantum.cab";
            db.extract_stream("SELECT `Data` FROM `_Streams` WHERE `Name` = ?", "first.cab", cab, 1024 * 1024);
            { platform::File file(cab); uint8_t compression = 2; file.write_at(42, &compression, 1); }
            db.execute("UPDATE `_Streams` SET `Data` = ? WHERE `Name` = ?", {platform::MsiStreamPath{cab}, std::string("first.cab")});
        }, "unsupported cabinet compression");
        const auto failure = fixture(dir, "signing failure");
        const auto failure_before = read(failure);
        try {
            unsigned attempts = 0;
            rewrite_msi_payload(failure, [&](const auto &payload, const auto &) -> bool {
                if (++attempts == 2) throw std::runtime_error("mock Azure failure");
                auto bytes = read(payload); bytes.push_back(42);
                platform::write_whole_file(payload, bytes.data(), bytes.size()); return true;
            });
            require(false, "signer failure was swallowed");
        } catch (const std::runtime_error &error) { require(std::string(error.what()) == "mock Azure failure", error.what()); }
        require(read(failure) == failure_before, "signing failure modified staged input");

        const auto vector = dir.path() + "/hash-vector";
        const std::string abc = "abc";
        platform::write_whole_file(vector, reinterpret_cast<const uint8_t *>(abc.data()), abc.size());
        const std::array<uint32_t, 4> md5{0x98500190, 0xb04fd23c, 0x7d3f96d6, 0x727fe128};
        const auto hash = platform::msi_file_hash(vector);
        require(std::memcmp(hash.data(), md5.data(), 16) == 0, "Windows MSI file hash vector mismatch");
        platform::write_whole_file(vector, nullptr, 0);
        require(platform::msi_file_hash(vector) == std::array<int32_t, 4>{}, "MSI empty file hash mismatch");
        platform::write_stdout("recursive MSI tests passed\n"); return 0;
    } catch (const std::exception &error) {
        platform::write_stderr(std::string(error.what()) + "\n"); return 1;
    }
}

#ifndef _WIN32
int main(int argc, char **argv) { return aas_sign_main(argc, argv); }
#endif
