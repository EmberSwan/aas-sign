#include "msi.hpp"
#include "platform.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

int failures;

void put16(uint8_t *p, uint16_t v)
{
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
}

void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
        p[i] = uint8_t(v >> (8 * i));
}

uint32_t get32(const uint8_t *p)
{
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 |
           uint32_t(p[3]) << 24;
}

std::string hex(const std::array<uint8_t, 32> &value)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (auto byte : value)
        out << std::setw(2) << unsigned(byte);
    return out.str();
}

void expect(bool condition, const std::string &message)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void expect_digest(const std::array<uint8_t, 32> &actual,
                   const std::array<uint8_t, 32> &expected,
                   const std::string &message)
{
    if (actual != expected) {
        std::cerr << "FAIL: " << message << "\n  expected: "
                  << hex(expected) << "\n  actual:   " << hex(actual) << '\n';
        ++failures;
    }
}

template <class F>
void expect_throws(F &&operation, const std::string &message)
{
    try {
        operation();
        std::cerr << "FAIL: " << message << " (no exception)\n";
        ++failures;
    } catch (const std::exception &) {
    }
}

struct TemporaryFile {
    explicit TemporaryFile(std::string name) : path(std::move(name)) {}
    ~TemporaryFile()
    {
        try {
            platform::remove_file(path);
        } catch (const std::exception &) {
        }
    }
    std::string path;
};

std::vector<uint8_t> empty_compound_file(uint16_t major)
{
    constexpr uint32_t FREE = 0xffffffff, END = 0xfffffffe;
    constexpr uint32_t FAT = 0xfffffffd;
    const uint32_t sector_size = major == 3 ? 512 : 4096;
    std::vector<uint8_t> bytes(size_t(3) * sector_size);
    const uint8_t magic[] = {0xd0, 0xcf, 0x11, 0xe0,
                             0xa1, 0xb1, 0x1a, 0xe1};
    std::copy(std::begin(magic), std::end(magic), bytes.begin());
    put16(bytes.data() + 24, 0x003e);
    put16(bytes.data() + 26, major);
    put16(bytes.data() + 28, 0xfffe);
    put16(bytes.data() + 30, uint16_t(major == 3 ? 9 : 12));
    put16(bytes.data() + 32, 6);
    put32(bytes.data() + 40, major == 4 ? 1 : 0);
    put32(bytes.data() + 44, 1);
    put32(bytes.data() + 48, 0);
    put32(bytes.data() + 56, 4096);
    put32(bytes.data() + 60, END);
    put32(bytes.data() + 68, END);
    put32(bytes.data() + 76, 1);
    for (int i = 1; i < 109; ++i)
        put32(bytes.data() + 76 + 4 * i, FREE);

    uint8_t *root = bytes.data() + sector_size;
    const char *name = "Root Entry";
    for (size_t i = 0; name[i]; ++i)
        put16(root + 2 * i, uint8_t(name[i]));
    put16(root + 64, 22);
    root[66] = 5;
    root[67] = 1;
    put32(root + 68, FREE);
    put32(root + 72, FREE);
    put32(root + 76, FREE);
    put32(root + 116, END);

    uint8_t *fat = bytes.data() + size_t(2) * sector_size;
    put32(fat, END);
    put32(fat + 4, FAT);
    for (size_t i = 2; i < sector_size / 4; ++i)
        put32(fat + 4 * i, FREE);
    return bytes;
}

std::vector<uint8_t> read_whole_file(const std::string &path)
{
    platform::File file(path);
    auto size = file.size();
    std::vector<uint8_t> bytes(static_cast<size_t>(size), uint8_t{});
    if (!bytes.empty())
        file.read_at(0, bytes.data(), bytes.size());
    return bytes;
}

void check_round_trip(uint16_t major,
                      const std::array<uint8_t, 32> &basic,
                      const std::array<uint8_t, 32> &enhanced)
{
    TemporaryFile file("/tmp/aas-sign-msi-test-" +
                       std::to_string(::getpid()) + "-v" +
                       std::to_string(major) + ".msi");
    auto input = empty_compound_file(major);
    platform::write_whole_file(file.path, input.data(), input.size());

    std::vector<uint8_t> metadata;
    {
        MsiFile msi(file.path);
        expect_digest(msi.authenticode_hash(false).file, basic,
                      "CFB v" + std::to_string(major) + " basic digest");
        auto digest = msi.authenticode_hash(true);
        expect_digest(digest.file, enhanced,
                      "CFB v" + std::to_string(major) + " enhanced digest");
        expect(digest.metadata.size() == 32,
               "enhanced digest includes a 32-byte metadata prehash");
        metadata = digest.metadata;
        expect_throws(
            [&] { msi.inject_signature({0x30, 0x00}, {0x00}); },
            "enhanced metadata with the wrong length is rejected");
        msi.inject_signature({0x30, 0x00}, metadata);
    }

    {
        MsiFile msi(file.path);
        expect_digest(msi.authenticode_hash(false).file, basic,
                      "small signature stream is excluded from basic digest");
        expect_digest(msi.authenticode_hash(true).file, enhanced,
                      "enhanced streams are excluded from enhanced digest");

        // Exercise the regular-stream serializer path as well as the mini
        // stream used by the small signature above.
        std::vector<uint8_t> large_signature(5000);
        for (size_t i = 0; i < large_signature.size(); ++i)
            large_signature[i] = uint8_t(i * 17 + 3);
        msi.inject_signature(large_signature, metadata);
    }

    {
        MsiFile msi(file.path);
        expect_digest(msi.authenticode_hash(false).file, basic,
                      "large signature stream is excluded from basic digest");
        expect_digest(msi.authenticode_hash(true).file, enhanced,
                      "large signature round trip preserves enhanced digest");
        msi.inject_signature({0x30, 0x00}, {});
    }

    {
        MsiFile msi(file.path);
        expect_digest(msi.authenticode_hash(false).file, basic,
                      "basic re-signing removes enhanced metadata safely");
    }
}

void check_stale_directory_sector_count(uint16_t major)
{
    TemporaryFile file("/tmp/aas-sign-msi-test-" +
                       std::to_string(::getpid()) + "-stale-dir-v" +
                       std::to_string(major) + ".msi");
    auto input = empty_compound_file(major);
    // The actual directory chain has one sector.  For v3 this field is
    // unused and must normally be zero; for v4 it is an incorrect count.
    put32(input.data() + 40, 2);
    platform::write_whole_file(file.path, input.data(), input.size());

    {
        MsiFile msi(file.path);
        msi.inject_signature({0x30, 0x00}, {});
    }

    auto rewritten = read_whole_file(file.path);
    expect(get32(rewritten.data() + 40) == (major == 4 ? 1U : 0U),
           "CFB v" + std::to_string(major) +
               " stale directory count is accepted and canonicalized");
    MsiFile reparsed(file.path);
}

void check_v3_uninitialized_stream_size_high_word()
{
    TemporaryFile file("/tmp/aas-sign-msi-test-" +
                       std::to_string(::getpid()) + "-v3-size-high.msi");
    auto input = empty_compound_file(3);
    constexpr size_t root_stream_size_high = 512 + 124;
    put32(input.data() + root_stream_size_high, 0xdeadbeef);
    platform::write_whole_file(file.path, input.data(), input.size());

    {
        MsiFile msi(file.path);
        msi.inject_signature({0x30, 0x00}, {});
    }

    auto rewritten = read_whole_file(file.path);
    auto dir_start = get32(rewritten.data() + 48);
    auto root_offset = (size_t(dir_start) + 1) * 512;
    expect(get32(rewritten.data() + root_offset + 124) == 0,
           "CFB v3 uninitialized stream-size high word is ignored and "
           "canonicalized");
    MsiFile reparsed(file.path);
}

void check_real_msi_seed()
{
    const std::array<uint8_t, 32> basic = {
        0x2d, 0xb0, 0xca, 0xf2, 0x8d, 0x80, 0xf8, 0xbe,
        0xfb, 0x02, 0xc3, 0x2d, 0xc1, 0xd8, 0x19, 0x3a,
        0xea, 0x02, 0x18, 0x98, 0xb6, 0x20, 0xa7, 0xa6,
        0x8d, 0x0a, 0x27, 0xb9, 0xf7, 0xf5, 0xd2, 0x24};
    const std::array<uint8_t, 32> enhanced = {
        0xf4, 0x91, 0x2f, 0x10, 0xaf, 0x89, 0x06, 0xa0,
        0x76, 0x6d, 0xa2, 0x5c, 0xd2, 0x39, 0xd3, 0x9b,
        0x7f, 0x26, 0x2f, 0xeb, 0xd0, 0x87, 0x81, 0x53,
        0x54, 0x92, 0x63, 0xcb, 0x3a, 0x38, 0xd3, 0x14};
    const std::vector<uint8_t> expected_metadata = {
        0x97, 0x24, 0xc6, 0x8d, 0x96, 0xf1, 0xeb, 0xa0,
        0x35, 0x7f, 0x72, 0x63, 0xc5, 0x26, 0x54, 0x23,
        0x30, 0xbb, 0xe5, 0x48, 0x36, 0x2a, 0xfb, 0x48,
        0x58, 0x2b, 0xef, 0xa0, 0x27, 0xce, 0xe7, 0xc9};
    const std::string source =
        std::string(AAS_SIGN_SOURCE_DIR) +
        "/fuzz/corpus/msi/minimal-msi-v3.msi";
    TemporaryFile copy("/tmp/aas-sign-msi-test-" +
                       std::to_string(::getpid()) + "-real.msi");
    auto bytes = read_whole_file(source);
    platform::write_whole_file(copy.path, bytes.data(), bytes.size());

    std::vector<uint8_t> metadata;
    {
        MsiFile msi(copy.path);
        expect_digest(msi.authenticode_hash(false).file, basic,
                      "real MSI digest matches osslsigncode");
        auto digest = msi.authenticode_hash(true);
        expect_digest(digest.file, enhanced,
                      "real enhanced MSI digest matches osslsigncode");
        expect(digest.metadata == expected_metadata,
               "real MSI metadata digest matches osslsigncode");
        metadata = digest.metadata;
        msi.inject_signature({0x30, 0x00}, metadata);
    }
    {
        MsiFile rewritten(copy.path);
        expect_digest(rewritten.authenticode_hash(false).file, basic,
                      "real MSI rewrite preserves its basic digest");
        expect_digest(rewritten.authenticode_hash(true).file, enhanced,
                      "real MSI rewrite preserves its enhanced digest");
    }
}

}  // namespace

int main()
{
    const std::array<uint8_t, 32> basic = {
        0x37, 0x47, 0x08, 0xff, 0xf7, 0x71, 0x9d, 0xd5, 0x97, 0x9e, 0xc8,
        0x75, 0xd5, 0x6c, 0xd2, 0x28, 0x6f, 0x6d, 0x3c, 0xf7, 0xec, 0x31,
        0x7a, 0x3b, 0x25, 0x63, 0x2a, 0xab, 0x28, 0xec, 0x37, 0xbb};
    const std::array<uint8_t, 32> enhanced = {
        0xa2, 0x29, 0x59, 0x50, 0xc0, 0x17, 0x20, 0xdb, 0x01, 0x80, 0x35,
        0xe9, 0x3a, 0xa8, 0x4b, 0x41, 0x40, 0x43, 0x01, 0x0b, 0x9f, 0x21,
        0x4d, 0xdc, 0x72, 0x2c, 0x0c, 0x75, 0x0a, 0xf0, 0xa8, 0xd6};

    try {
        check_round_trip(3, basic, enhanced);
        check_round_trip(4, basic, enhanced);
        check_stale_directory_sector_count(3);
        check_stale_directory_sector_count(4);
        check_v3_uninitialized_stream_size_high_word();
        check_real_msi_seed();

        TemporaryFile malformed("/tmp/aas-sign-msi-test-" +
                                std::to_string(::getpid()) + "-bad.msi");
        auto bytes = empty_compound_file(3);
        bytes[0] ^= 0xff;
        platform::write_whole_file(malformed.path, bytes.data(), bytes.size());
        expect_throws([&] { MsiFile ignored(malformed.path); },
                      "invalid CFB magic is rejected");
    } catch (const std::exception &e) {
        std::cerr << "FAIL: unexpected exception: " << e.what() << '\n';
        ++failures;
    }

    if (failures)
        std::cerr << failures << " MSI test(s) failed\n";
    return failures ? 1 : 0;
}
