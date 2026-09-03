#include "cms.hpp"
#include "platform.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int failures;

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

std::vector<uint8_t> read_certificate()
{
    const std::string path =
        std::string(AAS_SIGN_SOURCE_DIR) +
        "/fuzz/corpus/x509_cert_id/sample.der";
    platform::File file(path);
    auto size = file.size();
    std::vector<uint8_t> bytes(static_cast<size_t>(size), uint8_t{});
    if (!bytes.empty())
        file.read_at(0, bytes.data(), bytes.size());
    return bytes;
}

bool contains(const std::vector<uint8_t> &haystack,
              const std::vector<uint8_t> &needle)
{
    return std::search(haystack.begin(), haystack.end(),
                       needle.begin(), needle.end()) != haystack.end();
}

}  // namespace

int main()
{
    // Fixed inputs make these hashes compact golden tests for the complete
    // PE and MSI authenticated-attribute encodings.
    const std::array<uint8_t, 32> file_hash{};
    const std::array<uint8_t, 32> expected_pe_attrs = {
        0x58, 0xab, 0xaf, 0x0f, 0xea, 0x37, 0x3d, 0x6c,
        0xff, 0x38, 0xfc, 0x4d, 0xbe, 0xfd, 0xd3, 0x02,
        0x3d, 0x3d, 0x07, 0x8b, 0x15, 0xcc, 0x99, 0x4f,
        0x94, 0xf3, 0xa9, 0x42, 0xc8, 0x28, 0xee, 0x4a};
    const std::array<uint8_t, 32> expected_msi_attrs = {
        0x35, 0x7c, 0x18, 0x1c, 0x4f, 0x00, 0xe7, 0x75,
        0xba, 0xb7, 0xab, 0xfc, 0x76, 0xee, 0x63, 0xf5,
        0x17, 0x09, 0x9b, 0x75, 0x39, 0xe0, 0x3b, 0x31,
        0x9a, 0x96, 0xc1, 0x32, 0x8d, 0x8c, 0x49, 0xf1};
    const std::array<uint8_t, 32> expected_pe_cms = {
        0x39, 0x7a, 0x5e, 0xde, 0x76, 0xce, 0xf9, 0xf0,
        0xe7, 0xfa, 0xc0, 0x14, 0x15, 0x1b, 0x8f, 0x17,
        0xc4, 0x84, 0x04, 0x4a, 0xc2, 0x3f, 0x75, 0x96,
        0x5e, 0x7a, 0xfb, 0xdc, 0x9a, 0x25, 0xfc, 0xc9};
    const std::array<uint8_t, 32> expected_msi_cms = {
        0xf6, 0x55, 0xed, 0xd9, 0x62, 0x9c, 0x01, 0x77,
        0xe4, 0x27, 0x73, 0x9a, 0xfd, 0x76, 0x36, 0x9f,
        0x70, 0x28, 0xb0, 0x17, 0x60, 0x84, 0x84, 0xa0,
        0x94, 0xd3, 0x73, 0xd2, 0x19, 0x0c, 0x8f, 0x77};

    try {
        auto pe_attrs =
            cms_auth_attrs_hash(file_hash, AuthenticodeFormat::Pe);
        auto msi_attrs =
            cms_auth_attrs_hash(file_hash, AuthenticodeFormat::Msi);
        expect_digest(pe_attrs, expected_pe_attrs,
                      "PE authenticated attributes remain stable");
        expect_digest(msi_attrs, expected_msi_attrs,
                      "MSI authenticated attributes match the SIP encoding");
        expect(cms_auth_attrs_hash(file_hash) == pe_attrs,
               "the default CMS format remains PE for compatibility");
        expect(pe_attrs != msi_attrs,
               "PE and MSI authenticated attributes are distinct");

        auto cert = read_certificate();
        std::vector<uint8_t> signature(256);
        for (size_t i = 0; i < signature.size(); ++i)
            signature[i] = uint8_t(i);

        auto pe_cms = cms_build_authenticode(
            file_hash, signature, cert, {}, AuthenticodeFormat::Pe);
        auto msi_cms = cms_build_authenticode(
            file_hash, signature, cert, {}, AuthenticodeFormat::Msi);
        expect_digest(platform::sha256(pe_cms.data(), pe_cms.size()),
                      expected_pe_cms, "PE CMS encoding remains stable");
        expect_digest(platform::sha256(msi_cms.data(), msi_cms.size()),
                      expected_msi_cms, "MSI CMS encoding remains stable");

        const std::vector<uint8_t> pe_oid = {
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
            0x01, 0x82, 0x37, 0x02, 0x01, 0x0f};
        const std::vector<uint8_t> msi_oid = {
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
            0x01, 0x82, 0x37, 0x02, 0x01, 0x1e};
        const std::vector<uint8_t> msi_uuid = {
            0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
        expect(contains(pe_cms, pe_oid),
               "PE CMS contains the SpcPeImageData OID");
        expect(!contains(pe_cms, msi_oid),
               "PE CMS does not contain the MSI SIP OID");
        expect(contains(msi_cms, msi_oid),
               "MSI CMS contains the SpcSipInfo OID");
        expect(contains(msi_cms, msi_uuid),
               "MSI CMS contains the Windows Installer SIP UUID");

        const std::vector<uint8_t> timestamp_token = {0x30, 0x00};
        auto timestamped = cms_build_authenticode(
            file_hash, signature, cert, timestamp_token,
            AuthenticodeFormat::Msi);
        const std::vector<uint8_t> timestamp_oid = {
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
            0x01, 0x82, 0x37, 0x03, 0x03, 0x01};
        expect(contains(timestamped, timestamp_oid),
               "MSI CMS retains the Authenticode RFC 3161 attribute");
    } catch (const std::exception &e) {
        std::cerr << "FAIL: unexpected exception: " << e.what() << '\n';
        ++failures;
    }

    if (failures)
        std::cerr << failures << " CMS test(s) failed\n";
    return failures ? 1 : 0;
}
