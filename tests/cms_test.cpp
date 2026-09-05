#include "cms.hpp"
#include "der.hpp"
#include "platform.hpp"
#include "x509.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <functional>
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
        platform::write_stderr("FAIL: " + message + "\n");
        ++failures;
    }
}

void expect_digest(const std::array<uint8_t, 32> &actual,
                   const std::array<uint8_t, 32> &expected,
                   const std::string &message)
{
    if (actual != expected) {
        platform::write_stderr("FAIL: " + message + "\n  expected: " +
                              hex(expected) + "\n  actual:   " + hex(actual) + "\n");
        ++failures;
    }
}

Bytes read_fixture(const std::string &name)
{
    const std::string path = std::string(AAS_SIGN_SOURCE_DIR) + "/fuzz/corpus/" + name;
    platform::File file(path);
    auto size = file.size();
    std::vector<uint8_t> bytes(static_cast<size_t>(size), uint8_t{});
    if (!bytes.empty())
        file.read_at(0, bytes.data(), bytes.size());
    return bytes;
}

Bytes unhex(const std::string &hex)
{
    Bytes out;
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back(uint8_t(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return out;
}

// Fixed DER from the previous PE/MSI format implementations, containing an
// all-zero SHA-256 file digest. Format knowledge now lives only in fixtures.
Bytes indirect_fixture(bool msi)
{
    auto out = unhex(msi ?
        "30673032060a2b06010401823702011e30240201010410f1100c0000000000"
        "c0000000000000460201000201000201000201000201003031300d060960"
        "864801650304020105000420" :
        "304c3017060a2b06010401823702010f3009030100a004a2028000303130"
        "0d060960864801650304020105000420");
    out.insert(out.end(), 32, 0);
    return out;
}

std::vector<Bytes> children(const Bytes &encoded)
{
    auto outer = der_read_tlv(encoded.data(), encoded.size());
    std::vector<Bytes> fields;
    for (size_t offset = 0; offset < outer.content_len;) {
        auto field = der_read_tlv(outer.content + offset, outer.content_len - offset);
        fields.emplace_back(outer.content + offset, outer.content + offset + field.total_len);
        offset += field.total_len;
    }
    return fields;
}

Bytes enclosing(uint8_t tag, const std::vector<Bytes> &fields)
{
    Bytes content;
    for (const auto &field : fields) content.insert(content.end(), field.begin(), field.end());
    return der_wrap(tag, content.data(), content.size());
}

Bytes unsigned_envelope(const Bytes &indirect)
{
    auto alg = enclosing(0x30, {der_oid("2.16.840.1.101.3.4.2.1"), der_null()});
    auto eci = enclosing(0x30, {der_oid("1.3.6.1.4.1.311.2.1.4"), der_explicit(0, indirect)});
    auto sd = enclosing(0x30, {der_integer(1), enclosing(0x31, {alg}), eci, enclosing(0x31, {})});
    return enclosing(0x30, {der_oid("1.2.840.113549.1.7.2"), der_explicit(0, sd)});
}

Bytes alter_signed_data(const Bytes &cms, const std::function<void(std::vector<Bytes> &)> &change)
{
    auto outer = children(cms);
    auto sd = children(children(outer.at(1)).at(0));
    change(sd);
    outer[1] = der_explicit(0, enclosing(0x30, sd));
    return enclosing(0x30, outer);
}

Bytes alter_signer(const Bytes &cms, const std::function<void(std::vector<Bytes> &)> &change)
{
    return alter_signed_data(cms, [&](auto &sd) {
        auto signers = children(sd.back());
        auto signer = children(signers.at(0));
        change(signer);
        signers[0] = enclosing(0x30, signer);
        sd.back() = enclosing(0x31, signers);
    });
}

void rejects(const std::function<void()> &operation, const std::string &message)
{
    try { operation(); }
    catch (const std::exception &) { return; }
    expect(false, message);
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
    const auto pe_indirect = indirect_fixture(false);
    const auto msi_indirect = indirect_fixture(true);
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
            cms_auth_attrs_hash(pe_indirect);
        auto msi_attrs =
            cms_auth_attrs_hash(msi_indirect);
        expect_digest(pe_attrs, expected_pe_attrs,
                      "PE authenticated attributes remain stable");
        expect_digest(msi_attrs, expected_msi_attrs,
                      "MSI authenticated attributes match the SIP encoding");
        expect(pe_attrs != msi_attrs,
               "PE and MSI authenticated attributes are distinct");

        auto cert = read_fixture("x509_cert_id/sample.der");
        std::vector<uint8_t> signature(256);
        for (size_t i = 0; i < signature.size(); ++i)
            signature[i] = uint8_t(i);

        auto pe_cms = cms_build_authenticode(
            pe_indirect, signature, cert);
        auto msi_cms = cms_build_authenticode(
            msi_indirect, signature, cert);
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

        expect(cms_has_signer(pe_cms) && cms_has_signer(msi_cms), "assembled CMS contains a signer");
        expect(cms_extract_indirect_data(pe_cms) == pe_indirect, "exact PE indirect-data round trip");
        expect(cms_extract_indirect_data(msi_cms) == msi_indirect, "exact MSI indirect-data round trip");

        auto unsigned_pe = unsigned_envelope(pe_indirect);
        expect(!cms_has_signer(unsigned_pe), "extract-data envelope has no signer");
        expect(cms_extract_indirect_data(unsigned_pe) == pe_indirect, "unsigned extraction envelope is accepted");
        auto msix_envelope = read_fixture("cms_indirect/msix.der");
        auto msix_indirect = cms_extract_indirect_data(msix_envelope);
        expect(msix_indirect.size() > 128 && (msix_indirect.at(1) & 0x80), "MSIX uses long-form DER length");
        expect(!cms_has_signer(msix_envelope), "real MSIX extract-data fixture is unsigned");
        const auto expected_msix = unhex("0dabbb8b6ce94a4dcbd841b9b2720ed13a7ae8eefe84e2e73b6188d16e4a7011");
        const auto msix_attrs = cms_auth_attrs_hash(msix_indirect);
        expect(std::equal(msix_attrs.begin(), msix_attrs.end(), expected_msix.begin()),
               "MSIX attributes hash the sequence content beyond its full DER header");
        auto msix_cms = cms_build_authenticode(msix_indirect, signature, cert);
        expect(cms_extract_indirect_data(msix_cms) == msix_indirect && cms_has_signer(msix_cms),
               "MSIX composite digest survives CMS assembly byte-for-byte");

        // Every incomplete extraction envelope must fail without reading past
        // its input; this includes truncated long-form DER length octets.
        for (size_t size = 0; size < msix_envelope.size(); ++size) {
            Bytes truncated(msix_envelope.begin(), msix_envelope.begin() + size);
            rejects([&] { (void)cms_extract_indirect_data(truncated); }, "truncated envelope accepted");
        }
        auto trailing = unsigned_pe; trailing.push_back(0);
        rejects([&] { (void)cms_extract_indirect_data(trailing); }, "trailing outer bytes accepted");
        auto wrong_tag = unsigned_pe; wrong_tag[0] = 0x31;
        rejects([&] { (void)cms_extract_indirect_data(wrong_tag); }, "wrong ContentInfo tag accepted");
        auto outer = children(unsigned_pe);
        outer[1][0] = 0xa1;
        auto wrong_wrapper = enclosing(0x30, outer);
        rejects([&] { (void)cms_extract_indirect_data(wrong_wrapper); }, "wrong explicit wrapper accepted");
        outer = children(unsigned_pe);
        outer[0] = der_oid("1.2.840.113549.1.7.3");
        auto wrong_outer_oid = enclosing(0x30, outer);
        rejects([&] { (void)cms_extract_indirect_data(wrong_outer_oid); }, "wrong outer OID accepted");
        rejects([&] { (void)cms_has_signer(wrong_outer_oid); }, "signer parser accepts wrong outer OID");
        auto wrong_version = alter_signed_data(unsigned_pe, [](auto &sd) { sd[0] = der_integer(3); });
        rejects([&] { (void)cms_extract_indirect_data(wrong_version); }, "SignedData v3 accepted");
        rejects([&] { (void)cms_has_signer(wrong_version); }, "signer parser accepts SignedData v3");
        auto wrong_content_oid = alter_signed_data(unsigned_pe, [](auto &sd) {
            auto eci = children(sd[2]);
            eci[0] = der_oid("1.2.840.113549.1.7.1");
            sd[2] = enclosing(0x30, eci);
        });
        rejects([&] { (void)cms_extract_indirect_data(wrong_content_oid); }, "non-Authenticode content accepted");
        auto format_fields = children(pe_indirect);
        auto digest_fields = children(format_fields[1]);
        digest_fields[0] = enclosing(0x30, {der_oid("2.16.840.1.101.3.4.2.3"), der_null()});
        format_fields[1] = enclosing(0x30, digest_fields);
        auto sha512 = unsigned_envelope(enclosing(0x30, format_fields));
        rejects([&] { (void)cms_extract_indirect_data(sha512); }, "SHA-512 signing content accepted");
        format_fields = children(pe_indirect);
        digest_fields = children(format_fields[1]);
        digest_fields[1] = enclosing(0x04, {});
        format_fields[1] = enclosing(0x30, digest_fields);
        auto empty_digest = unsigned_envelope(enclosing(0x30, format_fields));
        rejects([&] { (void)cms_extract_indirect_data(empty_digest); }, "empty file digest accepted");
        auto empty_signature = alter_signer(pe_cms, [](auto &signer) { signer[5] = enclosing(0x04, {}); });
        rejects([&] { (void)cms_has_signer(empty_signature); }, "empty RSA signature accepted");
        auto signer_version = alter_signer(pe_cms, [](auto &signer) { signer[0] = der_integer(3); });
        rejects([&] { (void)cms_has_signer(signer_version); }, "SignerInfo v3 accepted");
        auto empty_issuer = alter_signer(pe_cms, [](auto &signer) {
            signer[1] = enclosing(0x30, {enclosing(0x30, {}), der_integer(1)});
        });
        rejects([&] { (void)cms_has_signer(empty_issuer); }, "empty issuer accepted");
        auto empty_algorithm = alter_signer(pe_cms, [](auto &signer) { signer[4] = enclosing(0x30, {}); });
        rejects([&] { (void)cms_has_signer(empty_algorithm); }, "empty signature algorithm accepted");
        auto empty_attributes = alter_signer(pe_cms, [](auto &signer) { signer[3] = enclosing(0xa0, {}); });
        rejects([&] { (void)cms_has_signer(empty_attributes); }, "empty authenticated attributes accepted");
        // Presence checks deliberately accept other digest algorithms: existing
        // SHA-1 payload signatures must be preservable without re-signing.
        auto sha1_signer = alter_signer(pe_cms, [](auto &signer) {
            signer[2] = enclosing(0x30, {der_oid("1.3.14.3.2.26"), der_null()});
        });
        expect(cms_has_signer(sha1_signer), "existing SHA-1 signer remains structurally detectable");
        auto timestamped = alter_signer(msi_cms, [](auto &signer) {
            auto attribute = enclosing(0x30, {der_oid("1.3.6.1.4.1.311.3.3.1"),
                                              enclosing(0x31, {enclosing(0x30, {})})});
            signer.push_back(enclosing(0xa1, {attribute}));
        });
        expect(cms_has_signer(timestamped) && cms_extract_indirect_data(timestamped) == msi_indirect,
               "companion-added timestamp attributes remain parseable");
    } catch (const std::exception &e) {
        platform::write_stderr(std::string("FAIL: unexpected exception: ") + e.what() + "\n");
        ++failures;
    }

    if (failures)
        platform::write_stderr(std::to_string(failures) + " CMS test(s) failed\n");
    return failures ? 1 : 0;
}
