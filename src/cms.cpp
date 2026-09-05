#include "cms.hpp"
#include "der.hpp"
#include "platform.hpp"
#include "x509.hpp"
#include <stdexcept>
#include <cstring>

// Well-known OIDs.
static Bytes oid_signed_data()       { return der_oid("1.2.840.113549.1.7.2"); }
static Bytes oid_spc_indirect_data() { return der_oid("1.3.6.1.4.1.311.2.1.4"); }
static Bytes oid_spc_statement_type(){ return der_oid("1.3.6.1.4.1.311.2.1.11"); }
static Bytes oid_spc_individual()    { return der_oid("1.3.6.1.4.1.311.2.1.21"); }
static Bytes oid_sha256()            { return der_oid("2.16.840.1.101.3.4.2.1"); }
static Bytes oid_rsa_encryption()    { return der_oid("1.2.840.113549.1.1.1"); }
static Bytes oid_content_type()      { return der_oid("1.2.840.113549.1.9.3"); }
static Bytes oid_message_digest()    { return der_oid("1.2.840.113549.1.9.4"); }

// SHA-256 AlgorithmIdentifier: SEQUENCE { OID sha-256, NULL }.
static Bytes sha256_alg_id()
{
    auto oid = oid_sha256();
    auto null = der_null();
    return der_sequence({&oid, &null});
}

// Build the authenticated attributes SET (tag 0x31).
static Bytes build_auth_attrs(const Bytes &spc_indirect_data)
{
    // Hash the content, not the SEQUENCE's DER tag and length. MSIX has
    // composite digests and therefore a long-form DER length.
    auto content = der_read_tlv(spc_indirect_data.data(), spc_indirect_data.size());
    if (content.tag != DER_SEQUENCE || content.total_len != spc_indirect_data.size())
        throw std::runtime_error("invalid SpcIndirectDataContent");
    auto content_hash = platform::sha256(content.content, content.content_len);

    // Attribute 1: contentType = SPC_INDIRECT_DATA
    auto ct_oid = oid_content_type();
    auto ct_val_oid = oid_spc_indirect_data();
    auto ct_val = der_set({&ct_val_oid});
    auto attr_content_type = der_sequence({&ct_oid, &ct_val});

    // Attribute 2: messageDigest = SHA256(SpcIndirectDataContent)
    auto md_oid = oid_message_digest();
    auto md_val_octets = der_octet_string(content_hash.data(),
                                          content_hash.size());
    auto md_val = der_set({&md_val_octets});
    auto attr_msg_digest = der_sequence({&md_oid, &md_val});

    // Attribute 3: SPC_STATEMENT_TYPE = { SPC_INDIVIDUAL_SP_KEY_PURPOSE }
    auto st_oid = oid_spc_statement_type();
    auto st_ind_oid = oid_spc_individual();
    auto st_ind_seq = der_sequence({&st_ind_oid});
    auto st_val = der_set({&st_ind_seq});
    auto attr_statement = der_sequence({&st_oid, &st_val});

    return der_set({&attr_content_type, &attr_msg_digest, &attr_statement});
}

static std::vector<uint8_t> assemble_cms(
    const Bytes &spc_idc,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &certs_der)
{
    // Parse signing cert to get issuer + serial.
    auto certs = x509_split_certs(certs_der.data(), certs_der.size());
    if (certs.empty())
        throw std::runtime_error("no certificates in chain");
    auto cert_id = x509_cert_id(certs[0].data(), certs[0].size());

    // Build authenticated attributes (as SET, tag 0x31).
    auto auth_attrs_set = build_auth_attrs(spc_idc);

    // --- SignerInfo ---

    auto si_version = der_integer(1);

    // IssuerAndSerialNumber.
    Bytes issuer_raw(cert_id.issuer_raw);
    Bytes serial_raw(cert_id.serial_raw);
    auto sid = der_sequence({&issuer_raw, &serial_raw});

    auto si_digest_alg = sha256_alg_id();

    // Authenticated attrs with IMPLICIT [0] tag (0xA0 replaces 0x31).
    auto si_auth_attrs = der_implicit(0, true, auth_attrs_set);

    // signatureAlgorithm: rsaEncryption with NULL.
    auto rsa_oid = oid_rsa_encryption();
    auto rsa_null = der_null();
    auto si_sig_alg = der_sequence({&rsa_oid, &rsa_null});

    auto si_signature = der_octet_string(signature.data(), signature.size());

    auto signer_info = der_sequence({&si_version, &sid, &si_digest_alg,
                                     &si_auth_attrs, &si_sig_alg, &si_signature});

    // --- SignedData ---

    auto sd_version = der_integer(1);

    auto sd_digest_alg = sha256_alg_id();
    auto sd_digest_algs = der_set({&sd_digest_alg});

    // encapContentInfo: SEQUENCE { OID SPC_INDIRECT_DATA, [0] EXPLICIT content }
    auto eciOid = oid_spc_indirect_data();
    auto eciContent = der_explicit(0, spc_idc);
    auto encap_content = der_sequence({&eciOid, &eciContent});

    // Certificates [0] IMPLICIT: concatenate individual cert DER blobs.
    Bytes all_certs;
    for (auto &c : certs)
        all_certs.insert(all_certs.end(), c.begin(), c.end());
    auto certs_wrapped = der_wrap(0xa0, all_certs.data(), all_certs.size());

    auto signer_infos = der_set({&signer_info});

    auto signed_data = der_sequence({&sd_version, &sd_digest_algs,
                                     &encap_content, &certs_wrapped,
                                     &signer_infos});

    // --- Outer ContentInfo ---

    auto ci_oid = oid_signed_data();
    auto ci_content = der_explicit(0, signed_data);

    return der_sequence({&ci_oid, &ci_content});
}

namespace {
class DerFields {
public:
    explicit DerFields(TlvView view) : p_(view.content), remaining_(view.content_len) {}
    TlvView take(uint8_t tag) {
        auto v = der_read_tlv(p_, remaining_);
        if (v.tag != tag) throw std::runtime_error("unexpected CMS DER field");
        p_ += v.total_len;
        remaining_ -= v.total_len;
        return v;
    }
    bool empty() const { return remaining_ == 0; }
    uint8_t next() const { return empty() ? 0 : *p_; }
    void end() const {
        if (!empty()) throw std::runtime_error("trailing CMS DER fields");
    }
private:
    const uint8_t *p_;
    size_t remaining_;
};
void require_oid(TlvView value, const Bytes &oid) {
    auto expected = der_read_tlv(oid.data(), oid.size());
    if (value.content_len != expected.content_len ||
        std::memcmp(value.content, expected.content, value.content_len))
        throw std::runtime_error("unexpected CMS content or digest algorithm (SHA-256 required)");
}
TlvView signed_data(const Bytes &pkcs7) {
    auto outer = der_read_tlv(pkcs7.data(), pkcs7.size());
    if (outer.tag != DER_SEQUENCE || outer.total_len != pkcs7.size())
        throw std::runtime_error("invalid PKCS#7 ContentInfo");
    DerFields ci(outer);
    require_oid(ci.take(0x06), oid_signed_data());
    DerFields wrapper(ci.take(0xa0));
    auto sd = wrapper.take(DER_SEQUENCE);
    wrapper.end(); ci.end();
    return sd;
}
TlvView skip_signed_data_header(DerFields &sd) {
    auto version = sd.take(0x02);
    if (version.content_len != 1 || version.content[0] != 1)
        throw std::runtime_error("Authenticode requires SignedData version 1");
    sd.take(DER_SET);
    return sd.take(DER_SEQUENCE);
}
}

Bytes cms_extract_indirect_data(const Bytes &pkcs7)
{
    DerFields sd(signed_data(pkcs7));
    DerFields eci(skip_signed_data_header(sd));
    require_oid(eci.take(0x06), oid_spc_indirect_data());
    DerFields content(eci.take(0xa0));
    auto idc = content.take(DER_SEQUENCE);
    content.end(); eci.end();
    DerFields data(idc);
    data.take(DER_SEQUENCE); // format-specific SIP payload, retained verbatim
    DerFields digest(data.take(DER_SEQUENCE));
    DerFields algorithm(digest.take(DER_SEQUENCE));
    require_oid(algorithm.take(0x06), oid_sha256());
    if (!algorithm.empty()) {
        if (algorithm.take(0x05).content_len != 0)
            throw std::runtime_error("invalid SHA-256 parameters");
    }
    algorithm.end();
    if (digest.take(0x04).content_len == 0)
        throw std::runtime_error("empty Authenticode digest");
    digest.end(); data.end();
    if (sd.next() == 0xa0) sd.take(0xa0);
    if (sd.next() == 0xa1) sd.take(0xa1);
    sd.take(DER_SET); sd.end();
    const auto *start = idc.content - (idc.total_len - idc.content_len);
    return Bytes(start, start + idc.total_len);
}

bool cms_has_signer(const Bytes &pkcs7)
{
    DerFields sd(signed_data(pkcs7));
    skip_signed_data_header(sd);
    if (sd.next() == 0xa0) sd.take(0xa0);
    if (sd.next() == 0xa1) sd.take(0xa1);
    DerFields signers(sd.take(DER_SET));
    sd.end();
    bool found = false;
    while (!signers.empty()) {
        DerFields signer(signers.take(DER_SEQUENCE));
        const auto version = signer.take(0x02);
        if (version.content_len != 1 || version.content[0] != 1)
            throw std::runtime_error("invalid Authenticode SignerInfo version");
        DerFields sid(signer.take(DER_SEQUENCE));
        const auto issuer = sid.take(DER_SEQUENCE);
        if (!issuer.content_len) throw std::runtime_error("empty signer issuer");
        const auto serial = sid.take(0x02);
        if (!serial.content_len) throw std::runtime_error("empty signer serial");
        sid.end();
        auto algorithm = [&] {
            DerFields fields(signer.take(DER_SEQUENCE));
            if (!fields.take(0x06).content_len)
                throw std::runtime_error("empty signature algorithm OID");
            if (!fields.empty()) fields.take(fields.next());
            fields.end();
        };
        algorithm();
        auto attributes = [&](uint8_t tag) {
            DerFields attrs(signer.take(tag));
            if (attrs.empty()) throw std::runtime_error("empty signer attributes");
            while (!attrs.empty()) {
                DerFields attr(attrs.take(DER_SEQUENCE));
                if (!attr.take(0x06).content_len) throw std::runtime_error("empty attribute OID");
                DerFields values(attr.take(DER_SET));
                if (values.empty()) throw std::runtime_error("empty attribute values");
                while (!values.empty()) values.take(values.next());
                attr.end();
            }
        };
        if (signer.next() == 0xa0) attributes(0xa0);
        algorithm();
        if (signer.take(0x04).content_len == 0)
            throw std::runtime_error("empty CMS signature");
        if (signer.next() == 0xa1) attributes(0xa1);
        signer.end(); found = true;
    }
    return found;
}

std::array<uint8_t, 32> cms_auth_attrs_hash(const Bytes &indirect_data)
{
    const auto attrs = build_auth_attrs(indirect_data);
    return platform::sha256(attrs.data(), attrs.size());
}

Bytes cms_build_authenticode(const Bytes &indirect_data, const Bytes &signature,
                             const Bytes &certs_der)
{
    return assemble_cms(indirect_data, signature, certs_der);
}
