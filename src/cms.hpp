#pragma once

#include <array>
#include <cstdint>
#include <vector>

// Extract the exact SpcIndirectDataContent DER from osslsigncode extract-data.
// Only SHA-256 content is supported. All wrappers are checked before returning.
std::vector<uint8_t> cms_extract_indirect_data(const std::vector<uint8_t> &pkcs7);
bool cms_has_signer(const std::vector<uint8_t> &pkcs7);

// Format-independent adapter. The same indirect_data bytes must be supplied
// to hashing and assembly; the digest can be an APPX composite hash blob.
std::array<uint8_t, 32> cms_auth_attrs_hash(
    const std::vector<uint8_t> &indirect_data);
std::vector<uint8_t> cms_build_authenticode(
    const std::vector<uint8_t> &indirect_data,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &certs_der);
