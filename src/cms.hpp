#pragma once

#include <array>
#include <cstdint>
#include <vector>

enum class AuthenticodeFormat { Pe, Msi };

// Compute SHA-256(DER(authenticated_attributes_as_SET)).
// file_hash is the format-specific Authenticode digest; format selects the
// PE image or MSI SIP payload. This is the digest that Azure will sign.
std::array<uint8_t, 32> cms_auth_attrs_hash(
    const std::array<uint8_t, 32> &file_hash,
    AuthenticodeFormat format = AuthenticodeFormat::Pe);

// Build a complete Authenticode SignedData ContentInfo. The caller stores it
// in a PE WIN_CERTIFICATE or the MSI DigitalSignature stream.
//
// If timestamp_token_der is non-empty, it is embedded in the SignerInfo as
// an unsigned attribute under OID 1.3.6.1.4.1.311.3.3.1
// (szOID_RFC3161_counterSign).  The bytes must be a complete DER-encoded
// ContentInfo SEQUENCE as returned by an RFC 3161 TSA.
std::vector<uint8_t> cms_build_authenticode(
    const std::array<uint8_t, 32> &file_hash,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &certs_der,
    const std::vector<uint8_t> &timestamp_token_der = {},
    AuthenticodeFormat format = AuthenticodeFormat::Pe);
