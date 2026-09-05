#pragma once

#include "azure.hpp"
#include <array>
#include <functional>
#include <string>

struct SigningOptions {
    std::string osslsigncode;
    std::string timestamp_url;
    std::string dump_cms;
    std::string ca_bundle;
    bool no_timestamp = false;
    bool msi_dse = false;
    bool recursive = false;
    bool insecure = false;
};

using DigestSigner = std::function<AzureSignResult(const std::array<uint8_t, 32> &)>;
using SigningLogger = std::function<void(const std::string &)>;

// Resolve and check once before starting workers. Explicit path, sibling, PATH.
std::string resolve_osslsigncode(const std::string &explicit_path);
// Stage, optionally rebuild MSI payloads, sign and atomically replace the input.
// Injection permits credential-free integration tests without a production
// local-key signing mode.
void sign_file(const std::string &path, const SigningOptions &options,
               const DigestSigner &sign_digest, const SigningLogger &log);
// Structural inspection only, used to preserve already-signed MSI payloads.
bool pe_has_signature(const std::string &path);
