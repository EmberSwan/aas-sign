#include "signing.hpp"
#include "cms.hpp"
#include "msi_recursive.hpp"
#include "platform.hpp"
#include "x509.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <vector>

namespace {
using Bytes = std::vector<uint8_t>;
enum class Kind { Pe, Msi, Msix };
constexpr uint64_t MAX_CMS = 16 * 1024 * 1024;
std::filesystem::path from_utf8(const std::string &value) {
    return std::filesystem::path(std::u8string(value.begin(), value.end()));
}

std::string extension(const std::string &path) {
    auto value = from_utf8(path).extension().string();
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return char(std::tolower(c)); });
    return value;
}
std::string utf8(const std::filesystem::path &path) {
    auto value = path.u8string();
    return std::string(value.begin(), value.end());
}
Bytes read_blob(const std::string &path) {
    platform::File file(path);
    auto size = file.size();
    if (size > MAX_CMS) throw std::runtime_error("signature data exceeds 16 MiB: " + path);
    Bytes bytes(static_cast<size_t>(size));
    if (!bytes.empty()) file.read_at(0, bytes.data(), bytes.size());
    return bytes;
}
void write_blob(const std::string &path, const Bytes &bytes) {
    platform::write_whole_file(path, bytes.data(), bytes.size());
}
uint16_t le16(const uint8_t *p) { return uint16_t(p[0] | uint16_t(p[1]) << 8); }
uint32_t le32(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 |
           uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
Kind identify(const std::string &path) {
    platform::File file(path);
    uint8_t magic[8];
    file.read_at(0, magic, sizeof(magic));
    static const uint8_t cfb[] = {0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1};
    auto ext = extension(path);
    if (!std::memcmp(magic, cfb, 8)) {
        if (ext != ".msi") throw std::runtime_error("compound file is not a supported .msi package");
        return Kind::Msi;
    }
    if (ext == ".msi") throw std::runtime_error("not an MSI compound file");
    if (magic[0] == 'M' && magic[1] == 'Z') return Kind::Pe;
    if (magic[0] == 'P' && magic[1] == 'K' && magic[2] == 3 && magic[3] == 4 &&
        (ext == ".msix" || ext == ".msixbundle" || ext == ".appx" || ext == ".appxbundle"))
        return Kind::Msix;
    throw std::runtime_error("unsupported file format; expected PE, MSI, MSIX or MSIX bundle");
}

platform::ProcessResult invoke(const SigningOptions &options,
                               const std::vector<std::string> &args) {
    return platform::run_process(options.osslsigncode, args);
}
void checked(const SigningOptions &options, const std::vector<std::string> &args) {
    auto result = invoke(options, args);
    if (result.exit_code != 0)
        throw std::runtime_error("osslsigncode " + args.front() + " failed (exit " +
                                 std::to_string(result.exit_code) + "):\n" + result.output);
}
// The pinned companion reports missing signatures distinctly from malformed
// input or extraction failures. Only these explicit absence messages permit
// continuing with an unsigned input; an arbitrary failed command never does.
bool extract_existing(const std::string &path, const std::string &output,
                      Kind kind, const SigningOptions &options) {
    auto result = invoke(options, {"extract-signature", "-in", path, "-out", output});
    if (!result.exit_code) {
        if (!cms_has_signer(read_blob(output)))
            throw std::runtime_error("existing signature contains no signer: " + path);
        return true;
    }
    const char *missing = kind == Kind::Pe ? "No signature found" :
                          kind == Kind::Msi ? "MSI file has no signature" :
                          "AppxSignature.p7x does not exist";
    if (result.output.find(missing) == std::string::npos)
        throw std::runtime_error("cannot inspect existing signature: " + path + "\n" + result.output);
    return false;
}

void sign_staged(const std::string &path, Kind kind, const SigningOptions &options,
                 const DigestSigner &sign_digest, const SigningLogger &log) {
    platform::TempDir work(utf8(from_utf8(path).parent_path()));
    const auto existing = work.path() + "/existing.der";
    const auto unsigned_path = work.path() + "/unsigned" + extension(path);
    std::string source = path;
    bool signed_input = extract_existing(path, existing, kind, options);
    if (signed_input) {
        checked(options, {"remove-signature", "-in", path, "-out", unsigned_path});
        source = unsigned_path;
    }
    const bool enhanced = kind == Kind::Msi && options.msi_dse;
    auto format_args = [&](std::vector<std::string> args) {
        args.insert(args.end(), {"-h", "sha256"});
        if (enhanced) args.push_back("-add-msi-dse");
        return args;
    };
    const auto extracted = work.path() + "/content.der";
    auto args = format_args({"extract-data"});
    args.insert(args.end(), {"-in", source, "-out", extracted});
    checked(options, args);
    const auto indirect_data = cms_extract_indirect_data(read_blob(extracted));
    const auto digest = cms_auth_attrs_hash(indirect_data);
    log("Signing via Azure...\n");
    const auto result = sign_digest(digest);
    const auto cms = cms_build_authenticode(indirect_data, result.signature, result.cert_chain_der);
    const auto signature_path = work.path() + "/signature.der";
    write_blob(signature_path, cms);
    auto output = work.path() + "/signed" + extension(path);
    args = format_args({"attach-signature"});
    args.insert(args.end(), {"-sigin", signature_path, "-in", source, "-out", output});
    checked(options, args);
    if (!options.no_timestamp) {
        log("Requesting timestamp from " + options.timestamp_url + " ...\n");
        auto timestamped = work.path() + "/timestamped" + extension(path);
        args = format_args({"add"});
        args.insert(args.end(), {"-ts", options.timestamp_url, "-in", output, "-out", timestamped});
        if (options.insecure) args.push_back("-noverifypeer");
        if (!options.ca_bundle.empty()) args.insert(args.end(), {"-HTTPS-CAfile", options.ca_bundle});
        checked(options, args);
        output = timestamped;
    }
    // Re-extract the final CMS to catch incomplete output and preserve dump-cms
    // semantics after timestamping. Attachment already checks the file digest.
    const auto final_cms_path = work.path() + "/final.der";
    checked(options, {"extract-signature", "-in", output, "-out", final_cms_path});
    auto final_cms = read_blob(final_cms_path);
    if (!cms_has_signer(final_cms)) throw std::runtime_error("completed signature contains no signer");
    if (cms_extract_indirect_data(final_cms) != indirect_data)
        throw std::runtime_error("completed signature changed the indirect data");
    const auto rechecked = work.path() + "/rechecked.der";
    args = format_args({"extract-data"});
    args.insert(args.end(), {"-in", output, "-out", rechecked});
    checked(options, args);
    if (cms_extract_indirect_data(read_blob(rechecked)) != indirect_data)
        throw std::runtime_error("completed file no longer matches its signature");
    if (!options.dump_cms.empty()) write_blob(options.dump_cms, final_cms);
    platform::atomic_replace_file(output, path);
}
}

std::string resolve_osslsigncode(const std::string &explicit_path)
{
    std::string resolved;
    if (!explicit_path.empty()) resolved = platform::find_executable(explicit_path);
    else {
        auto self = from_utf8(platform::executable_path());
        const auto name = std::string("osslsigncode") + (self.extension() == ".exe" ? ".exe" : "");
        try { resolved = platform::find_executable(utf8(self.parent_path() / name)); }
        catch (const std::exception &) { resolved = platform::find_executable(name); }
    }
    auto help = platform::run_process(resolved, {"--help"});
    if (help.exit_code != 0) throw std::runtime_error("cannot query osslsigncode: " + help.output);
    for (const auto *command : {"extract-data", "attach-signature", "extract-signature", "remove-signature", "-ts"})
        if (help.output.find(command) == std::string::npos)
            throw std::runtime_error("incompatible osslsigncode; missing " + std::string(command));
    return resolved;
}

bool pe_has_signature(const std::string &path)
{
    platform::File file(path);
    const auto size = file.size();
    uint8_t dos[64]; file.read_at(0, dos, sizeof(dos));
    if (dos[0] != 'M' || dos[1] != 'Z') throw std::runtime_error("not a PE image: " + path);
    const uint64_t pe = le32(dos + 60);
    uint8_t header[26]; file.read_at(pe, header, sizeof(header));
    if (std::memcmp(header, "PE\0\0", 4)) throw std::runtime_error("invalid PE header: " + path);
    const auto opt_len = le16(header + 20);
    const auto format = le16(header + 24);
    const uint64_t directories = format == 0x10b ? 96 : format == 0x20b ? 112 : 0;
    if (!directories || opt_len < directories) throw std::runtime_error("invalid PE optional header: " + path);
    uint8_t count[4]; file.read_at(pe + 24 + directories - 4, count, 4);
    if (le32(count) <= 4) return false;
    if (opt_len < directories + 40) throw std::runtime_error("truncated PE data directory: " + path);
    uint8_t entry[8]; file.read_at(pe + 24 + directories + 32, entry, 8);
    uint64_t offset = le32(entry), length = le32(entry + 4);
    if (!offset && !length) return false;
    if (!offset || !length || offset % 8 || offset < pe + 24 + opt_len ||
        offset > size || length > size - offset)
        throw std::runtime_error("invalid PE certificate table: " + path);
    bool found = false;
    while (length) {
        if (length < 8) throw std::runtime_error("truncated WIN_CERTIFICATE: " + path);
        uint8_t cert[8]; file.read_at(offset, cert, 8);
        uint64_t n = le32(cert);
        if (n < 8 || n > length || n > MAX_CMS || le16(cert + 4) != 0x200 || le16(cert + 6) != 2)
            throw std::runtime_error("malformed PE Authenticode signature: " + path);
        Bytes pkcs7(static_cast<size_t>(n - 8));
        file.read_at(offset + 8, pkcs7.data(), pkcs7.size());
        auto der = der_read_tlv(pkcs7.data(), pkcs7.size());
        for (size_t i = der.total_len; i < pkcs7.size(); ++i)
            if (pkcs7[i]) throw std::runtime_error("invalid PE signature padding: " + path);
        pkcs7.resize(der.total_len);
        if (!cms_has_signer(pkcs7)) throw std::runtime_error("PE signature contains no signer: " + path);
        found = true;
        auto aligned = (n + 7) & ~uint64_t(7);
        if (aligned > length) {
            if (n != length) throw std::runtime_error("invalid certificate alignment: " + path);
            aligned = n;
        }
        offset += aligned; length -= aligned;
    }
    return found;
}

void sign_file(const std::string &path, const SigningOptions &options,
               const DigestSigner &sign_digest, const SigningLogger &log)
{
    if (!options.dump_cms.empty() && platform::same_file(path, options.dump_cms))
        throw std::runtime_error("--dump-cms must not refer to the input file");
    const auto kind = identify(path);
    if (kind == Kind::Pe) (void)pe_has_signature(path); // reject malformed certificate tables
    const auto parent = utf8(from_utf8(path).parent_path());
    platform::TempDir work(parent.empty() ? "." : parent);
    const auto staged = work.path() + "/input" + extension(path);
    platform::copy_file(path, staged);
    if (kind == Kind::Msi && options.recursive) {
        auto payload_options = options;
        payload_options.dump_cms.clear();
        payload_options.recursive = false;
        const auto counts = rewrite_msi_payload(staged,
            [&](const std::string &payload, const std::string &display_name) {
                if (pe_has_signature(payload)) {
                    log("Preserved signed payload: " + display_name + "\n");
                    return false;
                }
                log("Signing payload: " + display_name + "\n");
                sign_staged(payload, Kind::Pe, payload_options, sign_digest, log);
                return true;
            });
        log("MSI payloads: " + std::to_string(counts.signed_files) + " signed, " +
            std::to_string(counts.preserved_files) + " preserved\n");
    }
    sign_staged(staged, kind, options, sign_digest, log);
    platform::atomic_replace_file(staged, path);
    log("Signed " + path + " successfully.\n");
}
