// This executable alone accepts a fixture private key. Production aas-sign
// always uses Azure; the injection exercises the same adapter/CMS implementation.
#include "signing.hpp"
#include "platform.hpp"
#include <stdexcept>
#include <string>
#include <vector>

int aas_sign_main(int argc, char **argv)
{
    try {
        if (argc < 5) throw std::runtime_error("usage: driver OSSLSIGNCODE KEY CERT_DER INPUT [options]");
        SigningOptions options;
        options.osslsigncode = resolve_osslsigncode(argv[1]);
        options.no_timestamp = true;
        std::string key = argv[2], certificate = argv[3], input = argv[4];
        unsigned fail_at = 0, requests = 0;
        for (int i = 5; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--recursive") options.recursive = true;
            else if (arg == "--msi-dse") options.msi_dse = true;
            else if (arg == "--dump-cms" && i + 1 < argc) options.dump_cms = argv[++i];
            else if (arg == "--timestamp-url" && i + 1 < argc) {
                options.timestamp_url = argv[++i]; options.no_timestamp = false;
            } else if (arg == "--fail-sign" && i + 1 < argc) fail_at = unsigned(std::stoul(argv[++i]));
            else throw std::runtime_error("unknown test option: " + arg);
        }
        auto read = [](const std::string &path) {
            platform::File f(path);
            std::vector<uint8_t> bytes(static_cast<size_t>(f.size()));
            f.read_at(0, bytes.data(), bytes.size());
            return bytes;
        };
        auto cert = read(certificate);
        platform::TempDir work("");
        auto openssl = platform::find_executable("openssl");
        sign_file(input, options, [&](const std::array<uint8_t, 32> &digest) {
            if (++requests == fail_at) throw std::runtime_error("injected signing failure");
            const auto in = work.path() + "/hash.bin", out = work.path() + "/rsa.bin";
            platform::write_whole_file(in, digest.data(), digest.size());
            auto r = platform::run_process(openssl, {"pkeyutl", "-sign", "-inkey", key,
                "-pkeyopt", "digest:sha256", "-in", in, "-out", out});
            if (r.exit_code) throw std::runtime_error("test signing failed: " + r.output);
            return AzureSignResult{read(out), cert};
        }, [](const std::string &line) { platform::write_stderr(line); });
        return 0;
    } catch (const std::exception &e) {
        platform::write_stderr(std::string("error: ") + e.what() + "\n");
        return 1;
    }
}

#ifndef _WIN32
int main(int argc, char **argv) { return aas_sign_main(argc, argv); }
#endif
