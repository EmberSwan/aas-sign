#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace platform {

// Write `bytes` to stdout/stderr as UTF-8.  If the handle is a
// Windows console, transcodes to UTF-16 and uses WriteConsoleW so
// non-ASCII characters render correctly regardless of the console's
// active code page.  If the handle is redirected (file or pipe),
// writes the UTF-8 bytes verbatim -- the right thing for
// `aas-sign ... 2> log.txt` and `| tee`.  On POSIX: plain write(2)
// in a loop.
//
// Best-effort: errors are swallowed (matches std::cerr, which also
// silently drops).  Partial writes are retried until the buffer is
// drained or write() returns a hard error.  Feature code builds a
// string in memory (std::string or std::ostringstream) and hands
// the finished UTF-8 bytes to these functions; no formatting is
// performed here.
void write_stdout(std::string_view bytes);
void write_stderr(std::string_view bytes);

struct ProcessResult {
    int exit_code;
    // Merged stdout/stderr, limited to the first 1 MiB. The pipe is
    // drained completely even when output exceeds this limit.
    std::string output;
};

// Execute directly (no shell). Arguments and paths are UTF-8. Stdin is
// closed/empty, and nonzero child exits are returned rather than thrown.
// Spawn or capture errors throw with the executable/operation context.
// Azure/GitHub token environment variables are withheld from companions;
// ordinary environment settings (PATH, CA bundles, proxies) are inherited.
ProcessResult run_process(const std::string &executable,
                          const std::vector<std::string> &args);
std::string executable_path();
// Resolve an executable using PATH, or validate a supplied path. Returns
// an absolute path and throws if no executable regular file is found.
std::string find_executable(const std::string &name);

// Private staging workspace. An empty parent selects the system temporary
// directory; a target's parent keeps staging on its filesystem for rename.
class TempDir {
public:
    explicit TempDir(const std::string &parent = {});
    ~TempDir();
    TempDir(const TempDir &) = delete;
    TempDir &operator=(const TempDir &) = delete;
    const std::string &path() const { return path_; }
private:
    std::string path_;
};

// Copy a regular file to a new path, preserving its permission mode.
// The destination must not already exist.
void copy_file(const std::string &from, const std::string &to);
// Compare filesystem identity, following symlinks and recognizing hard links.
// Returns false if either path is absent; throws on other inspection errors.
bool same_file(const std::string &first, const std::string &second);
// Flush and atomically replace an existing regular file with a stage on
// the same filesystem. Preserve original permissions/security metadata.
// A failed pre-commit operation leaves the destination unchanged.
void atomic_replace_file(const std::string &staged,
                         const std::string &destination);

struct Sha256 {
    Sha256();
    ~Sha256();
    Sha256(const Sha256 &) = delete;
    Sha256 &operator=(const Sha256 &) = delete;
    void update(const uint8_t *data, size_t len);
    std::array<uint8_t, 32> finish();
    void *ctx;
};

std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len);

struct HttpResponse {
    int status;
    std::string body;
};

// Thrown when a network operation fails in a way that's likely
// transient -- DNS, TCP connect, TLS handshake, mid-request socket
// I/O.  The public HTTP entry points retry these a small number of
// times before giving up; permanent failures (config errors,
// missing CA bundle, malformed responses, etc.) continue to throw
// plain std::runtime_error so the retry loop doesn't mask them.
class TransientNetworkError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Call `op()` up to `max_attempts` times, retrying on
// TransientNetworkError with linear backoff (2 s, 4 s, ...).  If
// every attempt fails, re-throws the last exception.  Caller must
// ensure `op` is safe to call more than once -- our HTTPS/HTTP
// operations all are: Azure signing produces a fresh signature for
// the same hash, the TSA produces a fresh timestamp, the OAuth
// token endpoint returns a (server-cached) token.
template <class F>
auto retry_transient(F &&op, int max_attempts = 3) -> decltype(op())
{
    for (int attempt = 1; ; ++attempt) {
        try {
            return op();
        } catch (const TransientNetworkError &e) {
            if (attempt >= max_attempts) throw;
            std::ostringstream msg;
            msg << "transient network error: " << e.what()
                << "; retrying (attempt " << (attempt + 1)
                << " of " << max_attempts << ")\n";
            write_stderr(msg.str());
            std::this_thread::sleep_for(std::chrono::seconds(attempt * 2));
        }
    }
}

HttpResponse https_post(const std::string &host, const std::string &path,
                        const std::string &bearer_token,
                        const std::string &json_body);

HttpResponse https_get(const std::string &host, const std::string &path,
                       const std::string &bearer_token);

// Plain HTTP POST with a binary body.  Used for RFC 3161 timestamping where
// integrity is guaranteed by the TSA's own signature rather than TLS.
HttpResponse http_post_binary(const std::string &host, int port,
                              const std::string &path,
                              const std::string &content_type,
                              const std::string &accept,
                              const std::vector<uint8_t> &body);

// HTTPS helpers that take a full URL.  Used by the OIDC flow, where one
// endpoint comes from runner-injected env vars and the other is a
// Microsoft login URL parameterised by tenant ID.
HttpResponse https_get_url(const std::string &url,
                           const std::string &bearer_token);

HttpResponse https_post_url(const std::string &url,
                            const std::string &content_type,
                            const std::string &body);

// Disable TLS certificate verification on all subsequent HTTPS calls
// (POSIX: mbedTLS authmode VERIFY_NONE; Windows: WinHTTP security flags
// ignoring CA / CN / date / usage).  Defaults to verification enabled
// using the system CA bundle.  Intended to be called once at startup
// when --insecure is passed.  Not thread-safe; call before any signing
// thread spawns.
void tls_disable_verification();

// Override the CA bundle path used for TLS verification.  Takes
// precedence over $SSL_CERT_FILE and the well-known-paths probe.
// POSIX only -- on Windows, WinHTTP verifies against the system
// certificate store and pinning to a single bundle file isn't
// straightforward; this function is a no-op there and the caller
// gets a one-line stderr note instead.  Like tls_disable_verification,
// not thread-safe; call once at startup.
void tls_set_ca_bundle(const std::string &path);

// 64-bit-offset file I/O with checked error handling.  Paths are UTF-8
// on all platforms (transcoded to UTF-16 for Windows CreateFileW).
// Every method throws std::runtime_error on error or short transfer.
class File {
public:
    // Open an existing file for read+write.  Throws if the file does
    // not exist or cannot be opened.
    explicit File(const std::string &utf8_path);
    ~File();
    File(const File &) = delete;
    File &operator=(const File &) = delete;

    uint64_t size();
    void read_at(uint64_t offset, void *buf, size_t len);
    void write_at(uint64_t offset, const void *buf, size_t len);
    void truncate(uint64_t new_size);
    void flush();

private:
    std::string path_;  // kept for error messages
    void *impl_;        // HANDLE on Windows, (void *)(intptr_t) fd on POSIX
};

// Create or overwrite a file and write exactly `len` bytes.  Throws on
// any error.  The UTF-8 path is transcoded as needed.
void write_whole_file(const std::string &utf8_path,
                      const uint8_t *data, size_t len);

// Atomically create or replace `utf8_path` with exactly `len` bytes of
// `data`.  Written via a sibling tempfile + rename, so a concurrent
// reader sees either the old contents or the new -- never a torn
// write.  POSIX: tempfile is created mode 0600 (user-only), fsync
// before rename.  Windows: relies on NTFS default ACL, which is
// already per-user under %APPDATA%.  Used for token caches and similar
// private per-user files.
void atomic_write_private_file(const std::string &utf8_path,
                               const uint8_t *data, size_t len);

// Delete `utf8_path` if it exists; no-op if missing.  Throws on other
// errors (permission denied, etc.).
void remove_file(const std::string &utf8_path);

// Loopback HTTP server used for the OAuth redirect in `aas-sign login`.
// Binds to 127.0.0.1 on an OS-assigned port, accepts exactly one
// connection, reads one HTTP request line, and sends one response.
//
// The caller reads the request path+query via accept_request() and
// then calls respond() with a tiny HTML body to display in the
// browser.  Single-use; destroy + construct fresh for another round.
class LoopbackServer {
public:
    LoopbackServer();
    ~LoopbackServer();
    LoopbackServer(const LoopbackServer &) = delete;
    LoopbackServer &operator=(const LoopbackServer &) = delete;

    int port() const;
    // Accept one connection, read the request.  Returns the request
    // target (the "/foo?bar=baz" part of "GET /foo?bar=baz HTTP/1.1").
    // Throws on IO error.
    std::string accept_request();
    // Send a minimal 200 OK response with the given HTML body, then
    // close.  Must be called after accept_request().
    void respond(const std::string &html);

private:
    void *impl_;  // fd (POSIX) or SOCKET (Windows), boxed via intptr_t
    int  port_;
    void *client_impl_;  // fd/SOCKET of the accepted client connection
};

// Launch the system's default web browser on the given URL.  Returns
// immediately; does not wait for the browser to exit.  Used for the
// OAuth authorize-URL redirect in `aas-sign login`.  Throws on fork/
// ShellExecute failure.
void launch_browser(const std::string &url);

// Return the per-user config directory aas-sign should use, creating
// it (with parent directories, 0700 perms on POSIX) if needed:
//   POSIX:   ${XDG_CONFIG_HOME:-$HOME/.config}/aas-sign
//   Windows: %APPDATA%\aas-sign
// Throws if neither is available.
std::string config_dir();

}  // namespace platform
