#include "app.hpp"
#include "narrow.hpp"
#include "platform.hpp"

#include <mbedtls/sha256.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#if defined(MBEDTLS_PSA_CRYPTO_C) || defined(MBEDTLS_PSA_CRYPTO_CLIENT)
#include <psa/crypto.h>
#endif

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <spawn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include <algorithm>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <utility>

extern char **environ;

namespace platform {

// --- Console output ---

namespace {
void write_fd_all(int fd, std::string_view bytes)
{
    const char *p = bytes.data();
    size_t left = bytes.size();
    while (left > 0) {
        ssize_t n = ::write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;  // best-effort; match std::cerr's silent-fail
        }
        if (n == 0) return;
        p += n;
        left -= size_t(n);
    }
}
}  // namespace

void write_stdout(std::string_view bytes) { write_fd_all(STDOUT_FILENO, bytes); }
void write_stderr(std::string_view bytes) { write_fd_all(STDERR_FILENO, bytes); }

// --- SHA-256 ---

Sha256::Sha256()
{
    auto *c = new mbedtls_sha256_context;
    mbedtls_sha256_init(c);
    mbedtls_sha256_starts(c, 0);
    ctx = c;
}

Sha256::~Sha256()
{
    auto *c = static_cast<mbedtls_sha256_context *>(ctx);
    mbedtls_sha256_free(c);
    delete c;
}

void Sha256::update(const uint8_t *data, size_t len)
{
    mbedtls_sha256_update(static_cast<mbedtls_sha256_context *>(ctx),
                          data, len);
}

std::array<uint8_t, 32> Sha256::finish()
{
    std::array<uint8_t, 32> hash;
    mbedtls_sha256_finish(static_cast<mbedtls_sha256_context *>(ctx),
                          hash.data());
    return hash;
}

std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len)
{
    std::array<uint8_t, 32> hash;
    mbedtls_sha256(data, len, hash.data(), 0);
    return hash;
}

// --- Minimal HTTPS client using mbedTLS ---

static std::string mbed_error(int ret)
{
    char buf[256];
    mbedtls_strerror(ret, buf, sizeof(buf));
    return buf;
}

static bool tls_wants_io(int ret)
{
    return ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE;
}

static bool tls_received_session_ticket(int ret)
{
#ifdef MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
    // mbedTLS 3.6.0 surfaced received TLS 1.3 session tickets to the caller.
    // Later 3.6 releases ignore them internally by default.
    return ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
#else
    (void)ret;
    return false;
#endif
}

static void ensure_psa_crypto()
{
#if defined(MBEDTLS_PSA_CRYPTO_C) || defined(MBEDTLS_PSA_CRYPTO_CLIENT)
    static std::once_flag once;
    std::call_once(once, [] {
        psa_status_t status = psa_crypto_init();
        if (status != PSA_SUCCESS)
            throw std::runtime_error(
                "psa_crypto_init failed (PSA status " +
                std::to_string(status) + ")");
    });
#endif
}

// Some system mbedTLS packages disable threading, and releases before 3.6 do
// not apply their threading support to all PSA global state.  Keep those
// builds safe by allowing only one complete TLS connection at a time.  The
// bundled build enables mbedTLS's current pthread support instead.
#if !defined(MBEDTLS_THREADING_C) || \
    MBEDTLS_VERSION_NUMBER < 0x03060000
#define AAS_SIGN_SERIALIZE_MBEDTLS
static std::mutex g_mbedtls_mutex;
#endif

// TLS verification mode.  Defaults to verifying against the system CA
// bundle.  --insecure flips this off for the rest of the process via
// platform::tls_disable_verification().  Set once at startup, before
// any worker threads spawn -- so a plain bool is fine, no atomics or
// mutex needed.
static bool g_tls_insecure = false;
// Optional explicit CA bundle path from --cacert, overriding both
// $SSL_CERT_FILE and the well-known-paths probe below.
static std::string g_ca_bundle_override;

void tls_disable_verification() { g_tls_insecure = true; }
void tls_set_ca_bundle(const std::string &path) { g_ca_bundle_override = path; }

// Locate a system CA bundle.  Order: explicit --cacert override,
// then $SSL_CERT_FILE (curl/Go/OpenSSL convention), then the
// bundles each major distro family ships at a known absolute path,
// then a few Homebrew/MacPorts fallbacks.  All of these are PEM
// files containing many concatenated certificates -- the format
// mbedtls_x509_crt_parse_file accepts directly.  Returns the empty
// string when none of the paths exists.
static std::string find_ca_bundle()
{
    if (!g_ca_bundle_override.empty())
        return g_ca_bundle_override;
    if (const char *p = std::getenv("SSL_CERT_FILE"); p && *p) {
        struct stat st;
        if (::stat(p, &st) == 0)
            return p;
    }
    static const char *paths[] = {
        "/etc/ssl/certs/ca-certificates.crt",       // Debian/Ubuntu/Arch
        "/etc/pki/tls/certs/ca-bundle.crt",         // RHEL/CentOS/Fedora
        "/etc/ssl/ca-bundle.pem",                   // OpenSUSE
        "/etc/ssl/cert.pem",                        // Alpine/FreeBSD/macOS Homebrew
        "/etc/pki/tls/cacert.pem",
        "/usr/local/share/certs/ca-root-nss.crt",   // FreeBSD ports
        "/usr/local/etc/openssl@3/cert.pem",        // Homebrew (Intel)
        "/opt/homebrew/etc/openssl@3/cert.pem",     // Homebrew (Apple Silicon)
    };
    for (const char *p : paths) {
        struct stat st;
        if (::stat(p, &st) == 0)
            return p;
    }
    return "";
}

struct TlsConnection {
#ifdef AAS_SIGN_SERIALIZE_MBEDTLS
    // Declared first so it remains held while all mbedTLS contexts are freed.
    std::unique_lock<std::mutex> mbedtls_lock{g_mbedtls_mutex};
#endif
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    TlsConnection(const std::string &host)
    {
        ensure_psa_crypto();

        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
        mbedtls_x509_crt_init(&cacert);

        try {
            int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                            &entropy, nullptr, 0);
            if (ret != 0)
                throw std::runtime_error("mbedtls_ctr_drbg_seed: " +
                                         mbed_error(ret));

            ret = mbedtls_net_connect(&server_fd, host.c_str(), "443",
                                      MBEDTLS_NET_PROTO_TCP);
            if (ret != 0)
                throw TransientNetworkError(
                    "connect to " + host + ":443: " + mbed_error(ret));

            ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                              MBEDTLS_SSL_TRANSPORT_STREAM,
                                              MBEDTLS_SSL_PRESET_DEFAULT);
            if (ret != 0)
                throw std::runtime_error("ssl_config_defaults: " +
                                         mbed_error(ret));

            if (g_tls_insecure) {
                mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
            } else {
                std::string bundle = find_ca_bundle();
                if (bundle.empty())
                    throw std::runtime_error(
                        "no CA certificate bundle found at any standard "
                        "location; install ca-certificates, set "
                        "SSL_CERT_FILE, or pass --insecure to skip "
                        "TLS verification");
                // Positive return = number of certs that failed to parse;
                // we tolerate that as long as some certs loaded.  Negative
                // = hard error.
                ret = mbedtls_x509_crt_parse_file(&cacert, bundle.c_str());
                if (ret < 0)
                    throw std::runtime_error(
                        "failed to parse CA bundle " + bundle + ": " +
                        mbed_error(ret));
                mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
                mbedtls_ssl_conf_authmode(&conf,
                                          MBEDTLS_SSL_VERIFY_REQUIRED);
            }
            mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

            ret = mbedtls_ssl_setup(&ssl, &conf);
            if (ret != 0)
                throw std::runtime_error("ssl_setup: " + mbed_error(ret));

            // SNI + (when verifying) cert hostname check.
            ret = mbedtls_ssl_set_hostname(&ssl, host.c_str());
            if (ret != 0)
                throw std::runtime_error("ssl_set_hostname: " +
                                         mbed_error(ret));

            mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send,
                                mbedtls_net_recv, nullptr);

            while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
                if (tls_wants_io(ret) || tls_received_session_ticket(ret))
                    continue;
                throw TransientNetworkError("TLS handshake with " + host +
                                            ": " + mbed_error(ret));
            }
        } catch (...) {
            free_contexts(false);
            throw;
        }
    }

    ~TlsConnection()
    {
        free_contexts(true);
    }

    TlsConnection(const TlsConnection &) = delete;
    TlsConnection &operator=(const TlsConnection &) = delete;

private:
    void free_contexts(bool notify) noexcept
    {
        if (notify)
            mbedtls_ssl_close_notify(&ssl);
        mbedtls_net_free(&server_fd);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_x509_crt_free(&cacert);
    }

public:
    void write_all(const std::string &data)
    {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(data.data());
        size_t remaining = data.size();
        while (remaining > 0) {
            int ret = mbedtls_ssl_write(&ssl, p, remaining);
            if (ret == 0)
                throw TransientNetworkError(
                    "ssl_write: connection closed without progress");
            if (ret < 0) {
                if (tls_wants_io(ret)) continue;
                // Retrying the same write after a 3.6.0 session-ticket
                // notification can duplicate a partially flushed TLS record.
                // Reconnect and retry the complete idempotent HTTP operation.
                if (tls_received_session_ticket(ret))
                    throw TransientNetworkError(
                        "ssl_write interrupted by TLS session ticket");
                throw TransientNetworkError("ssl_write: " + mbed_error(ret));
            }
            p += ret;
            remaining -= narrow<size_t>(ret);
        }
    }

    std::string read_all()
    {
        std::string result;
        uint8_t buf[4096];
        for (;;) {
            int ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
            if (tls_wants_io(ret) || tls_received_session_ticket(ret))
                continue;
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
                break;
            if (ret < 0)
                throw TransientNetworkError("ssl_read: " + mbed_error(ret));
            result.append(reinterpret_cast<char *>(buf), narrow<size_t>(ret));
        }
        return result;
    }
};

static HttpResponse parse_http_response(const std::string &raw)
{
    HttpResponse resp;
    // Parse status line.
    auto line_end = raw.find("\r\n");
    if (line_end == std::string::npos)
        throw std::runtime_error("malformed HTTP response");
    // "HTTP/1.1 200 OK"
    auto sp1 = raw.find(' ');
    if (sp1 == std::string::npos)
        throw std::runtime_error("malformed HTTP status line");
    resp.status = std::stoi(raw.substr(sp1 + 1, 3));

    // Find body (after \r\n\r\n).
    auto body_start = raw.find("\r\n\r\n");
    if (body_start != std::string::npos)
        resp.body = raw.substr(body_start + 4);

    // Handle chunked transfer encoding.
    if (raw.find("Transfer-Encoding: chunked") != std::string::npos ||
        raw.find("transfer-encoding: chunked") != std::string::npos) {
        std::string decoded;
        const std::string &src = resp.body;
        size_t pos = 0;
        while (pos < src.size()) {
            auto nl = src.find("\r\n", pos);
            if (nl == std::string::npos) break;
            size_t chunk_len = std::stoul(src.substr(pos, nl - pos),
                                          nullptr, 16);
            if (chunk_len == 0) break;
            pos = nl + 2;
            decoded.append(src, pos, chunk_len);
            pos += chunk_len + 2;  // skip \r\n after chunk
        }
        resp.body = decoded;
    }

    return resp;
}

static HttpResponse do_request(const std::string &host,
                               const std::string &method,
                               const std::string &path,
                               const std::string &bearer_token,
                               const std::string *body)
{
    TlsConnection conn(host);

    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n";
    req << "Host: " << host << "\r\n";
    req << "Authorization: Bearer " << bearer_token << "\r\n";
    req << "Connection: close\r\n";
    if (body) {
        req << "Content-Type: application/json; charset=utf-8\r\n";
        req << "Content-Length: " << body->size() << "\r\n";
    }
    req << "\r\n";
    if (body) req << *body;

    conn.write_all(req.str());
    auto raw = conn.read_all();
    return parse_http_response(raw);
}

HttpResponse https_post(const std::string &host, const std::string &path,
                        const std::string &bearer_token,
                        const std::string &json_body)
{
    return retry_transient([&] {
        return do_request(host, "POST", path, bearer_token, &json_body);
    });
}

HttpResponse https_get(const std::string &host, const std::string &path,
                       const std::string &bearer_token)
{
    return retry_transient([&] {
        return do_request(host, "GET", path, bearer_token, nullptr);
    });
}

// Parse "https://host[:port]/path?query" into components.  The port is
// ignored (TlsConnection hardcodes 443) since every endpoint we speak
// to HTTPS on is on the default port.
static void parse_https_url(const std::string &url,
                            std::string &host, std::string &path_and_query)
{
    const std::string scheme = "https://";
    if (url.compare(0, scheme.size(), scheme) != 0)
        throw std::runtime_error("expected https:// URL, got: " + url);
    size_t host_start = scheme.size();
    size_t path_start = url.find('/', host_start);
    host = (path_start == std::string::npos)
        ? url.substr(host_start)
        : url.substr(host_start, path_start - host_start);
    path_and_query = (path_start == std::string::npos)
        ? "/" : url.substr(path_start);
    // If host carries a :port suffix we just drop it (we always hit 443).
    auto colon = host.find(':');
    if (colon != std::string::npos)
        host.erase(colon);
}

HttpResponse https_get_url(const std::string &url,
                           const std::string &bearer_token)
{
    return retry_transient([&] {
        std::string host, path;
        parse_https_url(url, host, path);

        TlsConnection conn(host);
        std::ostringstream req;
        req << "GET " << path << " HTTP/1.1\r\n"
            << "Host: " << host << "\r\n"
            << "User-Agent: aas-sign/1.0\r\n"
            << "Accept: application/json\r\n"
            << "Authorization: Bearer " << bearer_token << "\r\n"
            << "Connection: close\r\n\r\n";
        conn.write_all(req.str());
        return parse_http_response(conn.read_all());
    });
}

HttpResponse https_post_url(const std::string &url,
                            const std::string &content_type,
                            const std::string &body)
{
    return retry_transient([&] {
        std::string host, path;
        parse_https_url(url, host, path);

        TlsConnection conn(host);
        std::ostringstream req;
        req << "POST " << path << " HTTP/1.1\r\n"
            << "Host: " << host << "\r\n"
            << "User-Agent: aas-sign/1.0\r\n"
            << "Accept: application/json\r\n"
            << "Content-Type: " << content_type << "\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "Connection: close\r\n\r\n"
            << body;
        conn.write_all(req.str());
        return parse_http_response(conn.read_all());
    });
}

HttpResponse http_post_binary(const std::string &host, int port,
                              const std::string &path,
                              const std::string &content_type,
                              const std::string &accept,
                              const std::vector<uint8_t> &body)
{
    return retry_transient([&] {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        std::string port_str = std::to_string(port);
        addrinfo *res = nullptr;
        int gai = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
        if (gai != 0)
            throw TransientNetworkError("getaddrinfo " + host + ": " +
                                        gai_strerror(gai));

        int fd = -1;
        for (addrinfo *a = res; a; a = a->ai_next) {
            fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
            if (fd < 0) continue;
            if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
            close(fd);
            fd = -1;
        }
        freeaddrinfo(res);
        if (fd < 0)
            throw TransientNetworkError("cannot connect to " + host + ":" +
                                        port_str);

        std::ostringstream req;
        req << "POST " << path << " HTTP/1.1\r\n";
        req << "Host: " << host;
        if (port != 80) req << ":" << port;
        req << "\r\n";
        req << "User-Agent: aas-sign/1.0\r\n";
        req << "Content-Type: " << content_type << "\r\n";
        if (!accept.empty())
            req << "Accept: " << accept << "\r\n";
        req << "Content-Length: " << body.size() << "\r\n";
        req << "Connection: close\r\n\r\n";
        std::string header = req.str();

        auto write_n = [&](const uint8_t *p, size_t n) {
            while (n > 0) {
                ssize_t w = write(fd, p, n);
                if (w <= 0) {
                    close(fd);
                    throw TransientNetworkError("write to TSA failed");
                }
                p += w;
                n -= size_t(w);
            }
        };
        write_n(reinterpret_cast<const uint8_t *>(header.data()), header.size());
        if (!body.empty())
            write_n(body.data(), body.size());

        std::string raw;
        char buf[4096];
        for (;;) {
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r < 0) {
                close(fd);
                throw TransientNetworkError("read from TSA failed");
            }
            if (r == 0) break;
            raw.append(buf, size_t(r));
        }
        close(fd);

        return parse_http_response(raw);
    });
}

// --- File I/O ---

static int file_fd(const File &f, void *impl)
{
    // impl_ holds (fd + 1) so we can distinguish "unset" (nullptr) from fd 0.
    (void)f;
    return int(reinterpret_cast<intptr_t>(impl)) - 1;
}

static std::string errno_msg(const char *op, const std::string &path)
{
    std::ostringstream s;
    s << op << " " << path << ": " << std::strerror(errno);
    return s.str();
}

File::File(const std::string &utf8_path) : path_(utf8_path), impl_(nullptr)
{
    int fd = ::open(path_.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0)
        throw std::runtime_error(errno_msg("open", path_));
    impl_ = reinterpret_cast<void *>(intptr_t(fd + 1));
}

File::~File()
{
    int fd = file_fd(*this, impl_);
    if (fd >= 0) ::close(fd);
}

uint64_t File::size()
{
    int fd = file_fd(*this, impl_);
    struct stat st;
    if (::fstat(fd, &st) < 0)
        throw std::runtime_error(errno_msg("fstat", path_));
    return uint64_t(st.st_size);
}

void File::read_at(uint64_t offset, void *buf, size_t len)
{
    int fd = file_fd(*this, impl_);
    uint8_t *p = static_cast<uint8_t *>(buf);
    while (len > 0) {
        ssize_t n = ::pread(fd, p, len, off_t(offset));
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(errno_msg("pread", path_));
        }
        if (n == 0)
            throw std::runtime_error("pread " + path_ +
                                     ": unexpected EOF");
        p += n;
        offset += uint64_t(n);
        len -= size_t(n);
    }
}

void File::write_at(uint64_t offset, const void *buf, size_t len)
{
    int fd = file_fd(*this, impl_);
    const uint8_t *p = static_cast<const uint8_t *>(buf);
    while (len > 0) {
        ssize_t n = ::pwrite(fd, p, len, off_t(offset));
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(errno_msg("pwrite", path_));
        }
        if (n == 0)
            throw std::runtime_error("pwrite " + path_ +
                                     ": zero bytes written");
        p += n;
        offset += uint64_t(n);
        len -= size_t(n);
    }
}

void File::truncate(uint64_t new_size)
{
    int fd = file_fd(*this, impl_);
    if (::ftruncate(fd, off_t(new_size)) < 0)
        throw std::runtime_error(errno_msg("ftruncate", path_));
}

void File::flush()
{
    int fd = file_fd(*this, impl_);
    // fsync would be overkill for a local file-edit; fdatasync is fine
    // where available, but fsync is the portable choice.
    if (::fsync(fd) < 0 && errno != EINVAL) {
        // Some filesystems (e.g. /tmp on some platforms) reject fsync
        // with EINVAL; treat as best-effort.
        throw std::runtime_error(errno_msg("fsync", path_));
    }
}

void write_whole_file(const std::string &utf8_path,
                      const uint8_t *data, size_t len)
{
    int fd = ::open(utf8_path.c_str(),
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        throw std::runtime_error(errno_msg("open(write)", utf8_path));
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            int saved = errno;
            ::close(fd);
            errno = saved;
            throw std::runtime_error(errno_msg("write", utf8_path));
        }
        off += size_t(n);
    }
    if (::close(fd) < 0)
        throw std::runtime_error(errno_msg("close", utf8_path));
}

void atomic_write_private_file(const std::string &utf8_path,
                               const uint8_t *data, size_t len)
{
    std::string tmp = utf8_path + ".tmp";
    int fd = ::open(tmp.c_str(),
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        throw std::runtime_error(errno_msg("open(write)", tmp));
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            int saved = errno; ::close(fd); errno = saved;
            throw std::runtime_error(errno_msg("write", tmp));
        }
        off += size_t(n);
    }
    ::fsync(fd);
    if (::close(fd) < 0)
        throw std::runtime_error(errno_msg("close", tmp));
    if (::rename(tmp.c_str(), utf8_path.c_str()) < 0)
        throw std::runtime_error(errno_msg("rename", utf8_path));
}

void remove_file(const std::string &utf8_path)
{
    if (::unlink(utf8_path.c_str()) < 0 && errno != ENOENT)
        throw std::runtime_error(errno_msg("unlink", utf8_path));
}

// --- Companion processes and private staging ---

namespace {
struct ScopedFd {
    int value = -1;
    explicit ScopedFd(int fd = -1) : value(fd) {}
    ~ScopedFd() { if (value >= 0) ::close(value); }
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
};

std::string absolute_path(const std::string &path)
{
    std::error_code ec;
    auto result = std::filesystem::absolute(path, ec);
    if (ec) throw std::runtime_error("resolve " + path + ": " + ec.message());
    return result.lexically_normal().string();
}

bool is_executable(const std::string &path)
{
    struct stat st;
    return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
           ::access(path.c_str(), X_OK) == 0;
}

bool private_environment(std::string_view name)
{
    return name.starts_with("AZURE_") || name.starts_with("ACTIONS_ID_TOKEN_") ||
           name == "GH_TOKEN" || name == "GITHUB_TOKEN" || name == "INPUT_TOKEN" ||
           name == "GH_ENTERPRISE_TOKEN" || name == "GITHUB_ENTERPRISE_TOKEN";
}
}  // namespace

std::string find_executable(const std::string &name)
{
    if (name.empty() || name.find('\0') != std::string::npos)
        throw std::runtime_error("find executable: empty or invalid name");
    if (name.find('/') != std::string::npos) {
        if (is_executable(name)) return absolute_path(name);
        throw std::runtime_error("find executable " + name + ": not an executable file");
    }
    const char *env = std::getenv("PATH");
    std::string path = env ? env : "/usr/bin:/bin";
    size_t first = 0;
    for (;;) {
        size_t last = path.find(':', first);
        std::string dir = path.substr(first, last - first);
        std::string candidate = (dir.empty() ? "." : dir) + "/" + name;
        if (is_executable(candidate)) return absolute_path(candidate);
        if (last == std::string::npos) break;
        first = last + 1;
    }
    throw std::runtime_error("find executable " + name + ": not found on PATH");
}

std::string executable_path()
{
#ifdef __APPLE__
    uint32_t length = 0;
    _NSGetExecutablePath(nullptr, &length);
    std::vector<char> buffer(length);
    if (_NSGetExecutablePath(buffer.data(), &length) != 0)
        throw std::runtime_error("_NSGetExecutablePath: path exceeds buffer");
    return absolute_path(buffer.data());
#else
    std::vector<char> buffer(1024);
    for (;;) {
        ssize_t n = ::readlink("/proc/self/exe", buffer.data(), buffer.size());
        if (n < 0) throw std::runtime_error(errno_msg("readlink", "/proc/self/exe"));
        if (size_t(n) < buffer.size()) return std::string(buffer.data(), size_t(n));
        if (buffer.size() >= 1024 * 1024)
            throw std::runtime_error("readlink /proc/self/exe: path exceeds 1 MiB");
        buffer.resize(buffer.size() * 2);
    }
#endif
}

ProcessResult run_process(const std::string &executable,
                          const std::vector<std::string> &args)
{
    std::string resolved = find_executable(executable);
    std::vector<char *> argv;
    argv.reserve(args.size() + 2);
    argv.push_back(resolved.data());
    for (const auto &arg : args) {
        if (arg.find('\0') != std::string::npos)
            throw std::runtime_error("execute " + executable + ": argument contains NUL");
        argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);
    std::vector<std::string> environment;
    for (char **entry = environ; entry && *entry; ++entry) {
        std::string value(*entry);
        if (!private_environment(std::string_view(value).substr(0, value.find('='))))
            environment.push_back(std::move(value));
    }
    std::vector<char *> envp;
    envp.reserve(environment.size() + 1);
    for (auto &entry : environment) envp.push_back(entry.data());
    envp.push_back(nullptr);
    ProcessResult result{0, {}};
    constexpr size_t output_limit = 1024 * 1024;
    // Allocate before spawning so an allocation failure cannot orphan a
    // child blocked on its output pipe. Appends below stay within capacity.
    result.output.reserve(output_limit);

    // Serialize descriptor setup/spawn so the portable pipe+fcntl fallback
    // cannot leak another worker's pipe into a concurrently spawned child.
    static std::mutex spawn_mutex;
    std::unique_lock<std::mutex> lock(spawn_mutex);
    int descriptors[2];
#ifdef __linux__
    if (::pipe2(descriptors, O_CLOEXEC) < 0)
#else
    if (::pipe(descriptors) < 0)
#endif
        throw std::runtime_error(errno_msg("pipe for", executable));
    ScopedFd read_end(descriptors[0]), write_end(descriptors[1]);
    // Keep source descriptors above stderr even when a caller closed stdio.
    for (ScopedFd *fd : {&read_end, &write_end}) {
        int replacement = ::fcntl(fd->value, F_DUPFD_CLOEXEC, 3);
        if (replacement < 0)
            throw std::runtime_error(errno_msg("duplicate pipe for", executable));
        ::close(fd->value);
        fd->value = replacement;
    }
    posix_spawn_file_actions_t actions;
    int error = posix_spawn_file_actions_init(&actions);
    if (error) throw std::runtime_error("spawn actions " + executable + ": " + std::strerror(error));
    struct ActionCleanup {
        posix_spawn_file_actions_t *actions;
        ~ActionCleanup() { posix_spawn_file_actions_destroy(actions); }
    } cleanup{&actions};
    auto check = [&](int code) {
        if (code) throw std::runtime_error("spawn actions " + executable + ": " + std::strerror(code));
    };
    check(posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0));
    check(posix_spawn_file_actions_adddup2(&actions, write_end.value, STDOUT_FILENO));
    check(posix_spawn_file_actions_adddup2(&actions, write_end.value, STDERR_FILENO));
    check(posix_spawn_file_actions_addclose(&actions, read_end.value));
    check(posix_spawn_file_actions_addclose(&actions, write_end.value));
#ifdef __GLIBC__
#if __GLIBC_PREREQ(2, 34)
    // Close unrelated parent sockets/files too, even if a dependency did
    // not mark them CLOEXEC. The duplicated standard handles survive.
    check(posix_spawn_file_actions_addclosefrom_np(&actions, 3));
#endif
#endif
    posix_spawnattr_t attributes;
    check(posix_spawnattr_init(&attributes));
    struct AttributeCleanup {
        posix_spawnattr_t *attributes;
        ~AttributeCleanup() { posix_spawnattr_destroy(attributes); }
    } attribute_cleanup{&attributes};
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    // Darwin provides default-close semantics; explicit dup2/open file
    // actions above select the only descriptors inherited by the child.
    check(posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT));
#endif
    pid_t pid = -1;
    error = posix_spawn(&pid, resolved.c_str(), &actions, &attributes, argv.data(), envp.data());
    if (error) throw std::runtime_error("execute " + executable + ": " + std::strerror(error));
    ::close(write_end.value);
    write_end.value = -1;
    lock.unlock();

    char buffer[16384];
    int read_error = 0;
    for (;;) {
        ssize_t n = ::read(read_end.value, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR) continue;
            read_error = errno;
            ::kill(pid, SIGKILL);
            break;
        }
        if (n == 0) break;
        result.output.append(buffer, std::min(size_t(n), output_limit - result.output.size()));
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        throw std::runtime_error(errno_msg("wait for", executable));
    }
    if (read_error)
        throw std::runtime_error("capture " + executable + ": " + std::strerror(read_error));
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    return result;
}

TempDir::TempDir(const std::string &parent)
{
    std::error_code ec;
    std::string base = parent.empty() ? std::filesystem::temp_directory_path(ec).string() : parent;
    if (ec) throw std::runtime_error("temporary directory: " + ec.message());
    std::string pattern = absolute_path(base) + "/.aas-sign-XXXXXX";
    if (!::mkdtemp(pattern.data()))
        throw std::runtime_error(errno_msg("mkdtemp", pattern));
    path_ = std::move(pattern);
}

TempDir::~TempDir()
{
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
}

void copy_file(const std::string &from, const std::string &to)
{
    ScopedFd source(::open(from.c_str(), O_RDONLY | O_CLOEXEC));
    if (source.value < 0) throw std::runtime_error(errno_msg("open(copy)", from));
    struct stat st;
    if (::fstat(source.value, &st) < 0) throw std::runtime_error(errno_msg("fstat", from));
    if (!S_ISREG(st.st_mode)) throw std::runtime_error("copy " + from + ": not a regular file");
    ScopedFd target(::open(to.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    if (target.value < 0) throw std::runtime_error(errno_msg("create(copy)", to));
    try {
        char buffer[65536];
        for (;;) {
            ssize_t n = ::read(source.value, buffer, sizeof(buffer));
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error(errno_msg("read(copy)", from));
            }
            if (n == 0) break;
            ssize_t offset = 0;
            while (offset < n) {
                ssize_t written = ::write(target.value, buffer + offset, size_t(n - offset));
                if (written < 0 && errno == EINTR) continue;
                if (written <= 0) throw std::runtime_error(errno_msg("write(copy)", to));
                offset += written;
            }
        }
        if (::fchmod(target.value, st.st_mode & 07777) < 0)
            throw std::runtime_error(errno_msg("fchmod(copy)", to));
        int fd = target.value;
        target.value = -1;
        if (::close(fd) < 0) throw std::runtime_error(errno_msg("close(copy)", to));
    } catch (...) {
        ::unlink(to.c_str());
        throw;
    }
}

void atomic_replace_file(const std::string &staged, const std::string &destination)
{
    struct stat original;
    if (::lstat(destination.c_str(), &original) < 0)
        throw std::runtime_error(errno_msg("lstat(replace)", destination));
    if (!S_ISREG(original.st_mode))
        throw std::runtime_error("replace " + destination + ": not a regular file");
    ScopedFd stage(::open(staged.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW));
    if (stage.value < 0) throw std::runtime_error(errno_msg("open(replace)", staged));
    struct stat st;
    if (::fstat(stage.value, &st) < 0) throw std::runtime_error(errno_msg("fstat(replace)", staged));
    if (!S_ISREG(st.st_mode)) throw std::runtime_error("replace " + staged + ": not a regular file");
    if (original.st_dev == st.st_dev && original.st_ino == st.st_ino)
        throw std::runtime_error("replace " + destination + ": stage is the original file");
    if (st.st_uid != original.st_uid || st.st_gid != original.st_gid) {
        if (::fchown(stage.value, original.st_uid, original.st_gid) < 0)
            throw std::runtime_error(errno_msg("fchown(replace)", staged));
    }
    if (::fchmod(stage.value, original.st_mode & 07777) < 0)
        throw std::runtime_error(errno_msg("fchmod(replace)", staged));
    if (::fsync(stage.value) < 0)
        throw std::runtime_error(errno_msg("fsync(replace)", staged));
    if (::rename(staged.c_str(), destination.c_str()) < 0)
        throw std::runtime_error(errno_msg("rename(replace)", destination));
    // Rename has committed. Directory fsync improves crash durability, but
    // cannot turn a successful replacement into a reported failed operation.
    auto parent = std::filesystem::path(destination).parent_path();
    ScopedFd directory(::open((parent.empty() ? "." : parent.string()).c_str(),
                              O_RDONLY | O_CLOEXEC | O_DIRECTORY));
    if (directory.value >= 0) ::fsync(directory.value);
}

bool same_file(const std::string &first, const std::string &second)
{
    struct stat a, b;
    for (auto entry : {std::pair<const std::string *, struct stat *>{&first, &a},
                       std::pair<const std::string *, struct stat *>{&second, &b}}) {
        if (::stat(entry.first->c_str(), entry.second) < 0) {
            if (errno == ENOENT || errno == ENOTDIR) return false;
            throw std::runtime_error(errno_msg("stat(identity)", *entry.first));
        }
    }
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

// --- LoopbackServer / launch_browser / config_dir (OAuth login) ---

static int lbs_fd(const void *impl) {
    return int(reinterpret_cast<intptr_t>(impl)) - 1;  // 0 means unset
}
static void *lbs_box(int fd) {
    return reinterpret_cast<void *>(intptr_t(fd + 1));
}

LoopbackServer::LoopbackServer()
    : impl_(nullptr), port_(0), client_impl_(nullptr)
{
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  // OS assigns
    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        int e = errno; ::close(fd); errno = e;
        throw std::runtime_error(std::string("bind loopback: ") +
                                 std::strerror(errno));
    }
    sockaddr_in bound{};
    socklen_t blen = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &blen) < 0) {
        int e = errno; ::close(fd); errno = e;
        throw std::runtime_error(std::string("getsockname: ") +
                                 std::strerror(errno));
    }
    port_ = ntohs(bound.sin_port);

    if (::listen(fd, 5) < 0) {
        int e = errno; ::close(fd); errno = e;
        throw std::runtime_error(std::string("listen: ") +
                                 std::strerror(errno));
    }
    impl_ = lbs_box(fd);
}

LoopbackServer::~LoopbackServer()
{
    int cfd = lbs_fd(client_impl_);
    if (cfd >= 0) ::close(cfd);
    int fd = lbs_fd(impl_);
    if (fd >= 0) ::close(fd);
}

int LoopbackServer::port() const { return port_; }

std::string LoopbackServer::accept_request()
{
    int lfd = lbs_fd(impl_);
    int cfd = ::accept(lfd, nullptr, nullptr);
    if (cfd < 0)
        throw std::runtime_error(std::string("accept: ") +
                                 std::strerror(errno));
    client_impl_ = lbs_box(cfd);

    // Read until end-of-headers; we only need the first line in
    // practice.  Cap at 16 KB to bound memory for pathological
    // clients.
    std::string buf;
    char tmp[4096];
    while (buf.find("\r\n\r\n") == std::string::npos && buf.size() < 16384) {
        ssize_t n = ::read(cfd, tmp, sizeof(tmp));
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("read: ") +
                                     std::strerror(errno));
        }
        if (n == 0) break;
        buf.append(tmp, size_t(n));
    }

    // Extract "METHOD target HTTP/..." from the first line.
    auto line_end = buf.find("\r\n");
    std::string line = buf.substr(0, line_end);
    auto sp1 = line.find(' ');
    auto sp2 = (sp1 == std::string::npos) ? std::string::npos
                                          : line.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos)
        throw std::runtime_error("malformed HTTP request line");
    return line.substr(sp1 + 1, sp2 - sp1 - 1);
}

void LoopbackServer::respond(const std::string &html)
{
    int cfd = lbs_fd(client_impl_);
    if (cfd < 0)
        throw std::runtime_error("respond() before accept_request()");
    std::ostringstream resp;
    resp << "HTTP/1.1 200 OK\r\n"
         << "Content-Type: text/html; charset=utf-8\r\n"
         << "Content-Length: " << html.size() << "\r\n"
         << "Connection: close\r\n\r\n"
         << html;
    std::string s = resp.str();
    const char *p = s.data();
    size_t remaining = s.size();
    while (remaining > 0) {
        ssize_t n = ::write(cfd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("write: ") +
                                     std::strerror(errno));
        }
        p += n;
        remaining -= size_t(n);
    }
    ::close(cfd);
    client_impl_ = nullptr;
}

void launch_browser(const std::string &url)
{
    // Prefer xdg-open (Linux/BSD) and open (macOS).  fork + execvp so
    // the browser runs asynchronously and we don't block on it.
    pid_t pid = ::fork();
    if (pid < 0)
        throw std::runtime_error(std::string("fork: ") +
                                 std::strerror(errno));
    if (pid == 0) {
        // Child.  Try xdg-open then open.  exec* returns only on error.
        const char *openers[] = { "xdg-open", "open", nullptr };
        for (int i = 0; openers[i]; i++) {
            char *argv[] = {
                const_cast<char *>(openers[i]),
                const_cast<char *>(url.c_str()),
                nullptr
            };
            ::execvp(argv[0], argv);
        }
        _exit(127);
    }
    // Parent: reap on next waitpid non-blocking attempt later;
    // SIGCHLD default is fine.  Don't block.
    (void)pid;
}

std::string config_dir()
{
    std::string base;
    if (const char *xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg) {
        base = xdg;
    } else if (const char *home = std::getenv("HOME"); home && *home) {
        base = std::string(home) + "/.config";
    } else {
        throw std::runtime_error(
            "cannot determine config dir: neither XDG_CONFIG_HOME nor HOME set");
    }
    // Ensure base exists (don't clobber if it already does).
    ::mkdir(base.c_str(), 0700);
    std::string dir = base + "/aas-sign";
    if (::mkdir(dir.c_str(), 0700) < 0 && errno != EEXIST)
        throw std::runtime_error(std::string("mkdir ") + dir + ": " +
                                 std::strerror(errno));
    return dir;
}

}  // namespace platform

// --- Entry point ---

// POSIX argv is UTF-8 under any modern locale.  Forward as-is.
// libFuzzer harnesses provide their own main(), so skip this one when
// AAS_SIGN_NO_MAIN is defined (set by cmake/Fuzzing.cmake).
#ifndef AAS_SIGN_NO_MAIN
int main(int argc, char **argv)
{
    return aas_sign_main(argc, argv);
}
#endif
