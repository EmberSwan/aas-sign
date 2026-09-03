# Agents

## Overview

aas-sign is a C++ command-line tool that signs PE images (EXE, DLL) and
Windows Installer packages (MSI) using Azure Artifact Signing (formerly
Trusted Signing). It does no local cryptographic signing -- it computes the
format-specific Authenticode hash, sends it to Azure's REST API, assembles
the returned signature into a CMS structure, optionally attaches an RFC
3161 timestamp, and injects the result into the PE certificate table or MSI
signature stream.

## Build

    cmake -B build
    cmake --build build

C++20 (needed for `std::jthread`). Dependencies fetched via CMake
FetchContent (nlohmann/json, mbedTLS on POSIX). Windows uses only system
APIs (BCrypt, WinHTTP). pthreads on POSIX, winpthreads on MinGW.

### Dependency resolution (`-DDEPS=`)

- **`FETCH`** (default): nlohmann/json (+ mbedTLS on POSIX) come
  in via CMake FetchContent.  If `deps/<name>/` exists in the
  source tree it's used directly (offline); otherwise the pinned
  upstream archive is downloaded.  Source-release tarballs ship
  with `deps/` already populated, so `cmake -B build` works with
  no network access.
- **`LOCAL`**: use system-installed packages via `find_package`.
  Skips any download and ignores `deps/`.  Useful on distros that
  package these libs and for system-integrator builds.

### Source releases

`cmake -P cmake/SourceRelease.cmake` produces
`aas-sign-VERSION.tar.gz` by `git archive`-ing HEAD and bundling
the dependency trees into `deps/`.  The version string comes from
`git describe --tags`.  The sibling `cmake/BundleDeps.cmake` can
be invoked directly (`cmake -P cmake/BundleDeps.cmake`) to just
materialise `deps/` in the current tree -- useful for working
offline without generating a full tarball.

Both URL/hash pairs in `BundleDeps.cmake` must stay in lock-step
with the `FetchContent_Declare` entries in the top-level
`CMakeLists.txt`.

## Fuzzing

Hand-rolled byte parsers (`pe.cpp`, `msi.cpp`, `x509.cpp`, `tsa.cpp`) have
libFuzzer harnesses under `fuzz/`.  Not built by default.  Clang
only (libFuzzer ships with it), POSIX (Linux + macOS).  Applies
ASan + UBSan and the matching stdlib debug mode
(`_GLIBCXX_DEBUG` on libstdc++, `_LIBCPP_HARDENING_MODE_DEBUG` on
libc++):

    cmake -B build-fuzz -DAAS_SIGN_FUZZ=ON \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
    cmake --build build-fuzz
    ./build-fuzz/fuzz_pe -dict=fuzz/pe.dict -max_total_time=60 fuzz/corpus/pe/
    ./build-fuzz/fuzz_msi -dict=fuzz/msi.dict -max_len=16777216 \
        -max_total_time=60 fuzz/corpus/msi/

Targets: `fuzz_pe`, `fuzz_msi`, `fuzz_x509_cert_id`, `fuzz_x509_split_certs`,
`fuzz_der_tlv`, `fuzz_tsa_parse`.  Each harness catches
`std::exception` so the rejection path is not a finding; libFuzzer
only flags sanitizer fires and real crashes.  We assume mbedTLS and
nlohmann/json are fuzzed upstream.

Seed corpora and dictionaries live next to the harnesses:

| harness | seeds | dict |
|---|---|---|
| `fuzz_pe` | `fuzz/corpus/pe/` (minimal PE32 + PE32+ stubs) | `fuzz/pe.dict` |
| `fuzz_msi` | `fuzz/corpus/msi/` (minimal unsigned MSI/CFB) | `fuzz/msi.dict` |
| `fuzz_x509_cert_id` | `fuzz/corpus/x509_cert_id/` (self-signed DER cert) | `fuzz/der.dict` |
| `fuzz_x509_split_certs` | `fuzz/corpus/x509_split_certs/` | `fuzz/der.dict` |
| `fuzz_der_tlv` | — | `fuzz/der.dict` |
| `fuzz_tsa_parse` | — | `fuzz/der.dict` |

Without their seed corpora, `fuzz_pe` and `fuzz_msi` burn most of their
budgets failing the MZ/PE and CFB signature/header checks.  The provided
seeds pass each constructor and land the fuzzer inside
`authenticode_hash()`.  Pass the matching dictionary and corpus every run
so mutations preserve the magic bytes and structural values our parsers
check.

## Distribution

`action.yml` at the repo root is a composite GitHub Action published
from this same repo.  Consumers reference it as
`EmberSwan/aas-sign@<tag>`.  It downloads the pinned
release binary for the runner OS, verifies it against the independently
published `https://artifacts.emberswan.com/aas-sign/<tag>/sha256sums.txt`,
accepts a caller-supplied Azure token or uses aas-sign's built-in GitHub OIDC
exchange, and invokes `aas-sign` with a multi-line `files:` input.  Release
checksums are uploaded to that immutable R2 path manually after publishing
the GitHub release.  Asset naming convention:
`aas-sign-{linux,windows}-x86_64[.exe]`.

`.github/workflows/release.yml` builds the assets on a `v*` tag push,
self-signs the Windows binary with the freshly-built Linux binary, and
publishes the release with checksums.  No dependency on a previous
release; bootstraps cleanly from the first tag.  No macOS build.

## Architecture

```
main.cpp         CLI + subcommand and PE/MSI dispatch + worker pool
pe.cpp           PE parsing, Authenticode hash, checksum, signature injection
msi.cpp          MSI/CFB parsing, SIP hash, signature-stream injection
der.cpp          DER/ASN.1 encoding primitives (build-and-wrap, no parsing)
cms.cpp          PE/MSI CMS/Authenticode structure assembly (SignedData v1)
x509.cpp         Minimal X.509 parser (issuer DN + serial, CMS cert splitting)
azure.cpp        Azure Trusted Signing REST client (POST + poll loop)
tsa.cpp          RFC 3161 TimeStampReq builder and TimeStampResp parser
oidc.cpp         CI-path OIDC exchange (GitHub Actions runner → Azure token)
auth_laptop.cpp  Laptop-path OAuth login (browser + PKCE) + refresh cache;
                 also hosts `logout` (delete cache) and `config`
                 (write signing defaults to config.json without auth)
base64.cpp       Base64 / base64url encode/decode
urlenc.cpp       RFC 3986 percent-encoder
signer.cpp       Parse the `region:account:profile` signer tuple
platform.hpp     Platform abstraction interface (everything below)
posix.cpp        POSIX impl: mbedTLS SHA-256, raw TLS HTTPS, TCP sockets,
                 open/pread/pwrite, /dev/urandom, xdg-open
win32.cpp        Windows impl: BCrypt, WinHTTP, WinSock, CreateFileW,
                 ShellExecuteW, SHGetFolderPathW
```

Platform-specific sources are selected by CMake generator expressions.

### Platform-layer paradigm (no #ifdef in feature code)

All OS-specific code — file I/O, sockets, crypto, HTTPS, browser
launch, per-user config directory lookup, atomic file replace, etc. —
lives behind `namespace platform` in `platform.hpp` and is implemented
independently in `posix.cpp` and `win32.cpp`.  Feature modules
(`auth_laptop.cpp`, `pe.cpp`, `cms.cpp`, …) are pure C++17/20 with no
`#ifdef _WIN32` blocks, no `<windows.h>` includes, no POSIX-specific
syscalls.

When adding a new feature that needs OS-specific behaviour, don't
reach for `#ifdef _WIN32` in the feature file.  Extend `platform.hpp`
with a new function or class (follow the `File`, `LoopbackServer`,
`atomic_write_private_file` shape), implement it twice (posix.cpp
and win32.cpp), and call the abstraction from the feature code.
Each implementation handles errors via `throw std::runtime_error`
with a message that includes the path/URL/operation and the
underlying errno / GetLastError in human-readable form.

The payoff: feature modules read cleanly on both platforms, and the
two platform files carry all the "this is how Windows does things"
knowledge in one place where it can be reviewed as a unit.

Console output follows the same rule: feature code never touches
`std::cout` / `std::cerr` / `printf` directly.  Everything bound for
stdout or stderr goes through `platform::write_stdout` /
`platform::write_stderr`, which on Windows detect a console handle and
use `WriteConsoleW` (UTF-8 → UTF-16 transcode) so non-ASCII paths and
identifiers render correctly regardless of the active code page.
Redirected streams get raw UTF-8 bytes — the right thing for
`2> log.txt` and `| tee`.  Feature code composes lines in memory with
`std::ostringstream` or `std::string`, then hands the finished bytes
to the platform API.

## Signing flow

1. Detect and parse the PE or MSI; compute the format-specific Authenticode
   SHA-256 (`pe.cpp` or `msi.cpp`).  Enhanced MSI signing also computes the
   `MsiDigitalSignatureEx` metadata digest.
2. Build SpcIndirectDataContent with `SpcPeImageData` or MSI `SpcSipInfo`,
   plus authenticated attributes (cms.cpp)
3. SHA-256 hash the authenticated attrs SET
4. POST hash to Azure, poll for signature + cert chain (azure.cpp)
5. Request RFC 3161 timestamp of the Azure signature (tsa.cpp, optional)
6. Build CMS ContentInfo with SignedData v1, timestamp embedded as
   unsigned attr in SignerInfo (cms.cpp)
7. For PE, wrap in WIN_CERTIFICATE, inject, and recompute the checksum.  For
   MSI, write the CMS to `DigitalSignature` and optionally write the metadata
   digest to `MsiDigitalSignatureEx`.

## Key details and gotchas

- **Signer tuple syntax** (`signer.cpp`): three non-empty fields
  separated by `:`, in outer-to-inner order — `REGION:ACCOUNT:PROFILE`.
  Azure resource names never contain `:`, so the split is unambiguous.
  The region field auto-expands: if it contains no `.` we append
  `.codesigning.azure.net`; otherwise it's taken verbatim as a full
  hostname (escape hatch for non-standard endpoints).  Accepted as a
  positional arg by `login` and `config`, and via `--as` on `sign`.
  The three individual flags (`--endpoint`/`--account`/`--profile`)
  are the equivalent long form and are what the GitHub Action emits;
  mixing the tuple and the individual flags on the same invocation
  is a hard error.
- **Authenticode PE hash** excludes three regions: PE checksum (4B at
  peHeaderOffset+88), certificate table data directory entry (8B), and
  existing cert table data.  Unsigned PEs are also padded to an 8-byte
  boundary in the digest.
- **Authenticode MSI hash** traverses each compound-file storage in MSI SIP
  name order, hashes stream contents recursively, appends storage CLSIDs,
  and excludes the root `DigitalSignature` and `MsiDigitalSignatureEx`
  streams.  Enhanced mode first hashes directory metadata, stores that
  32-byte digest in `MsiDigitalSignatureEx`, and prepends it to the ordinary
  MSI content digest.
- **MSI CMS content** uses `SpcSipInfo` OID `1.3.6.1.4.1.311.2.1.30` and
  MSI SIP UUID `{000c10f1-0000-0000-c000-000000000046}`.  Re-signing replaces
  the root signature streams; basic mode removes an existing enhanced stream.
- **messageDigest attribute** is SHA-256 of the *content* of the
  SpcIndirectDataContent SEQUENCE, not of the SEQUENCE itself (skip the
  tag + length header).  Getting this wrong produces a
  cryptographically-valid-looking signature that Windows silently rejects
  with TRUST_E_NOSIGNATURE.
- **SignedData version** MUST be 1 (not 3) for Authenticode.
- **signatureAlgorithm** in SignerInfo MUST be `rsaEncryption`, not
  `sha256WithRSAEncryption`.
- **SET OF elements** must be sorted lexicographically by encoded bytes
  per DER canonical form.  OpenSSL's PKCS7_verify re-encodes auth attrs
  before hashing, so unsorted order produces a signature mismatch.  See
  `der_set()` in der.cpp.
- **SpcPeImageData** is a fixed constant: flags=empty BIT STRING,
  file=[0] EXPLICIT { [2] EXPLICIT { [0] IMPLICIT BMPString("") } }.
  The [0] EXPLICIT wrapper on `file` is contrary to the ASN.1 spec but
  matches what real-world signed executables use.
- **Azure `signingCertificate`** is double-base64 encoded: the JSON
  string value is base64 text that decodes to MIME base64 text, which in
  turn decodes to a PKCS#7 SignedData wrapper holding the cert chain.
  See azure.cpp and x509.cpp `try_extract_cms_certs()`.
- **RFC 3161 timestamp** attribute OID is `1.3.6.1.4.1.311.3.3.1`
  (szOID_RFC3161_counterSign) -- the Authenticode-specific form, not the
  generic CMS id-aa-signatureTimeStampToken.  The attribute value is the
  full TimeStampToken ContentInfo as returned by the TSA.  It goes in
  unsignedAttrs `[1] IMPLICIT` after the signature OCTET STRING.
- **TSP messageImprint** hashes the contents of the signature OCTET
  STRING, not the OCTET STRING itself.
- **Azure API**: `api-version=2022-06-15-preview`, poll with backoff,
  60s timeout.
- **Default TSA**: `http://timestamp.acs.microsoft.com/timestamping/RFC3161`
  (Microsoft's free service, colocated with Azure Trusted Signing).
  Plain HTTP -- integrity is guaranteed by the TSA's own signature.
- **Transient network retry**: every public HTTPS/HTTP entry point
  in the platform layer is wrapped in `platform::retry_transient`
  (declared in `platform.hpp`).  Failures classed as transient
  (DNS, TCP connect, TLS handshake, mid-request socket I/O) throw
  `platform::TransientNetworkError`, which the retry helper catches
  and re-runs up to 3 attempts with linear backoff (2 s, 4 s).
  Permanent failures (config errors, missing CA bundle, malformed
  responses, HTTP non-2xx, etc.) keep throwing plain
  `std::runtime_error` so the retry loop doesn't mask them.  Safe
  because every operation we retry is idempotent at the caller
  level: Azure signing produces a fresh signature for the same
  hash, the TSA produces a fresh timestamp, the OAuth token
  endpoint returns a (server-cached) token.
- **Concurrency**: `sign_one_file()` is called from worker threads
  (default 8, tunable via `--max-parallel`).  All signing primitives
  (`PeFile`, `MsiFile`, `azure_sign`, `tsa_timestamp`, `cms_*`) are
  per-instance or create fresh TLS/TCP connections per call, with no shared
  mutable state.  Per-file stderr output is buffered via `FileLogger` and
  flushed as one block under a single mutex so concurrent file
  narratives don't interleave.  Single-file invocations bypass the
  worker pool entirely and write to `std::cerr` directly for identical
  behavior to the pre-concurrency version.
