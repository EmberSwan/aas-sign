# Agents

## Overview

aas-sign is a C++20 command-line Azure Artifact Signing adapter. It handles
OAuth/OIDC, Azure's REST API, authenticated attributes, and CMS assembly.
The unmodified `modules/osslsigncode` Git submodule supplies format hashing,
signature removal/attachment, and timestamping. Supported targets are PE,
MSI, MSIX and MSIX bundles (including APPX aliases). No local private-key
signing mode exists in the production executable.

## Build and tests

    git submodule update --init modules/osslsigncode
    python3 scripts/build-osslsigncode.py
    cmake -B build -DAAS_SIGN_OSSLSIGNCODE="$PWD/build-companion/osslsigncode"
    cmake --build build
    ctest --test-dir build --output-on-failure

CMake 3.20+, C++20. Fetched dependency builds require Python 3.12+.
The companion build uses Ninja, Perl, and a native C toolchain (MSVC on
Windows); POSIX MSI reconstruction additionally requires pkg-config,
Meson >=1.4, Bison, Vala, and gettext. CI uses Meson 1.9.1.

`DEPS=FETCH` (default) uses bundled `deps/` source trees if present and
otherwise downloads pinned archives. nlohmann/json and POSIX mbedTLS use
FetchContent. POSIX recursive MSI support links static libmsi/libgcab and
their dependencies, built by `scripts/build-dependencies.py`.
`DEPS=LOCAL` uses installed packages, including libmsi/libgcab on POSIX;
Windows uses system MSI and Cabinet APIs. Dependencies and source hashes
for the new builds live in `cmake/dependency-sources.json`.

The source-release script archives HEAD and bundles dependencies so aas-sign
can build offline. It does not include the osslsigncode checkout. Building
that companion requires an initialized submodule. Keep source URL/hash pairs
for existing json/mbedTLS declarations and BundleDeps in lock-step.

Test targets cover generic CMS, platform process/staging APIs, MSI
reconstruction, action installation/argument forwarding and release naming.
`signing_test_driver` is a test-only executable with an injected local fixture
signer. It exercises production signing/CMS code against the real companion;
never add its local-key behavior or test controls to aas-sign's CLI.
The Python integration suite uses a local TSA and no Azure credentials.
On native Windows it additionally verifies signatures with SignTool and
runs controlled MSI install/repair/uninstall and MSIX deployment tests.

## Architecture

- `main.cpp`: CLI, authentication resolution, buffered per-target logging,
  and worker pool.
- `signing.cpp`: companion resolution, target/PE-signature inspection,
  staged detached-signing orchestration and atomic commit.
- `cms.cpp`, `der.cpp`, `x509.cpp`: generic CMS/DER, authenticated attributes,
  certificate identifiers and strict extraction of indirect-data DER.
- `azure.cpp`: Azure POST and poll loop. `oidc.cpp` exchanges GitHub OIDC.
- `auth_laptop.cpp`: browser/PKCE login, refresh cache, logout and config.
- `msi_recursive.cpp`: pure C++ MSI media/CAB validation and reconstruction
  orchestration. `msi_package.hpp` declares the platform database/CAB API.
- `msi_package_posix.cpp`: libmsi/libgcab implementation.
  `msi_package_win32.cpp`: Windows Installer + Cabinet FDI/FCI implementation.
- `platform.hpp`, `posix.cpp`, `win32.cpp`: checked file I/O, HTTPS, crypto,
  process execution, private workspaces and atomic replacement.

### Platform boundaries

Feature modules contain no `_WIN32` branches, native OS headers or syscalls.
Extend a platform interface and implement it for both platforms. Use UTF-8
paths and identifiers; Windows implementations transcode at the boundary.
Exceptions must identify the operation/path and underlying OS error.

All feature console output goes through `platform::write_stdout` and
`platform::write_stderr`. Compose finished messages in memory. Windows
uses WriteConsoleW for consoles and raw UTF-8 for redirected output.

`run_process` uses argument arrays, captures bounded merged output, filters
Azure/GitHub authentication variables, and prevents inherited descriptors.
Never construct shell commands or pass authentication tokens to the companion.
New outputs use private staging; `copy_file` requires a new destination and
`atomic_replace_file` replaces an existing regular file after flushing.
`same_file` detects aliases, including hard links, when protecting inputs.

## Signing behavior and gotchas

1. Stage input; optionally rebuild MSI payloads.
2. Extract an existing signature and normalize it with `remove-signature`.
   Only explicit unsigned diagnostics permit continuing after an extraction
   failure. Windows subprocess diagnostics may contain CRLF.
3. `extract-data` produces PKCS#7 containing exact SpcIndirectDataContent DER.
4. Build attributes and POST their SHA-256 hash to Azure.
5. Assemble SignedData, attach with osslsigncode, then timestamp via `add -ts`.
6. Re-extract both final signature and indirect data, compare, and atomically
   commit. Dumped CMS is the final outer signature, including its timestamp.

- Azure returns a raw RSA signature and certificate chain, not complete CMS.
  Its `signingCertificate` is double-base64 encoded.
- The messageDigest attribute hashes the CONTENT of SpcIndirectDataContent,
  excluding the DER tag/length. Never assume a two-byte DER header: MSIX
  uses a composite digest and long-form lengths.
- Reuse identical indirect-data and canonical sorted SET attribute bytes for
  hashing and assembly. Authenticode SignedData/SignerInfo versions are 1;
  signatureAlgorithm is rsaEncryption.
- Only SHA-256 signing content is supported. The companion handles the
  MSIX composite digest and distinct package/bundle SIP encodings. It leaves
  inner bundle packages unchanged. Publishers must match the signing cert;
  no publisher rewrite or native manifest validation is implemented locally.
- The selected upstream revision mishandles stored `[Content_Types].xml`;
  the final digest validation rejects these outputs without altering inputs.
  Keep this negative regression test until an upstream upgrade resolves it.
- Default TSA is Microsoft's HTTP RFC3161 endpoint. `--timestamp-url`,
  `--no-timestamp`, `--cacert` and `--insecure` are forwarded as appropriate.
  Never silently discard timestamp failures.
- `--recursive` defaults off and is ignored for non-MSI inputs. Reconstruct
  only embedded, non-spanning CABs and Binary-table PE streams. Preserve
  already-signed PEs structurally without asserting trust; malformed
  signatures fail. Nested installers and non-PE payloads stay unchanged.
- Recursive extraction caps are 1 GiB and 65,535 members across the package.
  External media, loose files, unsupported compression and embedded database
  storages/transforms are rejected. Rebuild changed CABs with MSZIP, preserve
  identities/order/metadata, update FileSize and applicable MsiFileHash rows,
  and renew PackageCode only if payload bytes changed. ProductCode and
  UpgradeCode are preserved. Sign the outer MSI last, respecting `--msi-dse`.
- Default maximum top-level concurrency is 8. Payloads are processed serially
  inside their parent worker; never create nested pools. Each worker buffers
  its narrative for a mutex-protected flush.
- Signer tuple is REGION:ACCOUNT:PROFILE; a region without a dot expands to
  `.codesigning.azure.net`. It cannot be combined with endpoint/account/profile.
- Public network entry points retry only TransientNetworkError (3 attempts,
  2s/4s backoff). Permanent/config/HTTP errors remain runtime_error.

## Fuzzing

Clang-only POSIX harnesses use libFuzzer, ASan/UBSan and matching stdlib
hardening. Keep production inspection and CMS parsers fuzzed; format hashing
and injection are now upstream's responsibility.

    cmake -B build-fuzz -DAAS_SIGN_FUZZ=ON -DDEPS=FETCH \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
    cmake --build build-fuzz
    ./build-fuzz/fuzz_pe -dict=fuzz/pe.dict -max_total_time=60 fuzz/corpus/pe/
    ./build-fuzz/fuzz_msi -dict=fuzz/msi.dict -max_len=16777216 \
        -max_total_time=60 fuzz/corpus/msi/
    ./build-fuzz/fuzz_cms_indirect -dict=fuzz/der.dict \
        -max_total_time=60 fuzz/corpus/cms_indirect/

Other targets: fuzz_der_tlv, fuzz_x509_cert_id, fuzz_x509_split_certs.
Use matching seed corpora and dictionaries. Copy corpora into a build directory
for routine smoke tests to avoid committing fuzzer-generated mutations.
Include `tests/fixtures/recursive.msi` in the MSI corpus to exercise complete
multi-cabinet reconstruction. `DEPS=FETCH` includes the libmsi ownership fix;
an unpatched system libmsi can report dependency leaks with `DEPS=LOCAL`.
See `cmake/patches/README.md` for the direct regression and patch details.

## Distribution

The submodule gitlink alone pins osslsigncode. Do not fork it, modify its
checkout or internal version string, or duplicate its revision in CI/action.
Release metadata derives its first eight revision characters from Git.

Assets use `aas-sign-VERSION-{linux,windows}-x86_64[.exe]` and
`osslsigncode-SHORTSHA-{linux,windows}-x86_64[.exe]`. Strip a leading `v`
from aas-sign tags and preserve prerelease suffixes. The action installs
stable names in a dedicated directory and passes an absolute companion path.

The release workflow builds fresh Linux and Windows pairs, then the Linux
pair signs and timestamps both Windows executables. Compute checksums only
after final binary modifications. Include provenance and dependency notices.
No prior release is needed; no macOS binary is published.

The action obtains the exact aas-sign filename and a single platform-matching
osslsigncode filename from the independently published manifest at
`https://artifacts.emberswan.com/aas-sign/<tag>/sha256sums.txt`. Both downloads
must verify before either is installed or run. Missing/ambiguous entries fail.
The same manifest is manually uploaded to the immutable R2 path after release.
