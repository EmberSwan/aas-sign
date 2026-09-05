# aas-sign: Azure Artifact Signing utility

C++20 utility to code-sign PE images (EXE, DLL), MSI installers, MSIX
packages, and MSIX bundles via [Azure Artifact Signing][aas], with no local
private keys. aas-sign handles authentication, Azure requests, and CMS
assembly. An unmodified [osslsigncode](https://github.com/mtrojnar/osslsigncode)
companion handles file formats, signature attachment, and RFC 3161 timestamps.

## Installation and building

Download **both executables for your platform** from the same release and
verify them against the independently published
`https://artifacts.emberswan.com/aas-sign/<release-tag>/sha256sums.txt`.
Download names include the aas-sign version or osslsigncode short revision.
Rename them to `aas-sign[.exe]` and `osslsigncode[.exe]` and place them together.
The action installs and verifies both automatically.

To build from Git, initialize the recorded upstream submodule:

    $ git submodule update --init modules/osslsigncode
    $ python3 scripts/build-osslsigncode.py
    $ cmake -B build
    $ cmake --build build
    $ build/aas-sign sign --osslsigncode build-companion/osslsigncode myapp.exe

CMake 3.20+, C++20, and Python 3.12+ are required for fetched builds. The
companion builder also needs Ninja, Perl, and a C toolchain (MSVC on Windows).
POSIX recursive MSI dependencies additionally require Meson 1.4+, pkg-config,
Bison, Vala, and gettext. CI uses Meson 1.9.1. Release builds statically link
third-party runtime libraries; normal operating-system libraries remain dynamic.

`-DDEPS=FETCH` downloads pinned source dependencies, or uses `deps/` from an
offline source release. `-DDEPS=LOCAL` instead uses installed nlohmann/json,
mbedTLS, libmsi and libgcab packages on POSIX. Windows uses system APIs for
Azure access and MSI reconstruction. The source-release tarball builds aas-sign
offline; building the separate companion requires the Git submodule checkout.

To run the real companion integration tests without Azure credentials:

    $ cmake -B build -DAAS_SIGN_OSSLSIGNCODE="$PWD/build-companion/osslsigncode"
    $ cmake --build build
    $ ctest --test-dir build --output-on-failure

## Usage

### Quick start

    $ aas-sign login <region>:<account>:<profile>
    $ aas-sign sign myapp.exe installer.msi

The signer tuple has three fields separated by colons, in
less-to-more-specific order.  `<region>` is the short region slug
(e.g. `eus`, `neu`, `wus3`); it auto-expands to
`<region>.codesigning.azure.net`.  If you need a non-standard
endpoint, pass the full hostname instead of the slug.  For example:

    $ aas-sign login eus:mycompany:me

The login command opens your browser (Microsoft Entra Authorization
Code + PKCE), caches a refresh token at
`~/.config/aas-sign/token-cache.json` (POSIX) or
`%APPDATA%\aas-sign\token-cache.json` (Windows), and saves the three
signing defaults to `config.json` in the same directory.  Subsequent
`aas-sign sign` invocations silently mint fresh access tokens from
the cache and read the signing target from `config.json` — no
Azure CLI, no retyping.

The cache is revoked if you log out in Entra, the refresh token
expires (~90 days of inactivity), or you delete the file (or run
`aas-sign logout`).  Rerun `aas-sign login` to refresh.

To update the saved defaults later without re-authenticating, use
`aas-sign config`:

    $ aas-sign config eus:othercompany:me

For one-off signing against a different target, pass `--as` to
`sign`, which overrides `config.json` for that invocation:

    $ aas-sign sign --as eus:othercompany:me myapp.exe

The three long flags `--endpoint`, `--account`, `--profile` are
accepted everywhere the tuple is (mutually exclusive with it).
They're what the GitHub Action emits under the hood and are the
path to take when the three values come from separate variables
(CI secrets, etc.) rather than as one string.

### Full synopsis

    $ aas-sign sign [--as <region>:<account>:<profile>] \
                    [--endpoint <H> --account <N> --profile <P>] \
                    [--token <bearer-token>] \
                    [--oidc-client-id <ID> --oidc-tenant-id <ID>] \
                    [--timestamp-url <url> | --no-timestamp] \
                    [--msi-dse] [--recursive] \
                    [--osslsigncode <path>] \
                    [--max-parallel <N>] \
                    [--dump-cms <path>] \
                    <file.exe|file.dll|file.msi|file.msix|file.msixbundle> [FILE ...]

    $ aas-sign login [<region>:<account>:<profile>] \
                     [--tenant <tenant>] [--client-id <id>]
    $ aas-sign logout
    $ aas-sign config <region>:<account>:<profile>
    $ aas-sign config [--endpoint <H>] [--account <N>] [--profile <P>]
    $ aas-sign --version | --help

Authentication (first match wins): `--token`, `$AZURE_ACCESS_TOKEN`,
`--oidc-*` flags (GitHub Actions runner only), cached login from
`aas-sign login`.

By default, the signature is timestamped against Microsoft's free TSA at
`http://timestamp.acs.microsoft.com/timestamping/RFC3161`.  This is
**strongly recommended** because Azure Trusted Signing issues
short-lived certificates (on the order of days); without a timestamp, the
signature becomes invalid as soon as the signing cert expires.  A
timestamped signature remains verifiable indefinitely.

Use `--timestamp-url` to point at a different RFC 3161 TSA, or
`--no-timestamp` to skip timestamping entirely (not recommended for
production artifacts).

MSI files receive the standard `DigitalSignature` stream by default.
Pass `--msi-dse` to also add `MsiDigitalSignatureEx`, which covers MSI
compound-file metadata. The option is ignored for other formats. Mixed-format
invocations are supported, including the `.appx`/`.appxbundle` aliases.

`--dump-cms PATH` writes the raw DER-encoded CMS blob to a file for
inspection (`openssl asn1parse -inform DER -in PATH`).  Only supported
when signing a single file.

### MSIX and bundles

Only SHA-256 signing content is supported. Package publishers must match the
subject of the Azure signing certificate; aas-sign does not rewrite publisher
identities. Sign the bundle itself; contained packages remain byte-for-byte
unchanged. Signature replacement uses the companion's format support.

All operations use staged copies. A final digest check runs after attachment
and timestamping, and failures leave the original untouched. The selected
upstream revision mishandles packages with an **uncompressed
`[Content_Types].xml`**; these fail the final validation rather than replacing
the original. Standard MakeAppx packages use compressed content types.

### Recursive MSI signing

    $ aas-sign sign --recursive --msi-dse installer.msi

`--recursive` signs unsigned PE files in embedded CABs and Binary-table streams,
rebuilds changed cabinets, and signs the outer MSI last. Existing signed payload
PEs are preserved byte-for-byte. This is structural signature detection, not a
certificate-trust or revocation check. Malformed signatures cause an error.
Non-PE files and nested MSI/MSIX installers remain unchanged. The flag is ignored
for non-MSI inputs and defaults to off.

Recursive mode supports self-contained, non-spanning cabinets using uncompressed,
MSZIP, or LZX input; rebuilt cabinets use MSZIP. External cabinets, loose source
files, embedded database storages/transforms, and other compression types are
rejected. Extraction is limited to 65,535 payload members and 1 GiB total.
File sizes and applicable existing installer hash rows are updated. A changed
payload gets a new PackageCode; ProductCode and UpgradeCode remain unchanged.
Run recursive signing before generating patches/transforms tied to the final MSI.

If there are no unsigned PEs, the tool skips reconstruction and signs just the
outer installer. Errors during extraction, signing, rebuilding, or timestamping
leave the original MSI unchanged. Payload signing is sequential within each
parent worker, so `--max-parallel` remains the total signing-concurrency bound.

### Concurrency

When multiple files are given, they are signed in parallel with up to 8
in flight by default.  Use `--max-parallel N` to change the cap, or
`--max-parallel 1` for fully sequential signing.  The Azure signing API
is async and handles concurrent requests from the same token without
trouble.

In batch mode each file's progress output is prefixed with `[path]` and
buffered, then flushed as a single block when that file finishes, so
concurrent narratives don't interleave.  On completion the tool prints
a summary and exits non-zero if any file failed.

### GitHub Actions

A composite action is published alongside the tool.  It installs the
release pair for the runner OS, performs the GitHub-Actions
OIDC handshake to mint an Azure token, and signs every file you list.
Before installing it verifies both binaries against the independently
published manifest at
`https://artifacts.emberswan.com/aas-sign/VERSION/sha256sums.txt`.
No `azure/login`, no Azure CLI on the runner:

```yaml
permissions:
  id-token: write      # required for GitHub OIDC federation
  contents: read

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - ...                         # your build steps here
      - uses: EmberSwan/aas-sign@v1.3.0
        with:
          endpoint:  eus.codesigning.azure.net
          account:   myaccount
          profile:   myprofile
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          msi-dse: true
          recursive: true
          files: |
            dist/myapp.exe
            dist/mylib.dll
            dist/installer.msi
            dist/application.msixbundle
```

The Azure app registration for `client-id` must have a
federated-credential configured to trust the caller repo/environment.
See Microsoft's [workload identity federation docs][wif].

The [dcmake project uses this action][dcmake] in its build pipeline, which
can serve as a working example.

[dcmake]: https://github.com/skeeto/dcmake/blob/master/.github/workflows/release.yml
[wif]: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust?pivots=identity-wif-apps-methods-azp

Inputs:

| Input           | Required | Default                                      | Notes                                  |
| --------------- | -------- | -------------------------------------------- | -------------------------------------- |
| `endpoint`      | yes      | —                                            | Trusted Signing endpoint host          |
| `account`       | yes      | —                                            | Trusted Signing account                |
| `profile`       | yes      | —                                            | Certificate profile                    |
| `files`         | yes      | —                                            | One path per line; blanks ignored      |
| `client-id`     | see note | —                                            | Azure app ID for OIDC                  |
| `tenant-id`     | see note | —                                            | Azure tenant for OIDC                  |
| `token`         | see note | —                                            | Pre-minted bearer (alternative to OIDC)|
| `version`       | no       | `v1.3.0`                                     | aas-sign release to install            |
| `timestamp-url` | no       | Microsoft ACS                                | Override RFC 3161 TSA                  |
| `no-timestamp`  | no       | `false`                                      | Set `"true"` to skip timestamping      |
| `msi-dse`       | no       | `false`                                      | Add enhanced MSI metadata signature    |
| `recursive`     | no       | `false`                                      | Sign unsigned embedded MSI PE payloads |
| `max-parallel`  | no       | 8                                            | Concurrent sign operations             |

Either provide `client-id` + `tenant-id` (preferred — no extra setup
on the caller's side) or a pre-minted `token`.  When provided, `token`
is masked in the log.

## Releases

`.github/workflows/release.yml` builds both tools for Linux and Windows,
signs and timestamps both Windows executables with the freshly built Linux
pair, then publishes a GitHub release with checksums of the final bytes.  Triggered by pushing a
tag matching `v*`.

The sign-and-release job runs under a GitHub Actions *environment*
called `release`.  Create it at Settings → Environments → New
environment → `release`, then add the secrets there (not at the
repository level).  Using an environment lets the Azure
federated-credential binding match
`repo:<owner>/<repo>:environment:release`, which is more stable than
matching on tag refs.

Required environment configuration (Settings → Environments → `release`):

| Name                       | Purpose                                      |
| -------------------------- | -------------------------------------------- |
| `AZURE_CLIENT_ID`          | OIDC federated-identity app ID               |
| `AZURE_TENANT_ID`          | Azure tenant                                 |
| `TRUSTED_SIGNING_ENDPOINT` | e.g. `eus.codesigning.azure.net`             |
| `TRUSTED_SIGNING_ACCOUNT`  | Trusted Signing account name                 |
| `CERTIFICATE_PROFILE`      | Certificate profile name                     |

The workflow reads `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` from environment
secrets, and the three signing resource identifiers from environment variables.

`aas-sign` performs the OIDC-to-Azure-token exchange itself via its
`--oidc-client-id` / `--oidc-tenant-id` flags (which read
`AZURE_CLIENT_ID` / `AZURE_TENANT_ID` from the process environment as a
fallback).  The release workflow sets those env vars from the secrets
above and then invokes `aas-sign` directly — no `azure/login`, no
Azure CLI on the runner, no `AZURE_SUBSCRIPTION_ID` needed.

Linux releases use static third-party libraries on top of dynamic glibc
(Ubuntu 24.04 baseline). aas-sign's Windows executable is cross-compiled with
MinGW; osslsigncode is built with MSVC and static dependencies on Windows.
There is no macOS release asset.

For a release tagged `v1.3.0`, the assets include:

- `aas-sign-1.3.0-linux-x86_64`
- `aas-sign-1.3.0-windows-x86_64.exe`
- `osslsigncode-<short-sha>-linux-x86_64`
- `osslsigncode-<short-sha>-windows-x86_64.exe`
- `aas-sign-1.3.0.tar.gz`, provenance/third-party notices, and `sha256sums.txt`

The submodule gitlink alone pins osslsigncode. Updating it changes the derived
asset names; the action discovers the companion name from the independent
manifest, without a duplicated revision constant. osslsigncode's own version
output is unmodified. The action deliberately rejects releases missing the
expected versioned assets. After publishing, upload the identical checksum
manifest to the immutable R2 URL before using the new action release.

## How it works

1. Stage the input and, when requested, reconstruct its MSI payload.
2. Normalize an existing outer signature with osslsigncode, then run
   `extract-data` to obtain the exact `SpcIndirectDataContent` DER.
3. Build sorted CMS authenticated attributes and send their SHA-256 hash to
   Azure, receiving a raw RSA signature and the certificate chain.
4. Assemble Authenticode SignedData version 1, then use osslsigncode's
   `attach-signature` to embed it and check the file digest.
5. Delegate RFC 3161 timestamping to `osslsigncode add -ts`, recheck the final
   signing content, and atomically replace the original file.

The companion is invoked directly, without shell command construction. Azure
and GitHub authentication variables are removed from its environment. Tokens
are never placed in companion arguments or temporary files.

## Verifying

On Linux/macOS:

    $ osslsigncode verify myapp.exe
    $ osslsigncode verify installer.msi

On Windows: right-click the file → Properties → Digital Signatures, or
run `signtool verify /pa myapp.exe` (or pass the MSI path).


[aas]: https://learn.microsoft.com/en-us/azure/trusted-signing/
