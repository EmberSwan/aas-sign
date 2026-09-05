# aas-sign: Azure Artifact Signing utility

C++20 utility to code-sign PE images (EXE, DLL), MSI installers, MSIX
packages, and MSIX bundles via [Azure Artifact Signing][aas], with no local
private keys. aas-sign handles authentication, Azure requests, and CMS
assembly. An unmodified [osslsigncode](https://github.com/mtrojnar/osslsigncode)
companion handles file formats, signature attachment, and RFC 3161 timestamps.

## GitHub Actions

The composite action supports Linux and Windows x86_64 runners. It installs
both executables, exchanges a GitHub OIDC token for an Azure token, and signs
the files you list. A pre-minted Azure token can also be supplied.
Before installation, it verifies both binaries against the independently
published manifest at
`https://artifacts.emberswan.com/aas-sign/VERSION/sha256sums.txt`.
Neither `azure/login` nor the Azure CLI is required:

```yaml
permissions:
  id-token: write      # required for GitHub OIDC federation
  contents: read

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      # Add your build steps here before signing.
      - uses: EmberSwan/aas-sign@v2.0.0
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

For bundles, sign each inner package before your build creates the bundle.
`recursive: true` applies only to MSI files; it does not sign packages inside
an MSIX bundle. File paths are literal, one per line; globs are not expanded.

The Azure app registration for `client-id` must have a
federated-credential configured to trust the caller repo/environment.
See Microsoft's [workload identity federation docs][wif].

Inputs:

| Input           | Required | Default                                      | Notes                                   |
| --------------- | -------- | -------------------------------------------- | --------------------------------------- |
| `endpoint`      | yes      | —                                            | Artifact Signing endpoint host          |
| `account`       | yes      | —                                            | Artifact Signing account                |
| `profile`       | yes      | —                                            | Certificate profile                     |
| `files`         | yes      | —                                            | One path per line; blanks ignored       |
| `client-id`     | see note | —                                            | Azure app ID for OIDC                   |
| `tenant-id`     | see note | —                                            | Azure tenant for OIDC                   |
| `token`         | see note | —                                            | Pre-minted bearer (alternative to OIDC) |
| `version`       | no       | `v2.0.0`                                     | aas-sign release to install             |
| `timestamp-url` | no       | Microsoft ACS                                | Override RFC 3161 TSA                   |
| `no-timestamp`  | no       | `false`                                      | Set `"true"` to skip timestamping       |
| `msi-dse`       | no       | `false`                                      | Add enhanced MSI metadata signature     |
| `recursive`     | no       | `false`                                      | Sign unsigned embedded MSI PE payloads  |
| `max-parallel`  | no       | 8                                            | Concurrent sign operations              |

Provide either `client-id` and `tenant-id` for OIDC, or a pre-minted `token`.
OIDC requires `id-token: write`, an Azure federated credential matching the
caller, and permission to sign with the selected certificate profile. Client
and tenant IDs are identifiers, not credentials; they can also be stored as
GitHub configuration variables. A supplied bearer token is masked in the log.

The `version` input selects the binary release independently of the action
reference. The v2 action requires the v2 asset layout and cannot install v1
release assets.

## Installation and building

Download **both executables for your platform** from the same
[release](https://github.com/EmberSwan/aas-sign/releases) and
verify them against the independently published
`https://artifacts.emberswan.com/aas-sign/<release-tag>/sha256sums.txt`.
Download names include the aas-sign version or osslsigncode short revision.
Rename them to `aas-sign[.exe]` and `osslsigncode[.exe]` and place them together.
aas-sign looks beside its own executable first, then on `PATH`. Use
`--osslsigncode PATH` to select the companion explicitly.

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
`${XDG_CONFIG_HOME:-~/.config}/aas-sign/token-cache.json` (POSIX) or
`%APPDATA%\aas-sign\token-cache.json` (Windows), and saves the three
signing defaults to `config.json` in the same directory.  Subsequent
`aas-sign sign` invocations silently mint fresh access tokens from
the cache and read the signing target from `config.json` — no
Azure CLI, no retyping.

If Microsoft rejects the refresh token because it expired or was revoked,
run `aas-sign login` again. `aas-sign logout` deletes only the local token
cache; it does not revoke the token in Microsoft Entra or remove the saved
signing configuration.

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
rather than as one string.

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
GitHub OIDC, then the cached login from `aas-sign login`. OIDC uses
`--oidc-client-id` and `--oidc-tenant-id`, falling back to `AZURE_CLIENT_ID`
and `AZURE_TENANT_ID`, and requires the GitHub runner's OIDC environment.

Global options include `--cacert PATH` for a custom PEM trust bundle and
`--insecure` to disable HTTPS certificate verification for diagnostics.
On Windows, Azure HTTPS uses the system certificate store; the companion
also receives the custom CA option for its HTTPS requests.

By default, the signature is timestamped against Microsoft's free TSA at
`http://timestamp.acs.microsoft.com/timestamping/RFC3161`.  This is
**strongly recommended** because Azure Artifact Signing issues short-lived
certificates. A trusted timestamp allows verification after the signing
certificate expires, subject to certificate trust, revocation, and the
verifier's policy. See Microsoft's
[certificate management documentation][certificates].

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
identities. **Sign each package before creating a bundle, then sign the bundle.**
Contained packages remain byte-for-byte unchanged: aas-sign does not sign them
automatically. A bundle containing unsigned packages can pass outer signature
verification but fail Windows deployment. The `recursive` option applies only
to MSI files. Signature replacement uses the companion's format support.

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
File sizes and applicable existing installer hash rows are updated. An MSI
with changed payload bytes gets a new PackageCode; ProductCode and UpgradeCode
remain unchanged.
Run recursive signing before generating patches/transforms tied to the final MSI.

If there are no unsigned PEs, the tool skips reconstruction and signs just the
outer installer. Errors during extraction, signing, rebuilding, or timestamping
leave the original MSI unchanged. Payload signing is sequential within each
parent worker, so `--max-parallel` remains the total signing-concurrency bound.

### Concurrency

When multiple files are given, they are signed in parallel with up to 8
in flight by default.  Use `--max-parallel N` to change the cap, or
`--max-parallel 1` for sequential signing. Reduce the limit if needed
for service throttling or local resource constraints.

In batch mode each file's progress output is prefixed with `[path]` and
buffered, then flushed as a single block when that file finishes, so
concurrent narratives don't interleave.  On completion the tool prints
a summary and exits non-zero if any file failed.

## Release assets

Each release includes both tools, a source archive, dependency provenance,
third-party notices, and checksums. Both Windows executables are signed and
timestamped; checksums cover the final distributed files.

Linux releases use static third-party libraries on top of dynamic glibc
(Ubuntu 24.04 baseline). aas-sign's Windows executable is cross-compiled with
MinGW; osslsigncode is built with MSVC and static dependencies on Windows.
There is no macOS release asset.

For a release tagged `v2.0.0`, the assets include:

- `aas-sign-2.0.0-linux-x86_64`
- `aas-sign-2.0.0-windows-x86_64.exe`
- `osslsigncode-<short-sha>-linux-x86_64`
- `osslsigncode-<short-sha>-windows-x86_64.exe`
- `aas-sign-2.0.0.tar.gz`, provenance/third-party notices, and `sha256sums.txt`

The submodule gitlink alone pins osslsigncode. Updating it changes the derived
asset names; the action discovers the companion name from the independent
manifest, without a duplicated revision constant. osslsigncode's own version
output is unmodified. The action deliberately rejects releases missing the
expected versioned assets.

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

## Verifying signatures

With osslsigncode:

    $ osslsigncode verify -in myapp.exe
    $ osslsigncode verify -in installer.msi
    $ osslsigncode verify -in application.msix

If your system trust store lacks the required code-signing or timestamp roots,
provide trusted PEM bundles with `-CAfile` and `-TSA-CAfile`. Check both the code
signature and timestamp verification results; a successful process exit alone
does not guarantee that timestamp trust verification succeeded.

On Windows: right-click the file → Properties → Digital Signatures, or
run `signtool verify /pa myapp.exe` (or pass the MSI path).

[aas]: https://learn.microsoft.com/en-us/azure/artifact-signing/overview
[certificates]: https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management
[wif]: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust?pivots=identity-wif-apps-methods-azp
