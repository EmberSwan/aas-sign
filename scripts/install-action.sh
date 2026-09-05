#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${ACTION_REPOSITORY:?ACTION_REPOSITORY is required}"
: "${RUNNER_ARCH:?RUNNER_ARCH is required}"
: "${RUNNER_OS:?RUNNER_OS is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"

fail() { echo "::error::$*" >&2; exit 1; }
[[ "${ACTION_REPOSITORY}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "invalid action repository: ${ACTION_REPOSITORY}"
[[ "${VERSION}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?(\+[A-Za-z0-9.-]+)?$ ]] || fail "invalid aas-sign version: ${VERSION}"
[ "${RUNNER_ARCH}" = X64 ] || fail "unsupported RUNNER_ARCH: ${RUNNER_ARCH}"
case "${RUNNER_OS}" in
  Linux) platform=linux; suffix= ;;
  Windows) platform=windows; suffix=.exe ;;
  *) fail "unsupported RUNNER_OS: ${RUNNER_OS}" ;;
esac
asset="aas-sign-${VERSION#v}-${platform}-x86_64${suffix}"
base_url="https://github.com/${ACTION_REPOSITORY}/releases/download/${VERSION}"
checksums_url="https://artifacts.emberswan.com/aas-sign/${VERSION}/sha256sums.txt"
stage="$(mktemp -d "${RUNNER_TEMP}/aas-sign-stage.XXXXXXXX")"
trap 'rm -rf "${stage}"' EXIT

curl -fsSL --retry 3 --retry-all-errors -o "${stage}/sha256sums.txt" "${checksums_url}"
# The independently published manifest identifies the companion revision.
# Do not allow filenames from it to influence a path or arbitrary URL.
companion="$(awk -v platform="${platform}" -v suffix="${suffix}" '
  { name=$2; sub(/^\*/, "", name) }
  name ~ ("^osslsigncode-[0-9a-f]+-" platform "-x86_64") {
    split(name, parts, "-")
    if (length(parts[2]) == 8 && name == "osslsigncode-" parts[2] "-" platform "-x86_64" suffix) {
      count++; selected=name
    }
  }
  END { if (count == 1) print selected; else exit 1 }
' "${stage}/sha256sums.txt")" || fail "release ${VERSION} has no unique compatible osslsigncode asset"

verify_download() {
  local name="$1" output="$2" expected actual
  expected="$(awk -v asset="${name}" '
    { name=$2; sub(/^\*/, "", name) }
    name == asset { count++; if (NF != 2) invalid=1; hash=$1 }
    END { if (count == 1 && !invalid) print hash; else exit 1 }
  ' "${stage}/sha256sums.txt")" || fail "sha256sums.txt has no unique checksum for ${name}; release ${VERSION} may be incompatible"
  [[ "${expected}" =~ ^[0-9A-Fa-f]{64}$ ]] || fail "sha256sums.txt has an invalid checksum for ${name}"
  curl -fsSL --retry 3 --retry-all-errors -o "${output}" "${base_url}/${name}"
  actual="$(sha256sum "${output}")"; actual="${actual%% *}"
  [ "${actual}" = "${expected,,}" ] || fail "SHA-256 mismatch for ${name}: expected ${expected,,}, got ${actual}"
}
verify_download "${asset}" "${stage}/aas-sign${suffix}"
verify_download "${companion}" "${stage}/osslsigncode${suffix}"
# Neither program is installed or run until both independent checks pass.
chmod +x "${stage}/aas-sign${suffix}" "${stage}/osslsigncode${suffix}"
rm "${stage}/sha256sums.txt"
dest="$(mktemp -d "${RUNNER_TEMP}/aas-sign-${VERSION#v}.XXXXXXXX")"
mv "${stage}/aas-sign${suffix}" "${stage}/osslsigncode${suffix}" "${dest}/"
echo "${dest}" >> "${GITHUB_PATH}"
companion_path="${dest}/osslsigncode${suffix}"
# Git Bash paths are not native absolute Windows paths for CreateProcessW.
if [ "${RUNNER_OS}" = Windows ] && command -v cygpath >/dev/null 2>&1; then
  companion_path="$(cygpath -am "${companion_path}")"
fi
printf 'AAS_SIGN_OSSLSIGNCODE=%s\n' "${companion_path}" >> "${GITHUB_ENV}"
echo "Installed aas-sign ${VERSION} and ${companion}"
