#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${ACTION_REPOSITORY:?ACTION_REPOSITORY is required}"
: "${RUNNER_ARCH:?RUNNER_ARCH is required}"
: "${RUNNER_OS:?RUNNER_OS is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"

if [[ ! "${ACTION_REPOSITORY}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "::error::invalid action repository: ${ACTION_REPOSITORY}"
  exit 1
fi

case "${VERSION}" in
  "" | *[!A-Za-z0-9._+-]*)
    echo "::error::invalid aas-sign version: ${VERSION}"
    exit 1
    ;;
esac

if [ "${RUNNER_ARCH}" != "X64" ]; then
  echo "::error::unsupported RUNNER_ARCH: ${RUNNER_ARCH}"
  exit 1
fi

case "${RUNNER_OS}" in
  Linux)
    asset=aas-sign-linux-x86_64
    exe=aas-sign
    ;;
  Windows)
    asset=aas-sign-windows-x86_64.exe
    exe=aas-sign.exe
    ;;
  *)
    echo "::error::unsupported RUNNER_OS: ${RUNNER_OS}"
    exit 1
    ;;
esac

base_url="https://github.com/${ACTION_REPOSITORY}/releases/download/${VERSION}"
checksums="$(mktemp "${RUNNER_TEMP}/aas-sign-checksums.XXXXXX")"
download="$(mktemp "${RUNNER_TEMP}/aas-sign-download.XXXXXX")"
trap 'rm -f "${checksums}" "${download}"' EXIT

echo "Installing aas-sign ${VERSION} from ${ACTION_REPOSITORY}"
curl -fsSL --retry 3 --retry-all-errors \
  -o "${checksums}" "${base_url}/sha256sums.txt"
curl -fsSL --retry 3 --retry-all-errors \
  -o "${download}" "${base_url}/${asset}"

expected="$({
  awk -v asset="${asset}" '
    $2 == asset {
      if (found) exit 2
      print $1
      found = 1
    }
    END { if (!found) exit 1 }
  ' "${checksums}"
})" || {
  echo "::error::sha256sums.txt has no unique checksum for ${asset}"
  exit 1
}

case "${expected}" in
  "" | *[!0-9A-Fa-f]* )
    echo "::error::sha256sums.txt has an invalid checksum for ${asset}"
    exit 1
    ;;
esac
if [ "${#expected}" -ne 64 ]; then
  echo "::error::sha256sums.txt has an invalid checksum for ${asset}"
  exit 1
fi

actual="$(sha256sum "${download}")"
actual="${actual%% *}"
if [ "${actual}" != "${expected,,}" ]; then
  echo "::error::SHA-256 mismatch for ${asset}: expected ${expected,,}, got ${actual}"
  exit 1
fi

dest="${RUNNER_TEMP}/${exe}"
mv -f "${download}" "${dest}"
chmod +x "${dest}" || true   # no-op on Windows
echo "${RUNNER_TEMP}" >> "${GITHUB_PATH}"
