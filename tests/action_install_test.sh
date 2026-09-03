#!/usr/bin/env bash
set -euo pipefail

source_dir="${1:?source directory is required}"
test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT

release_dir="${test_dir}/release"
fake_bin="${test_dir}/bin"
mkdir -p "${release_dir}" "${fake_bin}"

printf 'generic linux executable\n' > "${release_dir}/aas-sign-linux-x86_64"
printf 'generic windows executable\n' > "${release_dir}/aas-sign-windows-x86_64.exe"
(
  cd "${release_dir}"
  sha256sum aas-sign-linux-x86_64 aas-sign-windows-x86_64.exe \
    > sha256sums.txt
)

cat > "${fake_bin}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      output="$2"
      shift 2
      ;;
    -* )
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done

[ -n "${output}" ] && [ -n "${url}" ]
case "${url}" in
  https://github.com/ExampleOrg/example-action/releases/download/v9.8.7/*) ;;
  *)
    echo "unexpected URL: ${url}" >&2
    exit 1
    ;;
esac

printf '%s\n' "${url}" >> "${CURL_LOG}"
cp "${FAKE_RELEASE_DIR}/${url##*/}" "${output}"
EOF
chmod +x "${fake_bin}/curl"

run_install()
{
  local runner_os="$1"
  local runner_temp="$2"
  mkdir -p "${runner_temp}"
  : > "${runner_temp}/github-path"
  ACTION_REPOSITORY=ExampleOrg/example-action \
  VERSION=v9.8.7 \
  RUNNER_ARCH=X64 \
  RUNNER_OS="${runner_os}" \
  RUNNER_TEMP="${runner_temp}" \
  GITHUB_PATH="${runner_temp}/github-path" \
  CURL_LOG="${runner_temp}/curl.log" \
  FAKE_RELEASE_DIR="${release_dir}" \
  PATH="${fake_bin}:${PATH}" \
    bash "${source_dir}/scripts/install-action.sh"
}

linux_temp="${test_dir}/linux"
run_install Linux "${linux_temp}"
cmp "${release_dir}/aas-sign-linux-x86_64" "${linux_temp}/aas-sign"
grep -Fxq "${linux_temp}" "${linux_temp}/github-path"
grep -Fxq \
  'https://github.com/ExampleOrg/example-action/releases/download/v9.8.7/sha256sums.txt' \
  "${linux_temp}/curl.log"
grep -Fxq \
  'https://github.com/ExampleOrg/example-action/releases/download/v9.8.7/aas-sign-linux-x86_64' \
  "${linux_temp}/curl.log"

windows_temp="${test_dir}/windows"
run_install Windows "${windows_temp}"
cmp "${release_dir}/aas-sign-windows-x86_64.exe" \
  "${windows_temp}/aas-sign.exe"

printf 'corrupted executable\n' > "${release_dir}/aas-sign-linux-x86_64"
corrupt_temp="${test_dir}/corrupt"
if run_install Linux "${corrupt_temp}" > "${test_dir}/corrupt.out" 2>&1; then
  echo "corrupt release asset was accepted" >&2
  exit 1
fi
grep -Fq '::error::SHA-256 mismatch for aas-sign-linux-x86_64' \
  "${test_dir}/corrupt.out"
if [ -e "${corrupt_temp}/aas-sign" ]; then
  echo "corrupt release asset was installed" >&2
  exit 1
fi
