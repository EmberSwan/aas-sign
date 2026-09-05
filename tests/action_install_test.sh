#!/usr/bin/env bash
set -euo pipefail
source_dir="${1:?source directory is required}"
test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT
release_dir="${test_dir}/release"
fake_bin="${test_dir}/bin"
mkdir -p "${release_dir}" "${fake_bin}"
for platform in linux windows; do
  suffix=; [ "${platform}" != windows ] || suffix=.exe
  for tool in aas-sign-9.8.7 osslsigncode-abcdef01; do
    printf 'executable that must never be invoked\n' > "${release_dir}/${tool}-${platform}-x86_64${suffix}"
  done
done
(cd "${release_dir}"; sha256sum aas-* osslsigncode-* > sha256sums.txt)
cp "${release_dir}/sha256sums.txt" "${test_dir}/manifest"
cat > "${fake_bin}/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
output=; url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "${url}" in
  https://artifacts.emberswan.com/aas-sign/v9.8.7*/sha256sums.txt) ;;
  https://github.com/ExampleOrg/example-action/releases/download/v9.8.7*/*) ;;
  *) echo "unexpected URL: ${url}" >&2; exit 1 ;;
esac
printf '%s\n' "${url}" >> "${CURL_LOG}"
cp "${FAKE_RELEASE_DIR}/${url##*/}" "${output}"
CURL
chmod +x "${fake_bin}/curl"
run_install() {
  local runner_os="$1" runner_temp="$2" version="${3:-v9.8.7}"
  mkdir -p "${runner_temp}"
  : > "${runner_temp}/github-path"
  : > "${runner_temp}/github-env"
  ACTION_REPOSITORY=ExampleOrg/example-action VERSION="${version}" RUNNER_ARCH=X64 \
    RUNNER_OS="${runner_os}" RUNNER_TEMP="${runner_temp}" GITHUB_PATH="${runner_temp}/github-path" \
    GITHUB_ENV="${runner_temp}/github-env" CURL_LOG="${runner_temp}/curl.log" \
    FAKE_RELEASE_DIR="${release_dir}" PATH="${fake_bin}:${PATH}" \
      bash "${source_dir}/scripts/install-action.sh"
}
for platform in Linux Windows; do
  directory="${test_dir}/${platform} path"
  run_install "${platform}" "${directory}"
  install_dir="$(cat "${directory}/github-path")"
  suffix=; [ "${platform}" != Windows ] || suffix=.exe
  cmp "${release_dir}/aas-sign-9.8.7-${platform,,}-x86_64${suffix}" "${install_dir}/aas-sign${suffix}"
  cmp "${release_dir}/osslsigncode-abcdef01-${platform,,}-x86_64${suffix}" "${install_dir}/osslsigncode${suffix}"
  [ "$(wc -l < "${directory}/curl.log")" -eq 3 ]
  [ "$(cat "${directory}/github-env")" = "AAS_SIGN_OSSLSIGNCODE=${install_dir}/osslsigncode${suffix}" ]
done
fail_install() {
  local scenario="$1"
  if run_install Linux "${test_dir}/${scenario}" > "${test_dir}/${scenario}.out" 2>&1; then
    echo "${scenario} was accepted" >&2; exit 1
  fi
  [ ! -s "${test_dir}/${scenario}/github-path" ]
  [ ! -s "${test_dir}/${scenario}/github-env" ]
  [ -z "$(find "${test_dir}/${scenario}" -name 'aas-sign' -o -name 'osslsigncode')" ]
}
printf 'corrupt\n' > "${release_dir}/osslsigncode-abcdef01-linux-x86_64"
fail_install corrupt_companion
printf 'executable that must never be invoked\n' > "${release_dir}/osslsigncode-abcdef01-linux-x86_64"
printf 'corrupt\n' > "${release_dir}/aas-sign-9.8.7-linux-x86_64"
fail_install corrupt_aas
printf 'executable that must never be invoked\n' > "${release_dir}/aas-sign-9.8.7-linux-x86_64"
for scenario in duplicate_aas duplicate_companion ambiguous_companion missing_companion missing_aas invalid_checksum malformed_entry; do
  cp "${test_dir}/manifest" "${release_dir}/sha256sums.txt"
  case "${scenario}" in
    duplicate_aas) sed -n '/aas-sign.*linux/p' "${test_dir}/manifest" >> "${release_dir}/sha256sums.txt" ;;
    duplicate_companion) sed -n '/osslsigncode.*linux/p' "${test_dir}/manifest" >> "${release_dir}/sha256sums.txt" ;;
    ambiguous_companion) sed -n '/osslsigncode.*linux/{s/abcdef01/12345678/p;}' "${test_dir}/manifest" >> "${release_dir}/sha256sums.txt" ;;
    missing_companion) sed -i '/osslsigncode.*linux/d' "${release_dir}/sha256sums.txt" ;;
    missing_aas) sed -i '/aas-sign.*linux/d' "${release_dir}/sha256sums.txt" ;;
    invalid_checksum) sed -i '/aas-sign.*linux/s/^[^ ]*/nothash/' "${release_dir}/sha256sums.txt" ;;
    malformed_entry) sed -i '/osslsigncode.*linux/s/$/ trailing/' "${release_dir}/sha256sums.txt" ;;
  esac
  fail_install "${scenario}"
done
# The exact selected release version must survive prerelease normalization.
cp "${release_dir}/aas-sign-9.8.7-linux-x86_64" "${release_dir}/aas-sign-9.8.7-rc.2-linux-x86_64"
sed 's/aas-sign-9.8.7-linux/aas-sign-9.8.7-rc.2-linux/' "${test_dir}/manifest" > "${release_dir}/sha256sums.txt"
run_install Linux "${test_dir}/prerelease" v9.8.7-rc.2
