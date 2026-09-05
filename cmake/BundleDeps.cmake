# Bundle dependencies into deps/ for offline source releases.
# Usage: cmake -P cmake/BundleDeps.cmake
#
# Downloads the same upstream archives the main CMakeLists.txt
# pins and extracts them under deps/.  After running this, the
# tree can be `cmake -B build`'d with no network access: the
# FETCH mode sees deps/<name>/ and uses it directly.

if(NOT DEPS_DIR)
  set(DEPS_DIR "${CMAKE_CURRENT_LIST_DIR}/../deps")
endif()

# Keep these URL/hash pairs in lock-step with the FetchContent_Declare
# entries in ../CMakeLists.txt.
set(JSON_URL  "https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz")
set(JSON_HASH "d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d")

set(MBEDTLS_URL  "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2")
set(MBEDTLS_HASH "a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6")

function(bundle_dep name url hash)
  set(dest "${DEPS_DIR}/${name}")
  if(IS_DIRECTORY "${dest}")
    message(STATUS "${name}: already bundled")
    return()
  endif()

  set(local "${CMAKE_CURRENT_LIST_DIR}/../deps/${name}")
  if(IS_DIRECTORY "${local}")
    file(COPY "${local}" DESTINATION "${DEPS_DIR}")
    return()
  endif()

  string(REGEX REPLACE ".*/" "" archive "${url}")
  set(archive_path "${DEPS_DIR}/${archive}")
  message(STATUS "${name}: downloading ${url}")
  file(DOWNLOAD "${url}" "${archive_path}"
       EXPECTED_HASH SHA256=${hash}
       SHOW_PROGRESS)

  # Extract into a scratch dir, then move the sole top-level directory
  # the archive produces to deps/<name>/.
  set(tmp "${DEPS_DIR}/_tmp_${name}")
  file(REMOVE_RECURSE "${tmp}")
  file(MAKE_DIRECTORY "${tmp}")
  file(ARCHIVE_EXTRACT INPUT "${archive_path}" DESTINATION "${tmp}")
  file(REMOVE "${archive_path}")

  file(GLOB children "${tmp}/*")
  list(LENGTH children n)
  if(n EQUAL 1 AND IS_DIRECTORY "${children}")
    file(RENAME "${children}" "${dest}")
  else()
    file(RENAME "${tmp}" "${dest}")
  endif()
  file(REMOVE_RECURSE "${tmp}")

  message(STATUS "${name}: bundled into ${dest}")
endfunction()

file(MAKE_DIRECTORY "${DEPS_DIR}")
bundle_dep(json    "${JSON_URL}"    "${JSON_HASH}")
bundle_dep(mbedtls "${MBEDTLS_URL}" "${MBEDTLS_HASH}")

# The companion is rebuilt from an initialized Git checkout, not bundled here.
# MSI reconstruction libraries are included for the offline aas-sign build.
# Copy only named source directories; deps/.env and other private files are
# deliberately outside this allowlist.
find_program(PYTHON3 python3 REQUIRED)
execute_process(
  COMMAND "${PYTHON3}" "${CMAKE_CURRENT_LIST_DIR}/../scripts/build-dependencies.py"
          bundle --sources "${DEPS_DIR}"
  RESULT_VARIABLE recursive_bundle_result)
if(NOT recursive_bundle_result EQUAL 0)
  message(FATAL_ERROR "Bundling MSI dependency sources failed")
endif()
