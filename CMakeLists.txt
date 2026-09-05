cmake_minimum_required(VERSION 3.20)
project(aas-sign VERSION 1.3.0 LANGUAGES CXX C)
# Release labels preserve prerelease/build suffixes while numeric resources use
# the project's version. Refuse accidental tags for a different project version.
set(AAS_SIGN_RELEASE_VERSION "${PROJECT_VERSION}" CACHE STRING "Release version label (optional leading v)")
string(REGEX REPLACE "^v" "" AAS_SIGN_VERSION_STRING "${AAS_SIGN_RELEASE_VERSION}")
string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" _release_core "${AAS_SIGN_VERSION_STRING}")
if(NOT AAS_SIGN_VERSION_STRING MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+(-[A-Za-z0-9.-]+)?(\\+[A-Za-z0-9.-]+)?$"
   OR NOT _release_core STREQUAL PROJECT_VERSION)
  message(FATAL_ERROR "AAS_SIGN_RELEASE_VERSION must match project ${PROJECT_VERSION}, with optional prerelease/build suffixes")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable Windows resource compiler (windres on MinGW / rc on MSVC).
if(WIN32)
  enable_language(RC)
endif()

find_package(Threads REQUIRED)

# Dependency resolution mode:
#   FETCH (default)  nlohmann/json (+ mbedTLS on POSIX) come in via
#                    CMake FetchContent.  If a bundled copy is present
#                    under deps/<name>/ (as in a source-release
#                    tarball), that's used directly -- no download.
#                    Otherwise the pinned upstream archive is
#                    downloaded.
#   LOCAL            Use system-installed packages via find_package.
#                    Skips any download and ignores deps/.
set(DEPS "FETCH" CACHE STRING
    "Dependency resolution: FETCH or LOCAL")
set_property(CACHE DEPS PROPERTY STRINGS FETCH LOCAL)

if(NOT DEPS STREQUAL "LOCAL" AND NOT DEPS STREQUAL "FETCH")
  message(FATAL_ERROR "DEPS must be FETCH or LOCAL")
endif()

if(DEPS STREQUAL "LOCAL")
  find_package(nlohmann_json REQUIRED)
  message(STATUS "nlohmann/json: system")
  if(NOT WIN32)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    find_package(MbedTLS REQUIRED)
    message(STATUS "mbedTLS: system")
  endif()
else()
  include(FetchContent)

  if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/deps/json")
    set(FETCHCONTENT_SOURCE_DIR_JSON "${CMAKE_CURRENT_SOURCE_DIR}/deps/json")
    set(_json_origin "bundled")
  else()
    set(_json_origin "downloaded")
  endif()
  FetchContent_Declare(json
    URL                     https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    URL_HASH                SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
  FetchContent_MakeAvailable(json)
  message(STATUS "nlohmann/json: ${_json_origin}")

  if(NOT WIN32)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_AS_SUBPROJECT ON CACHE BOOL "" FORCE)
    # mbedTLS enables -Werror by default and newer clang (>=19)
    # adds diagnostics that trip it.  We don't need mbedTLS to be that
    # strict for our consumer-level use.
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
    # TLS 1.3 uses the global PSA keystore.  aas-sign performs HTTPS requests
    # from multiple signing workers, so the bundled library must protect that
    # state with its pthread threading implementation.
    set(MBEDTLS_USER_CONFIG_FILE
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/MbedTLSUserConfig.h"
        CACHE FILEPATH "" FORCE)
    set(LINK_WITH_PTHREAD ON CACHE BOOL "" FORCE)
    if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/deps/mbedtls")
      set(FETCHCONTENT_SOURCE_DIR_MBEDTLS
          "${CMAKE_CURRENT_SOURCE_DIR}/deps/mbedtls")
      set(_mbedtls_origin "bundled")
    else()
      set(_mbedtls_origin "downloaded")
    endif()
    FetchContent_Declare(mbedtls
      URL                     https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
      URL_HASH                SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
      DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
    FetchContent_MakeAvailable(mbedtls)
    message(STATUS "mbedTLS: ${_mbedtls_origin}")
  endif()
endif()

include(cmake/RecursiveDeps.cmake)

# Windows EXE metadata (CompanyName, FileVersion, etc.) via .rc file.
# The template substitutes CMake project version into both the numeric
# FILEVERSION/PRODUCTVERSION fields and the displayed string fields.
if(WIN32)
  configure_file(src/aas-sign.rc.in
                 ${CMAKE_CURRENT_BINARY_DIR}/aas-sign.rc @ONLY)
endif()

add_executable(aas-sign
  src/main.cpp
  src/base64.cpp
  src/der.cpp
  src/x509.cpp
  src/signing.cpp
  src/msi_recursive.cpp
  $<$<PLATFORM_ID:Windows>:src/msi_package_win32.cpp>
  $<$<NOT:$<PLATFORM_ID:Windows>>:src/msi_package_posix.cpp>
  src/azure.cpp
  src/cms.cpp
  src/oidc.cpp
  src/urlenc.cpp
  src/signer.cpp
  src/auth_laptop.cpp
  $<$<PLATFORM_ID:Windows>:src/win32.cpp>
  $<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_BINARY_DIR}/aas-sign.rc>
  $<$<NOT:$<PLATFORM_ID:Windows>>:src/posix.cpp>
)

target_compile_definitions(aas-sign PRIVATE
  AAS_SIGN_VERSION="${AAS_SIGN_VERSION_STRING}")

target_link_libraries(aas-sign PRIVATE nlohmann_json::nlohmann_json Threads::Threads aas_msi_dependencies)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(aas-sign PRIVATE -Wall -Wconversion)
endif()

if(WIN32)
  target_link_libraries(aas-sign PRIVATE
    winhttp bcrypt shell32 ws2_32 advapi32)
elseif(DEPS STREQUAL "LOCAL")
  target_link_libraries(aas-sign PRIVATE
    MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
else()
  target_include_directories(aas-sign PRIVATE
    ${mbedtls_SOURCE_DIR}/include)
  target_link_libraries(aas-sign PRIVATE
    mbedtls mbedx509 mbedcrypto)
endif()

# libFuzzer harnesses.  Built only when explicitly requested; requires
# Clang (for libFuzzer).  Detection of libstdc++ vs libc++ and the
# per-harness add_executable wiring live in cmake/Fuzzing.cmake.
option(AAS_SIGN_FUZZ "Build libFuzzer harnesses (Clang-only, POSIX)" OFF)

if(AAS_SIGN_FUZZ)
  list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
  include(Fuzzing)
endif()

include(CTest)
if(BUILD_TESTING AND NOT WIN32)
  function(aas_sign_link_posix_test target)
    target_include_directories(${target} PRIVATE src)
    target_compile_definitions(${target} PRIVATE AAS_SIGN_NO_MAIN)
    target_link_libraries(${target} PRIVATE
      nlohmann_json::nlohmann_json Threads::Threads)
    if(DEPS STREQUAL "LOCAL")
      target_link_libraries(${target} PRIVATE
        MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
    else()
      target_include_directories(${target} PRIVATE
        ${mbedtls_SOURCE_DIR}/include)
      target_link_libraries(${target} PRIVATE mbedtls mbedx509 mbedcrypto)
    endif()
  endfunction()

  add_executable(libmsi_ownership_test tests/libmsi_ownership_test.c)
  target_link_libraries(libmsi_ownership_test PRIVATE aas_msi_dependencies)
  if(AAS_SIGN_FUZZ AND DEPS STREQUAL "FETCH")
    target_compile_options(libmsi_ownership_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(libmsi_ownership_test PRIVATE -fsanitize=address,undefined)
  endif()
  add_test(NAME libmsi_ownership_test
    COMMAND libmsi_ownership_test
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/recursive.msi"
            "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/msi/minimal-msi-v3.msi")

  add_executable(cms_test
    tests/cms_test.cpp src/cms.cpp src/der.cpp src/x509.cpp src/posix.cpp)
  target_compile_definitions(cms_test PRIVATE
    AAS_SIGN_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  aas_sign_link_posix_test(cms_test)
  add_test(NAME cms_test COMMAND cms_test)

  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME action_sign_test
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/action_sign_test.py")
  add_test(NAME release_assets_test
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/release_assets_test.py")

  add_test(NAME action_install_test
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/action_install_test.sh"
                 "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

if(BUILD_TESTING AND AAS_SIGN_FUZZ)
  set(_aas_fuzz_msi_corpus
    "${CMAKE_CURRENT_BINARY_DIR}/fuzz-corpus/msi")
  file(REMOVE_RECURSE "${_aas_fuzz_msi_corpus}")
  file(MAKE_DIRECTORY "${_aas_fuzz_msi_corpus}")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/msi/minimal-msi-v3.msi"
    "${_aas_fuzz_msi_corpus}/minimal-msi-v3.msi" COPYONLY)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/recursive.msi"
    "${_aas_fuzz_msi_corpus}/recursive.msi" COPYONLY)
  add_test(NAME fuzz_msi_smoke
    COMMAND fuzz_msi
      -runs=1000
      -max_len=16777216
      -dict=${CMAKE_CURRENT_SOURCE_DIR}/fuzz/msi.dict
      ${_aas_fuzz_msi_corpus})
  set_tests_properties(fuzz_msi_smoke PROPERTIES TIMEOUT 60)
endif()

if(BUILD_TESTING)
  set(_platform_source src/posix.cpp)
  if(WIN32)
    set(_platform_source src/win32.cpp)
  endif()
  add_executable(platform_test tests/platform_test.cpp ${_platform_source})
  target_include_directories(platform_test PRIVATE src)
  target_link_libraries(platform_test PRIVATE Threads::Threads)
  if(WIN32)
    target_link_libraries(platform_test PRIVATE winhttp bcrypt shell32 ws2_32 advapi32)
  else()
    aas_sign_link_posix_test(platform_test)
  endif()
  add_test(NAME platform_test COMMAND platform_test)

  add_executable(signing_test_driver tests/signing_driver.cpp
    src/signing.cpp src/cms.cpp src/der.cpp src/x509.cpp src/base64.cpp
    src/msi_recursive.cpp ${_platform_source}
    $<$<PLATFORM_ID:Windows>:src/msi_package_win32.cpp>
    $<$<NOT:$<PLATFORM_ID:Windows>>:src/msi_package_posix.cpp>)
  target_include_directories(signing_test_driver PRIVATE src)
  target_link_libraries(signing_test_driver PRIVATE aas_msi_dependencies Threads::Threads)
  if(WIN32)
    target_link_libraries(signing_test_driver PRIVATE winhttp bcrypt shell32 ws2_32 advapi32)
  else()
    aas_sign_link_posix_test(signing_test_driver)
  endif()
  add_executable(msi_recursive_test tests/msi_recursive_test.cpp
    src/msi_recursive.cpp ${_platform_source}
    $<$<PLATFORM_ID:Windows>:src/msi_package_win32.cpp>
    $<$<NOT:$<PLATFORM_ID:Windows>>:src/msi_package_posix.cpp>)
  target_include_directories(msi_recursive_test PRIVATE src)
  target_compile_definitions(msi_recursive_test PRIVATE AAS_SIGN_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(msi_recursive_test PRIVATE aas_msi_dependencies Threads::Threads)
  if(WIN32)
    target_link_libraries(msi_recursive_test PRIVATE winhttp bcrypt shell32 ws2_32 advapi32)
  else()
    aas_sign_link_posix_test(msi_recursive_test)
  endif()
  add_test(NAME msi_recursive_test COMMAND msi_recursive_test)

  set(AAS_SIGN_OSSLSIGNCODE "" CACHE FILEPATH "Companion executable for interoperability tests")
  if(AAS_SIGN_OSSLSIGNCODE)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME signing_integration_test
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/signing_integration_test.py"
              "$<TARGET_FILE:signing_test_driver>" "${AAS_SIGN_OSSLSIGNCODE}" "${CMAKE_CURRENT_SOURCE_DIR}"
              "$<TARGET_FILE:msi_recursive_test>")
    set_tests_properties(signing_integration_test PROPERTIES TIMEOUT 180)
  endif()
endif()
