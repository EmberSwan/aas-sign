cmake_minimum_required(VERSION 3.20)
project(aas-sign VERSION 1.2.0 LANGUAGES CXX C)
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

if(DEPS STREQUAL "LOCAL")
  find_package(nlohmann_json REQUIRED)
  message(STATUS "nlohmann/json: system")
  if(NOT WIN32)
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
  src/pe.cpp
  src/msi.cpp
  src/azure.cpp
  src/cms.cpp
  src/tsa.cpp
  src/oidc.cpp
  src/urlenc.cpp
  src/signer.cpp
  src/auth_laptop.cpp
  $<$<PLATFORM_ID:Windows>:src/win32.cpp>
  $<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_BINARY_DIR}/aas-sign.rc>
  $<$<NOT:$<PLATFORM_ID:Windows>>:src/posix.cpp>
)

target_compile_definitions(aas-sign PRIVATE
  AAS_SIGN_VERSION="${PROJECT_VERSION}")

target_link_libraries(aas-sign PRIVATE nlohmann_json::nlohmann_json Threads::Threads)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(aas-sign PRIVATE -Wall -Wconversion)
endif()

if(WIN32)
  target_link_libraries(aas-sign PRIVATE
    winhttp bcrypt shell32 ws2_32)
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

  add_executable(msi_test
    tests/msi_test.cpp src/msi.cpp src/posix.cpp)
  target_compile_definitions(msi_test PRIVATE
    AAS_SIGN_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  aas_sign_link_posix_test(msi_test)
  add_test(NAME msi_test COMMAND msi_test)

  add_executable(cms_test
    tests/cms_test.cpp src/cms.cpp src/der.cpp src/x509.cpp src/posix.cpp)
  target_compile_definitions(cms_test PRIVATE
    AAS_SIGN_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  aas_sign_link_posix_test(cms_test)
  add_test(NAME cms_test COMMAND cms_test)
endif()

if(BUILD_TESTING AND AAS_SIGN_FUZZ)
  set(_aas_fuzz_msi_corpus
    "${CMAKE_CURRENT_BINARY_DIR}/fuzz-corpus/msi")
  file(REMOVE_RECURSE "${_aas_fuzz_msi_corpus}")
  file(MAKE_DIRECTORY "${_aas_fuzz_msi_corpus}")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/msi/minimal-msi-v3.msi"
    "${_aas_fuzz_msi_corpus}/minimal-msi-v3.msi" COPYONLY)
  add_test(NAME fuzz_msi_smoke
    COMMAND fuzz_msi
      -runs=1000
      -max_len=16777216
      -dict=${CMAKE_CURRENT_SOURCE_DIR}/fuzz/msi.dict
      ${_aas_fuzz_msi_corpus})
  set_tests_properties(fuzz_msi_smoke PROPERTIES TIMEOUT 60)
endif()
