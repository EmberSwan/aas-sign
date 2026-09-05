# Distribution packages do not consistently provide an MbedTLS CMake config.
find_path(MbedTLS_INCLUDE_DIR mbedtls/ssl.h)
foreach(component mbedtls mbedx509 mbedcrypto)
  find_library(MbedTLS_${component}_LIBRARY NAMES ${component})
endforeach()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS REQUIRED_VARS MbedTLS_INCLUDE_DIR
  MbedTLS_mbedtls_LIBRARY MbedTLS_mbedx509_LIBRARY MbedTLS_mbedcrypto_LIBRARY)
if(MbedTLS_FOUND)
  foreach(component mbedtls mbedx509 mbedcrypto)
    if(NOT TARGET MbedTLS::${component})
      add_library(MbedTLS::${component} UNKNOWN IMPORTED)
      set_target_properties(MbedTLS::${component} PROPERTIES
        IMPORTED_LOCATION "${MbedTLS_${component}_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}")
    endif()
  endforeach()
endif()
