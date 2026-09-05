# MSI reconstruction uses the same database/CAB APIs in both dependency modes.
if(NOT WIN32)
  find_package(PkgConfig REQUIRED)
  if(DEPS STREQUAL "FETCH")
    find_package(Python3 3.12 COMPONENTS Interpreter REQUIRED)
    set(_recursive_prefix "${CMAKE_BINARY_DIR}/recursive-deps/prefix")
    # Build once during configuration so pkg-config can describe the complete
    # static dependency closure. Each dependency has a configuration stamp.
    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E env
              "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
              "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/build-dependencies.py"
              msi --build "${CMAKE_BINARY_DIR}/recursive-deps"
      RESULT_VARIABLE _recursive_result)
    if(NOT _recursive_result EQUAL 0)
      message(FATAL_ERROR "Building recursive MSI dependencies failed; install Meson >=1.4, Ninja, Bison, Vala, gettext, patch, pkg-config and a C toolchain, or use -DDEPS=LOCAL")
    endif()
    set(_saved_pc_path "$ENV{PKG_CONFIG_PATH}")
    set(_saved_pc_libdir "$ENV{PKG_CONFIG_LIBDIR}")
    set(ENV{PKG_CONFIG_PATH} "${_recursive_prefix}/lib/pkgconfig")
    set(ENV{PKG_CONFIG_LIBDIR} "${_recursive_prefix}/lib/pkgconfig")
  endif()
  pkg_check_modules(MSI_PACKAGE REQUIRED IMPORTED_TARGET libmsi-1.0 libgcab-1.0>=1.4)
  add_library(aas_msi_dependencies INTERFACE)
  if(DEPS STREQUAL "FETCH")
    target_include_directories(aas_msi_dependencies INTERFACE ${MSI_PACKAGE_STATIC_INCLUDE_DIRS})
    target_link_directories(aas_msi_dependencies INTERFACE ${MSI_PACKAGE_STATIC_LIBRARY_DIRS})
    target_link_libraries(aas_msi_dependencies INTERFACE ${MSI_PACKAGE_STATIC_LIBRARIES})
    target_link_options(aas_msi_dependencies INTERFACE ${MSI_PACKAGE_STATIC_LDFLAGS_OTHER})
    target_compile_options(aas_msi_dependencies INTERFACE ${MSI_PACKAGE_STATIC_CFLAGS_OTHER})
    set(ENV{PKG_CONFIG_PATH} "${_saved_pc_path}")
    set(ENV{PKG_CONFIG_LIBDIR} "${_saved_pc_libdir}")
  else()
    target_link_libraries(aas_msi_dependencies INTERFACE PkgConfig::MSI_PACKAGE)
  endif()
else()
  add_library(aas_msi_dependencies INTERFACE)
  target_link_libraries(aas_msi_dependencies INTERFACE msi cabinet rpcrt4 ole32)
endif()
