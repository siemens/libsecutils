# =============================
# Define targets
# =============================
add_executable(siemens_icvutil icvutil.c)
add_executable(siemens::icvutil ALIAS siemens_icvutil)

set_target_properties(siemens_icvutil PROPERTIES
    EXPORT_NAME icvutil
    OUTPUT_NAME icvutil
)

target_compile_features(siemens_icvutil PRIVATE c_std_90)
set_target_properties(siemens_icvutil PROPERTIES C_EXTENSIONS OFF)
target_compile_options(siemens_icvutil PRIVATE
    -Woverflow -Wswitch -Wmissing-prototypes -Wstrict-prototypes
    -Wtype-limits -Wundef -Wconversion -Wno-shadow -Wno-conversion
    -Wno-sign-conversion -Wno-unused-parameter -Wno-sign-compare # TODO enable -Wsign-conversion -Wsign-compare -Wunused-parameter
    -Wformat -Wformat-security -Wno-declaration-after-statement -Wno-vla # -Wpointer-arith -pedantic -DPEDANTIC # -Werror
    -pedantic -Werror
)

target_link_libraries(siemens_icvutil PRIVATE siemens::libsecutils)

# =============================
# Installing
# =============================
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

install(TARGETS siemens_icvutil
    EXPORT siemens_icvutilTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT siemens_icvutil_Runtime
)

install(EXPORT siemens_icvutilTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/siemens
    NAMESPACE siemens::
    FILE siemens_icvutilTargets.cmake
    COMPONENT siemens_icvutil_Development
)

write_basic_package_version_file(
    siemens_icvutilConfigVersion.cmake
    VERSION ${siemens_icvutil_VERSION}
    COMPATIBILITY SameMajorVersion # semantic versioning
)

install(FILES
    siemens_icvutilConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/siemens_icvutilConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/siemens
    COMPONENT siemens_icvutil_Development
)
