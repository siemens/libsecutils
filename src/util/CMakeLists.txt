# =============================
# Define targets
# =============================
add_executable(security-utilities_icvutil icvutil.c)
add_executable(security-utilities::icvutil ALIAS security-utilities_icvutil)

set_target_properties(security-utilities_icvutil PROPERTIES
    EXPORT_NAME icvutil
    OUTPUT_NAME icvutil
)

target_compile_features(security-utilities_icvutil PRIVATE c_std_90)
set_target_properties(security-utilities_icvutil PROPERTIES C_EXTENSIONS OFF)

target_link_libraries(security-utilities_icvutil PRIVATE security-utilities::library secutils_compilation_options)

# =============================
# Installing
# =============================
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

install(TARGETS security-utilities_icvutil
    EXPORT security-utilities_icvutilTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT security-utilities_icvutil_Runtime
)

install(EXPORT security-utilities_icvutilTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/siemens
    NAMESPACE security-utilities::
    FILE security-utilities_icvutilTargets.cmake
    COMPONENT security-utilities_icvutil_Development
)

write_basic_package_version_file(
    security-utilities_icvutilConfigVersion.cmake
    VERSION ${security-utilities_icvutil_VERSION}
    COMPATIBILITY SameMajorVersion # semantic versioning
)

install(FILES
    security-utilities_icvutilConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/security-utilities_icvutilConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/siemens
    COMPONENT security-utilities_icvutil_Development
)
