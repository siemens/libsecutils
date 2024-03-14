# =============================
# Define targets
# =============================
add_executable(security-utilities_icvutil icvutil.c)
add_executable(security-utilities::icvutil ALIAS security-utilities_icvutil)

set_target_properties(security-utilities_icvutil PROPERTIES
    EXPORT_NAME icvutil
    OUTPUT_NAME icvutil
)

# TODO maybe clean up code and re-enable property
# set_target_properties(security-utilities_library PROPERTIES C_STANDARD 90)
# target_compile_features(security-utilities_library PRIVATE c_std_90)  # would have no effect
set_target_properties(security-utilities_library PROPERTIES C_EXTENSIONS ON)

target_link_libraries(security-utilities_icvutil
    PRIVATE
    security-utilities::library
    secutils_compilation_options
    $<$<BOOL:${SECURITY_UTILITIES_USE_UTA}>:security-utilities_uta-api>
)

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
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/security-utilities
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
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/security-utilities
    COMPONENT security-utilities_icvutil_Development
)
