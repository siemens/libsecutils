# =============================
# Define targets
# =============================
add_library(siemens_libsecutils SHARED)
add_library(siemens::libsecutils ALIAS siemens_libsecutils)

set_target_properties(siemens_libsecutils PROPERTIES
    EXPORT_NAME libsecutils
    OUTPUT_NAME secutils
    SOVERSION ${siemens_secutils_VERSION_MAJOR}
    VERSION ${siemens_secutils_VERSION_MAJOR}.${siemens_secutils_VERSION_MINOR}.${siemens_secutils_VERSION_PATCH}
)

target_compile_features(siemens_libsecutils PRIVATE c_std_90)
set_target_properties(siemens_libsecutils PROPERTIES C_EXTENSIONS OFF)

# must be public, targets linking libsecutils need those too
target_compile_options(siemens_libsecutils PRIVATE
    $<$<CONFIG:Debug>:-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all>
)
target_link_options(siemens_libsecutils PUBLIC
    $<$<CONFIG:Debug>:-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all>
)

add_subdirectory(include)
add_subdirectory(src)

target_link_libraries(siemens_libsecutils
    PUBLIC
    $<$<BOOL:${SIEMENS_LIBSECUTILS_USE_UTA}>:-luta>

    PRIVATE
    OpenSSL::SSL
    secutils_compilation_options
)

# =============================
# Installing
# =============================
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

install(TARGETS siemens_libsecutils
    EXPORT siemens_libsecutilsTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT siemens_libsecutils_Runtime
    NAMELINK_COMPONENT siemens_libsecutils_Development
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT siemens_libsecutilsTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/siemens
    NAMESPACE siemens::
    FILE siemens_libsecutilsTargets.cmake
    COMPONENT siemens_libsecutils_Development
)

write_basic_package_version_file(
    siemens_libsecutilsConfigVersion.cmake
    VERSION ${siemens_libsecutils_VERSION}
    COMPATIBILITY SameMajorVersion # semantic versioning
)

install(FILES
    siemens_libsecutilsConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/siemens_libsecutilsConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/siemens
    COMPONENT siemens_libsecutils_Development
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT siemens_libsecutils_Development
    PATTERN CMakeLists.txt EXCLUDE
)
