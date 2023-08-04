# =============================
# Define targets
# =============================
add_library(security-utilities_library SHARED)
add_library(security-utilities::library ALIAS security-utilities_library)

set_target_properties(security-utilities_library PROPERTIES
    EXPORT_NAME library
    OUTPUT_NAME secutils
    SOVERSION ${security-utilities_VERSION_MAJOR}
    VERSION ${security-utilities_VERSION_MAJOR}.${security-utilities_VERSION_MINOR}.${security-utilities_VERSION_PATCH}
)

target_compile_features(security-utilities_library PRIVATE c_std_90)
set_target_properties(security-utilities_library PROPERTIES C_EXTENSIONS OFF)

# must be public, targets linking libsecutils need those too
target_compile_options(security-utilities_library PRIVATE
    $<$<CONFIG:Debug>:-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all>
)
target_link_options(security-utilities_library PUBLIC
    $<$<CONFIG:Debug>:-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all>
)

add_subdirectory(include)
add_subdirectory(src)

target_link_libraries(security-utilities_library
    PUBLIC
    $<$<BOOL:${SIEMENS_LIBSECUTILS_USE_UTA}>:-luta>

    # must be public, targets linking the library need those too
    $<$<CONFIG:Debug>:security-utlities_sanitizer_options>

    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    secutils_compilation_options
)

# =============================
# Installing
# =============================
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

install(TARGETS security-utilities_library
    EXPORT security-utilities_libraryTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT security-utilities_library_Runtime
    NAMELINK_COMPONENT security-utilities_library_Development
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT security-utilities_libraryTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/siemens
    NAMESPACE security-utilities::
    FILE security-utilities_libraryTargets.cmake
    COMPONENT security-utilities_library_Development
)

write_basic_package_version_file(
    security-utilities_libraryConfigVersion.cmake
    VERSION ${security-utilities_library_VERSION}
    COMPATIBILITY SameMajorVersion # semantic versioning
)

install(FILES
    security-utilities_libraryConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/security-utilities_libraryConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/siemens
    COMPONENT security-utilities_library_Development
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT security-utilities_library_Development
    PATTERN CMakeLists.txt EXCLUDE
)
