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
target_compile_options(siemens_libsecutils PRIVATE
    -Woverflow -Wswitch -Wmissing-prototypes -Wstrict-prototypes
    -Wtype-limits -Wundef -Wconversion -Wno-shadow -Wno-conversion
    -Wno-sign-conversion -Wno-unused-parameter -Wno-sign-compare # TODO enable -Wsign-conversion -Wsign-compare -Wunused-parameter
    -Wformat -Wformat-security -Wno-declaration-after-statement -Wno-vla # -Wpointer-arith -pedantic -DPEDANTIC # -Werror
    -pedantic -Werror
)

# must be public, targets linking libsecutils need those too
target_compile_options(siemens_libsecutils PRIVATE
    $<$<CONFIG:Debug>:-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all>
)
target_link_options(siemens_libsecutils PUBLIC
    $<$<CONFIG:Debug>:-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all>
)

if(SIEMENS_LIBSECUTILS_USE_UTA)
    target_link_libraries(siemens_libsecutils PUBLIC -luta)
endif()

add_subdirectory(include)
add_subdirectory(src)

target_link_libraries(siemens_libsecutils PRIVATE OpenSSL::SSL)

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
    INCLUDES DESTINATION include
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
    DESTINATION include
    COMPONENT siemens_libsecutils_Development
    PATTERN CMakeLists.txt EXCLUDE
)