add_subdirectory(secutils)

target_include_directories(security-utilities_library PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}> # make sure that secutils_static_config.h is taken from the build dir
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
    $<INSTALL_INTERFACE:include>
)
