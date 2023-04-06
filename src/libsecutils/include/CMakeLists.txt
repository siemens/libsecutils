add_subdirectory(secutils)

target_include_directories(siemens_libsecutils PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
    $<INSTALL_INTERFACE:include>
)
