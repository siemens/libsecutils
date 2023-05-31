add_subdirectory(certstatus)
add_subdirectory(config)
add_subdirectory(connections)
add_subdirectory(credentials)
add_subdirectory(crypto)
add_subdirectory(storage)
add_subdirectory(util)

target_sources(siemens_libsecutils PRIVATE
    operators.h
    basic.h
)

target_include_directories(siemens_libsecutils PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
    $<INSTALL_INTERFACE:include>
)

if(SIEMENS_LIBSECUTILS_USE_UTA OR DEFINED ENV{SECUTILS_USE_UTA})
    set(SECUTILS_USE_UTA ON)
endif()

if(SIEMENS_LIBSECUTILS_USE_ICV OR DEFINED ENV{SECUTILS_USE_ICV})
    set(SECUTILS_USE_ICV ON)
endif()

if(SIEMENS_LIBSECUTILS_NO_TLS OR DEFINED ENV{SECUTILS_NO_TLS})
    set(SECUTILS_NO_TLS ON)
endif()

configure_file(static_config.h.in static_config.h)

target_include_directories(siemens_libsecutils PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)
