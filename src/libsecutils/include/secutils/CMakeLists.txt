add_subdirectory(certstatus)
add_subdirectory(config)
add_subdirectory(connections)
add_subdirectory(credentials)
add_subdirectory(crypto)
add_subdirectory(storage)
add_subdirectory(util)

target_sources(security-utilities_library PRIVATE
    operators.h
    basic.h
)

target_include_directories(security-utilities_library PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
    $<INSTALL_INTERFACE:include>
)

if(SECURITY_UTILITIES_USE_UTA)
    set(SECUTILS_USE_UTA ON)
endif()

if(SECURITY_UTILITIES_USE_ICV)
    set(SECUTILS_USE_ICV ON)
endif()

if(SECURITY_UTILITIES_NO_TLS)
    set(SECUTILS_NO_TLS ON)
endif()

configure_file(secutils_static_config.h.in secutils_static_config.h)

target_include_directories(security-utilities_library PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)
