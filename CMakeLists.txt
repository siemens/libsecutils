cmake_minimum_required(VERSION 3.7)

set( CMAKE_VERBOSE_MAKEFILE on )

project(secutils)

if (NOT YOCTO_BUILD)

    find_package(Git)

    if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")

        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            RESULT_VARIABLE GIT_SUBMOD_RESULT
        )

        if(NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "git submodule update --init failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
        endif()

    else()
        message(FATAL_ERROR "GIT not found please install git...")
    endif()

endif()

if(NOT DEFINED SECUTILS_VERSION )
    set(SECUTILS_VERSION 0.9)
endif()

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/secutils
    ${PROJECT_SOURCE_DIR}/libs/interfaces/include
)

include_directories(
    ${INCLUDE_DIRS}
)

set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(SRC_EXAMPLE_DIR ${PROJECT_SOURCE_DIR}/test)

find_package(OpenSSL REQUIRED)

# Add this to get some additional runtime checks.
# Warning: it's incompatible with tools like Valgrind and you have to add it to the app using this lib too.
# add_definitions("-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all")
# link_libraries("-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all")

add_definitions(-Wall -Woverflow -Wextra -Wswitch -Wmissing-prototypes -Wstrict-prototypes -Wformat -Wtype-limits -Wundef -Wconversion -Wno-shadow -Wno-conversion -Wno-sign-conversion -Wno-unused-parameter -Wno-sign-compare) # TODO enable -Wconversion -Wsign-conversion -Wsign-compare -Wunused-parameter
add_definitions(-Wformat -Wformat-security -Wno-declaration-after-statement -Wno-vla) # -Wpointer-arith -pedantic -DPEDANTIC # -Werror

if(DEFINED ENV{SECUTILS_USE_UTA})
  add_definitions(-DSECUTILS_USE_UTA=1)
endif()
if(DEFINED ENV{SECUTILS_CONFIG_USE_ICV})
  add_definitions(-DSECUTILS_CONFIG_USE_ICV=1)
endif()
if(DEFINED ENV{SECUTILS_NO_TLS})
  add_definitions(-DSECUTILS_NO_TLS=1)
endif()

set(SECUTIL_LIB_SRC ${SRC_DIR}/certstatus/certstatus.c
    ${SRC_DIR}/certstatus/cdp_util.c
    ${SRC_DIR}/certstatus/certstatus.c
    ${SRC_DIR}/certstatus/crl_mgmt.c
    ${SRC_DIR}/certstatus/crls.c
    ${SRC_DIR}/certstatus/ocsp.c
    ${SRC_DIR}/config/config.c
    ${SRC_DIR}/config/config_update.c
    ${SRC_DIR}/config/opt.c
    ${SRC_DIR}/connections/conn.c
    ${SRC_DIR}/connections/http.c
    ${SRC_DIR}/connections/tls.c
    ${SRC_DIR}/credentials/cert.c
    ${SRC_DIR}/credentials/credentials.c
    ${SRC_DIR}/credentials/key.c
    ${SRC_DIR}/credentials/store.c
    ${SRC_DIR}/credentials/trusted.c
    ${SRC_DIR}/credentials/verify.c
    ${SRC_DIR}/crypto/crypto.c
    ${SRC_DIR}/storage/files.c
    ${SRC_DIR}/storage/files_dv.c
    ${SRC_DIR}/storage/files_icv.c
    ${SRC_DIR}/storage/uta_api.c
    ${SRC_DIR}/util/extensions.c
    ${SRC_DIR}/util/log.c
    ${SRC_DIR}/util/util.c
)

#${SRC_DIR}/storage/uta_api.c

add_library(secutils SHARED
    ${SECUTIL_LIB_SRC}
)

target_link_libraries(secutils ${OPENSSL_LIBRARIES} )
set_property(TARGET secutils PROPERTY C_STANDARD 90)

set_target_properties(secutils PROPERTIES
    VERSION ${SECUTILS_VERSION}
)

install(TARGETS secutils
    LIBRARY
        DESTINATION lib
        COMPONENT Library
)

install(DIRECTORY include/
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
)

