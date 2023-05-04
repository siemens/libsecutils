cmake_minimum_required(VERSION 3.7)

project(secutils)

if(NOT DEFINED SECUTILS_VERSION)
  set(SECUTILS_VERSION_MAJOR 2)
  set(SECUTILS_VERSION ${SECUTILS_VERSION_MAJOR}.0)
endif()

message(STATUS "SecurityUtilities version " ${SECUTILS_VERSION})

# set(CMAKE_VERBOSE_MAKEFILE on)

if(NOT("$ENV{OPENSSL_DIR}" STREQUAL ""))
  message(STATUS "using OpenSSL from " $ENV{OPENSSL_DIR})
  if(DEFINED ENV{OPENSSL_LIB})
    set(OPENSSL_LIB $ENV{OPENSSL_LIB})
  else()
    set(OPENSSL_LIB $ENV{OPENSSL_DIR})
  endif()
  set(OpenSSL_INCLUDE_DIRS $ENV{OPENSSL_DIR}/include)
  set(OPENSSL_LIBRARIES ${OPENSSL_LIB}/libssl.so ${OPENSSL_LIB}/libcrypto.so)
  add_definitions(-isystem ${OpenSSL_INCLUDE_DIRS})
else()
  find_package(OpenSSL REQUIRED)
  message(STATUS "using OpenSSL version " ${OPENSSL_VERSION})
  add_definitions(-isystem /usr/include)
endif()

set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(SECUTIL_LIB_SRC
  ${SRC_DIR}/certstatus/certstatus.c
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
  ${SRC_DIR}/credentials/credentials.c
  ${SRC_DIR}/credentials/key.c
  ${SRC_DIR}/credentials/store.c
  ${SRC_DIR}/credentials/trusted.c
  ${SRC_DIR}/credentials/verify.c
  ${SRC_DIR}/credentials/cert.c
  ${SRC_DIR}/crypto/crypto.c
  ${SRC_DIR}/storage/files.c
  ${SRC_DIR}/storage/files_dv.c
  ${SRC_DIR}/storage/files_icv.c
  ${SRC_DIR}/storage/uta_api.c
  ${SRC_DIR}/util/extensions.c
  ${SRC_DIR}/util/log.c
  ${SRC_DIR}/util/util.c
)

add_library(secutils SHARED
  ${SECUTIL_LIB_SRC}
)


set(INC_DIR ${PROJECT_SOURCE_DIR}/include/secutils)
set(INC_PUBLIC_HDRS
  ${INC_DIR}/credentials/store.h
  ${INC_DIR}/credentials/cert.h
  ${INC_DIR}/credentials/credentials.h
  ${INC_DIR}/credentials/trusted.h
  ${INC_DIR}/credentials/verify.h
  ${INC_DIR}/credentials/key.h
  ${INC_DIR}/config/config.h
  ${INC_DIR}/config/opt.h
  ${INC_DIR}/config/config_update.h
  ${INC_DIR}/certstatus/ocsp.h
  ${INC_DIR}/certstatus/crl_mgmt.h
  ${INC_DIR}/certstatus/crls.h
  ${INC_DIR}/certstatus/cdp_util.h
  ${INC_DIR}/certstatus/certstatus.h
  ${INC_DIR}/storage/files_icv.h
  ${INC_DIR}/storage/uta_api.h
  ${INC_DIR}/storage/files_dv.h
  ${INC_DIR}/storage/files.h
  ${INC_DIR}/crypto/crypto.h
  ${INC_DIR}/connections/tls.h
  ${INC_DIR}/connections/conn.h
  ${INC_DIR}/connections/http.h
  ${INC_DIR}/util/util.h
  ${INC_DIR}/util/extensions.h
  ${INC_DIR}/util/log.h
  ${INC_DIR}/operators.h
  ${INC_DIR}/basic.h
)

include_directories(${INC_DIR}/.. ${INC_DIR})

if((CMAKE_BUILD_TYPE MATCHES Release) OR (DEFINED ENV{NDEBUG}))
  message(STATUS "build mode: Release")
  add_definitions(-DNDEBUG=1 -O2)
else()
  message(STATUS "build mode: Debug")
  add_definitions(-g -O0)
  set(DEBUG_FLAGS -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all)
  add_definitions(${DEBUG_FLAGS})
  link_libraries(${DEBUG_FLAGS})
endif()

add_definitions(
  -Wall -Woverflow -Wextra -Wswitch -Wmissing-prototypes -Wstrict-prototypes
  -Wformat -Wtype-limits -Wundef -Wconversion -Wno-shadow -Wno-conversion
  -Wno-sign-conversion -Wno-unused-parameter -Wno-sign-compare -Wpointer-arith
  -Wformat -Wformat-security -Wno-declaration-after-statement -Wno-vla
  # TODO enable -Wconversion -Wsign-conversion -Wsign-compare -Wunused-parameter
  )
add_definitions(-pedantic -DPEDANTIC -Werror)

if(DEFINED ENV{SECUTILS_USE_UTA})
  add_definitions(-DSECUTILS_USE_UTA=1)
endif()

if(DEFINED ENV{SECUTILS_USE_ICV})
  add_definitions(-DSECUTILS_USE_ICV=1)
endif()

if(DEFINED ENV{SECUTILS_NO_TLS})
  add_definitions(-DSECUTILS_NO_TLS=1)
endif()

target_link_libraries(secutils ${OPENSSL_LIBRARIES})

# set_property(TARGET secutils PROPERTY C_STANDARD 90)

set_target_properties(secutils PROPERTIES
  VERSION ${SECUTILS_VERSION} SOVERSION ${SECUTILS_VERSION_MAJOR}
  PUBLIC_HEADER "${INC_PUBLIC_HDRS}"
)

if(NOT TARGET build)
  add_custom_target(build COMMAND make all)
endif()

if(DEFINED ENV{ROOTFS})
  set(CMAKE_INSTALL_PREFIX $ENV{ROOTFS} CACHE PATH "comment" FORCE)
endif()

install(TARGETS secutils
  LIBRARY
    DESTINATION lib
    COMPONENT Library
  PUBLIC_HEADER
    DESTINATION include/secutils
    COMPONENT Development
)

if(NOT TARGET uninstall)
  add_custom_target(uninstall COMMAND xargs rm -vf <install_manifest.txt)
endif()
