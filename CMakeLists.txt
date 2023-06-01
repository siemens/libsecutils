cmake_minimum_required(VERSION 3.18)

project(libsecutils)
set (LIBSECUTILS_NAME secutils)

if(NOT DEFINED LIBSECUTILS_VERSION)
  set(LIBSECUTILS_VERSION_MAJOR 2)
  set(LIBSECUTILS_VERSION_MINOR 0)
  set(LIBSECUTILS_VERSION ${LIBSECUTILS_VERSION_MAJOR}.${LIBSECUTILS_VERSION_MINOR})
endif()

message(STATUS "SecurityUtilities version " ${LIBSECUTILS_VERSION})

# set(CMAKE_VERBOSE_MAKEFILE on)

set(CMAKE_INSTALL_PREFIX "/usr") # must be set before include(GNUInstallDirs)
include(GNUInstallDirs)

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
set(LIBSECUTILS_LIB_SRC
  "${PROJECT_SOURCE_DIR}/.github/workflows/build.yml"
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
  ${LIBSECUTILS_LIB_SRC}
)

set(INC_DIR "${PROJECT_SOURCE_DIR}/include/${LIBSECUTILS_NAME}")
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
  ${INC_DIR}/secutils_static_config.h
)

include_directories(${INC_DIR}/.. ${INC_DIR})

if(CMAKE_BUILD_TYPE MATCHES Release OR DEFINED ENV{NDEBUG})
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
  set(SECUTILS_USE_UTA 1)
endif()

if(DEFINED ENV{SECUTILS_USE_ICV})
  set(SECUTILS_USE_ICV 1)
endif()

if(DEFINED ENV{SECUTILS_NO_TLS})
  set(SECUTILS_NO_TLS 1)
endif()

# help CPackDeb please dpkg-shlibdeps
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.20.0")
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS
    "../lib/${CMAKE_INSTALL_FULL_LIBDIR}")
else()
  set(CMAKE_INSTALL_RPATH # must be done before add_executable()
    "../lib/${CMAKE_INSTALL_FULL_LIBDIR}")
endif()

if(DEFINED ENV{SECUTILS_USE_ICV})
  add_executable(icvutil
    util/icvutil.c
    )
  target_link_libraries(icvutil
    ${LIBSECUTILS_NAME}
    ${OPENSSL_LIBRARIES}
    )
endif()

configure_file(${INC_DIR}/secutils_static_config.h.in
               ${INC_DIR}/secutils_static_config.h)

# set_property(TARGET ${LIBSECUTILS_NAME} PROPERTY C_STANDARD 90)

set_target_properties(${LIBSECUTILS_NAME} PROPERTIES
  VERSION ${LIBSECUTILS_VERSION} SOVERSION ${LIBSECUTILS_VERSION_MAJOR}
  # not used as directory structure would not be preserved on installation:
  # PUBLIC_HEADER "${INC_PUBLIC_HDRS}"
)

if(NOT TARGET build)
  add_custom_target(build COMMAND make all)
endif()


# installation and uninstall

if(DEFINED ENV{ROOTFS})
  set(CMAKE_INSTALL_PREFIX $ENV{ROOTFS} CACHE PATH "comment" FORCE)
endif()

# see also https://gitlab.kitware.com/cmake/cmake/-/issues/24929 and
# https://stackoverflow.com/questions/46490448/how-i-can-add-a-changelog-in-deb-with-cmake
add_custom_command(
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog"
    COMMAND gzip -cn9 "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog"
    > "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
)
if(NOT TARGET changelog)
  add_custom_target(changelog ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz")
endif()

install(TARGETS ${LIBSECUTILS_NAME}
  LIBRARY
  DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}"
  COMPONENT lib
  )

find_program(DOXYGEN doxygen)
if(NOT TARGET doc AND DOXYGEN)
  add_custom_command(
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/secutils/basic.h"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMAND doxygen Doxyfile # required packages: doxygen graphviz
    OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/doc/html" # BINARY_DIR woud be better
    )
  add_custom_target(doc ALL DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/doc/html")
endif()

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/doc/html/."
  OPTIONAL # as doxygen may not be available
  DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}-dev/html"
  COMPONENT dev
  )

install(DIRECTORY include/.
  DESTINATION "${CMAKE_INSTALL_FULL_INCLUDEDIR}"
  COMPONENT dev
  )

if(DEFINED ENV{SECUTILS_USE_ICV})
  install(TARGETS icvutil
    RUNTIME
    DESTINATION "${CMAKE_INSTALL_FULL_BINDIR}"
    COMPONENT bin
    )
endif()

if(NOT TARGET uninstall)
  add_custom_target(uninstall COMMAND xargs -I{} rm -vf $ENV{DESTDIR}{} <install_manifest.txt)
endif()


if(NOT DEFINED CPACK_PACKAGE_NAME)
# generate Debian packages using CPack, relying on installation defined above

SET(CPACK_PACKAGE_NAME ${PROJECT_NAME})
SET(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/siemens/libsecutils")
SET(CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}/libsecutils.svg")
SET(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE.txt")
SET(CPACK_PACKAGE_VENDOR "Siemens")
set(CPACK_PACKAGE_CONTACT "David von Oheimb <David.von.Oheimb@siemens.com>")
set(CPACK_PACKAGE_VERSION       ${LIBSECUTILS_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${LIBSECUTILS_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${LIBSECUTILS_VERSION_MINOR})
set(CPACK_STRIP_FILES ON)

set(CPACK_COMPONENT_LIB_DESCRIPTION "OpenSSL enhancement wrapper library
OpenSSL wrapper library simplifying use of commonly needed functionality
With extended support for certficate status checking using CRLs and/or OCSP")
set(CPACK_COMPONENT_DEV_DESCRIPTION "libsecutils C headers and documentation
Development support for libsecutils")
set(CPACK_COMPONENT_BIN_DESCRIPTION "libsecutils helper binaries
Stand-alone helper CLI applications using libsecutils")

set(CPACK_GENERATOR "DEB")
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_LIB_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_DEBIAN_DEV_PACKAGE_ARCHITECTURE "all")
set(CPACK_DEBIAN_LIB_PACKAGE_SECTION "libs")
set(CPACK_DEBIAN_DEV_PACKAGE_SECTION "devel")
set(CPACK_DEBIAN_BIN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS "${CMAKE_CURRENT_BINARY_DIR}")
set(CPACK_DEBIAN_DEV_PACKAGE_DEPENDS "libsecutils (>= ${CPACK_PACKAGE_VERSION})")
set(CPACK_DEBIAN_DEV_PACKAGE_SUGGESTS "libssl-dev, libuta-dev")
# see also https://gitlab.kitware.com/cmake/cmake/-/issues/21834
# CPack Deb does not create postinst when installing to /usr/lib/x86_64-linux-gnu
set(CPACK_DEBIAN_LIB_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/debian/extra/triggers")
set(CPACK_DEBIAN_LIB_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)

set(CPACK_SOURCE_GENERATOR "TGZ")
#set(CPACK_SET_DESTDIR TRUE) # prevents package creation error when using cpack
set(CPACK_VERBATIM_VARIABLES YES)
set(CPACK_SOURCE_IGNORE_FILES
  ${CPACK_IGNORE_FILES}
  ~$
  \./\.git/
  \\.git$
  \\.deb$
  \\.gz$
  \\.o$
  \\.so
  \./attic/
  \./tmp/
  CMakeFiles/
  _CPack_Packages/
  \\.cmake$
  /CMakeCache.txt$
  /compile_commands.json$
  /install_manifest.*\.txt$
  /changelog.gz$
  \./debian/tmp/
  \\.substvars$
  \\.log$
  /debian/\\.debhelper/
  /debian/files$
  /debian/debhelper-build-stamp$
  \./debian/${PROJECT_NAME}/
  \./debian/${PROJECT_NAME}-dev/
  \./debian/${PROJECT_NAME}-bin/
  \./doc/
  \./icvutil$
  )

include(CPack)

# see also https://gitlab.kitware.com/cmake/cmake/-/issues/21832
# CPack Deb lacks a way to configure copyright files by component
foreach(component IN LISTS CPACK_COMPONENTS_ALL)
  if(${component} STREQUAL "lib")
    set(suffix "")
  else()
    set(suffix "-${component}")
  endif()
  install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/debian/copyright"
    "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
    "${CMAKE_SOURCE_DIR}/libsecutils.svg"
    DESTINATION "${CMAKE_INSTALL_FULL_DOCDIR}${suffix}"
    COMPONENT ${component}
    )
endforeach()

if(NOT TARGET deb)
  set (deb_pack_full_name
    "${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-dev_${CPACK_PACKAGE_VERSION}_all.deb")
  add_custom_command(
    OUTPUT "${deb_pack_full_name}"
    DEPENDS build
    COMMENT "Building packages possibly including doxygen run"
    COMMAND cpack # --config CPackConfig.cmake
    COMMAND cpack --config CPackSourceConfig.cmake
    )
  add_custom_target(deb DEPENDS ${deb_pack_full_name})
endif()

endif(NOT DEFINED CPACK_PACKAGE_NAME)
