cmake_minimum_required(VERSION 3.13)

project(
  security-utilities
  VERSION 2.0.0 # always 3 components for correct versioning
  LANGUAGES C)
message(STATUS "SecurityUtilities version ${security-utilities_VERSION}")

# set(CMAKE_VERBOSE_MAKEFILE on)

if(DEFINED ENV{NDEBUG})
  message(STATUS "Setting build type to 'Release' because NDEBUG was set.")
  set(CMAKE_BUILD_TYPE
    Release  # automatically leads to CFLAGS += -DNDEBUG -O3
    CACHE STRING "Choose the type of build." FORCE)
elseif(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'Debug' as none was specified.")
  set(CMAKE_BUILD_TYPE
    Debug  # automatically leads to CFLAGS += -g  # -O0 not added by default
    CACHE STRING "Choose the type of build." FORCE)
endif()
message(STATUS "Build mode: ${CMAKE_BUILD_TYPE}")

# https://cmake.org/cmake/help/v3.6/module/FindOpenSSL.html
if(NOT "$ENV{OPENSSL_DIR}" STREQUAL "")
  set(OPENSSL_ROOT_DIR $ENV{OPENSSL_DIR})
  set(OPENSSL_INCLUDE_DIR "$ENV{OPENSSL_DIR}/include")
  set(OPENSSL_LIB $ENV{OPENSSL_DIR})
endif()
if(DEFINED ENV{OPENSSL_LIB})
  set(OPENSSL_LIB $ENV{OPENSSL_LIB})
endif()
find_package(OpenSSL QUIET REQUIRED COMPONENTS SSL Crypto)
if("$ENV{OPENSSL_DIR}" STREQUAL "" OR NOT DEFINED ENV{OPENSSL_LIB})
  message(STATUS "using OpenSSL package, with version ${OPENSSL_VERSION}")
endif()
message(STATUS "using OpenSSL hdrs from ${OPENSSL_INCLUDE_DIR}")
if(NOT "${OPENSSL_LIB}" STREQUAL "")
  if(TARGET OpenSSL::Crypto)
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_LIB}/libcrypto${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIBRARY})
  endif()
  if(TARGET OpenSSL::SSL)
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_LIB}/libssl${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set_target_properties(OpenSSL::SSL PROPERTIES IMPORTED_LOCATION ${OPENSSL_SSL_LIBRARY})
  endif()
endif()
message(STATUS "using OpenSSL libraries ${OPENSSL_CRYPTO_LIBRARY}, ${OPENSSL_SSL_LIBRARY}")

option(SECURITY_UTILITIES_USE_UTA "Use UTA API" OFF)
option(SECURITY_UTILITIES_USE_ICV "Use configuration ICV" OFF)
option(SECURITY_UTILITIES_NO_TLS "Do not use TLS" OFF)
set(CMAKE_INSTALL_DOCDIR "/usr/share/doc")

if(DEFINED ENV{SECUTILS_USE_UTA})
  set(SECURITY_UTILITIES_USE_UTA ON)
endif()

if(DEFINED ENV{SECUTILS_USE_ICV})
  set(SECURITY_UTILITIES_USE_ICV ON)
endif()

if(DEFINED ENV{SECUTILS_NO_TLS})
  set(SECURITY_UTILITIES_NO_TLS ON)
endif()

add_subdirectory(src)

# =============================
# Installing
# =============================
include(GNUInstallDirs)

find_package(Doxygen QUIET)
if(NOT TARGET security-utilities_doxygen AND Doxygen_FOUND)
  set(DOXYGEN_OUTPUT_DIRECTORY doc)
  doxygen_add_docs(
    security-utilities_doxygen
    ${CMAKE_CURRENT_LIST_DIR}/src
  )
endif()

if(NOT TARGET doc)
  add_custom_target(doc)
  add_dependencies(doc security-utilities_doxygen)
endif()

if(NOT TARGET uninstall)
  add_custom_target(uninstall COMMAND xargs -I{} rm -vf $ENV{DESTDIR}{} <install_manifest.txt)
endif()

if(NOT TARGET build)
  add_custom_target(build COMMAND make all)
endif()

# =============================
# Packaging
# =============================

if(DEFINED CPACK_PACKAGE_NAME)
  return()
endif()

# help CPackDeb please dpkg-shlibdeps
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.20.0")
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS
    "../lib/${CMAKE_INSTALL_FULL_LIBDIR}")
else()
  set(CMAKE_INSTALL_RPATH # must be done before add_executable()
    "../lib/${CMAKE_INSTALL_FULL_LIBDIR}")
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

include(cmake/CPackDebianPackageSettings.cmake)

set(CPACK_SOURCE_IGNORE_FILES
  ${CPACK_IGNORE_FILES}
  ~$
  \\.diff$
  \./\.git/
  \\.git$
  \\.deb$
  \\.gz$
  \\.o$
  \\.so
  \\.dylib$
  \./attic/
  \./tmp/
  CMakeFiles/
  _CPack_Packages/
  \\.cmake$
  /Makefile$
  ./CMakeCache.txt$
  ./CMakeDoxyfile.in$
  ./Doxyfile.doc$
  /compile_commands.json$
  /install_manifest.*\.txt$
  /changelog.gz$
  \\.substvars$
  \\.log$
  \./debian/\\.debhelper/
  \./debian/tmp/
  \./debian/files$
  \./debian/md5sums$
  \./debian/shlibs$
  \./debian/substvars$
  \./debian/triggers$
  \./debian/debhelper-build-stamp$
  \./debian/libsecutils/
  \./debian/libsecutils-dev/
  \./debian/libsecutils-bin/
  \./doc/
  \./icvutil$
  /src/libsecutils/include/secutils/secutils_static_config.h$
)

include(CPack)

# see also https://gitlab.kitware.com/cmake/cmake/-/issues/21832
# CPack Deb lacks a way to configure copyright files by component
foreach(component IN LISTS CPACK_COMPONENTS_ALL)
  if(${component} STREQUAL "security-utilities_library_Runtime")
    set(suffix "")
  elseif(${component} STREQUAL "security-utilities_library_Development")
    set(suffix "-dev")
  elseif(${component} STREQUAL "security-utilities_icvutil_Runtime")
    set(suffix "-bin")
  else()
    set(suffix "")
  endif()

  set(COMPONENT_DOC_DIRECTORY "${PROJECT_NAME}${suffix}")

  if(suffix STREQUAL "-dev")
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doc/html
      OPTIONAL # TODO add build for doc/
      DESTINATION "${CMAKE_INSTALL_DOCDIR}/${COMPONENT_DOC_DIRECTORY}"
      COMPONENT security-utilities_library_Development
    )
  endif()

  install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/debian/copyright"
    "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
    "${CMAKE_CURRENT_SOURCE_DIR}/libsecutils.svg"
    DESTINATION "${CMAKE_INSTALL_DOCDIR}/${COMPONENT_DOC_DIRECTORY}"
    COMPONENT ${component}
    )
endforeach()

if(NOT TARGET deb)
  if(NOT APPLE)
    set (deb_pack_full_name
      "${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-dev_${CPACK_PACKAGE_VERSION}_all.deb")
  endif()
  add_custom_command(
    OUTPUT "${deb_pack_full_name}"
    DEPENDS build
    COMMENT "Building packages possibly including doxygen run"
    COMMAND cpack --config CPackConfig.cmake
                -G DEB
                -D CPACK_PACKAGING_INSTALL_PREFIX=/usr
    COMMAND cpack --config CPackSourceConfig.cmake
    )
  add_custom_target(deb DEPENDS ${deb_pack_full_name})
endif()
