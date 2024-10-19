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

set(OPENSSL_COMPONENTS REQUIRED COMPONENTS Crypto SSL) # TODO SSL should not be needed if SECUTILS_NO_TLS
# improved from https://cmake.org/cmake/help/v3.6/module/FindOpenSSL.html
if(NOT DEFINED OPENSSL_ROOT_DIR AND NOT "$ENV{OPENSSL_DIR}" STREQUAL "")
  get_filename_component(OPENSSL_ROOT_DIR "$ENV{OPENSSL_DIR}" ABSOLUTE)
  set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
endif()
if(NOT DEFINED OPENSSL_FOUND) # not already done by superordinate module
  if(DEFINED OPENSSL_ROOT_DIR)
    find_package(OpenSSL HINTS "${OPENSSL_ROOT_DIR}" NO_DEFAULT_PATH ${OPENSSL_COMPONENTS})
  else()
    find_package(OpenSSL ${OPENSSL_COMPONENTS})
  endif()
  STRING(REGEX REPLACE "/?/libcrypto\..*" "" OPENSSL_LIB "${OPENSSL_CRYPTO_LIBRARY}")
endif()
message(STATUS "using OpenSSL version ${OPENSSL_VERSION}")
message(STATUS "using OpenSSL inc dir ${OPENSSL_INCLUDE_DIR}")
STRING(REGEX REPLACE ";.*" "" OPENSSL_INCLUDE_DIR "${OPENSSL_INCLUDE_DIR}")
if(NOT EXISTS "${OPENSSL_INCLUDE_DIR}/openssl")
  message(FATAL_ERROR "OpenSSL include directory does not exist: ${OPENSSL_INCLUDE_DIR}/openssl")
endif()
if(NOT DEFINED OPENSSL_LIB_SET AND NOT "$ENV{OPENSSL_LIB}" STREQUAL "")
  set(OPENSSL_LIB_SET 1)
  get_filename_component(OPENSSL_LIB "$ENV{OPENSSL_LIB}" ABSOLUTE)
  if(NOT EXISTS "${OPENSSL_LIB}")
    message(FATAL_ERROR "directory OPENSSL_LIB does not exist: ${OPENSSL_LIB}")
  endif()
  if(TARGET OpenSSL::Crypto)
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_LIB}/libcrypto${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIBRARY})
  endif()
  if(TARGET OpenSSL::SSL)
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_LIB}/libssl${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set_target_properties(OpenSSL::SSL PROPERTIES IMPORTED_LOCATION ${OPENSSL_SSL_LIBRARY})
  endif()
  # set(OPENSSL_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
endif()
message(STATUS "using OpenSSL lib dir ${OPENSSL_LIB}")
message(STATUS "using OpenSSL library ${OPENSSL_CRYPTO_LIBRARY}, ${OPENSSL_SSL_LIBRARY}")
if(NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
  message(FATAL_ERROR "OpenSSL crypto library file does not exist: ${OPENSSL_CRYPTO_LIBRARY}")
endif()

option(SECURITY_UTILITIES_USE_UTA "Use UTA API" OFF)
option(SECURITY_UTILITIES_USE_ICV "Use configuration ICV" OFF)
option(SECURITY_UTILITIES_NO_TLS "Do not use TLS" OFF)

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

#if(UNIX AND NOT APPLE)
#  set(CMAKE_INSTALL_PREFIX "/usr")
#else()
#  set(CMAKE_INSTALL_PREFIX "tmp")
#endif()
#set(CMAKE_INSTALL_DOCDIR "${CMAKE_INSTALL_PREFIX}/share/doc")
include(GNUInstallDirs) # any CMAKE_INSTALL_PREFIX must be set before

# https://stackoverflow.com/questions/73248130/how-to-avoid-the-removal-of-the-rpath-during-cmake-install-step
if (APPLE)
  set(rbase "@loader_path")
else ()
  set(rbase "$ORIGIN")
endif ()
file(RELATIVE_PATH lib_dir
     "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}"
     "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
# Honor user overrides, whether at the command line or FetchContent
set(CMAKE_INSTALL_RPATH "${rbase};${rbase}/${lib_dir}" CACHE STRING "Install RPATH")

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
endif()
if(Doxygen_FOUND)
  add_dependencies(doc security-utilities_doxygen)
endif()

if(NOT TARGET uninstall)
  add_custom_target(uninstall COMMAND xargs -I{} rm -vf $ENV{DESTDIR}{} <install_manifest.txt)
endif()

if(NOT TARGET build)
  add_custom_target(build COMMAND make all)
endif()


# =============================
# Cleaning
# =============================

# https://stackoverflow.com/questions/9680420/looking-for-a-cmake-clean-command-to-clear-up-cmake-output/78133906#78133906

set_property(
  DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  APPEND
  PROPERTY ADDITIONAL_CLEAN_FILES
      # only works for predefined names as globbing would be done on cmake run
      src/libsecutils/include/secutils/secutils_static_config.h
      doc CMakeDoxyfile.in Doxyfile.security-utilities_doxygen
      install_manifest.txt _CPack_Packages
      )

if(NOT TARGET clean_all)
  add_custom_target(clean_all
    COMMAND ${CMAKE_BUILD_TOOL} clean
    COMMAND find . -name "*.o" -o -regex "./libsecutils-.*" | xargs rm
    # after the following, cannot call this target again:
    COMMAND find . ( -name "*.cmake" -o -name Makefile )
            -not -path ./src/libsecutils/security-utilities_libraryConfig.cmake
            -not -path ./src/util/security-utilities_icvutilConfig.cmake
            -not -path ./coverage/Makefile
            | xargs rm
    COMMAND find . -name CMakeFiles | xargs rm -r
    COMMAND rm CMakeCache.txt
    VERBATIM
  )
endif()

# =============================
# Packaging
# =============================

# generate Debian etc. packages using CPack, relying on installation defined above

if(DEFINED CPACK_PACKAGE_NAME)
  return()
endif()

SET(CPACK_PACKAGE_NAME libsecutils)
SET(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/siemens/libsecutils")
SET(CPACK_PACKAGE_ICON "${CMAKE_CURRENT_SOURCE_DIR}/libsecutils.svg")
SET(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt")
SET(CPACK_PACKAGE_VENDOR "Siemens")
set(CPACK_PACKAGE_CONTACT "David von Oheimb <David.von.Oheimb@siemens.com>")

set(CPACK_STRIP_FILES ON)

set(CPACK_COMPONENTS_ALL
  security-utilities_library_Runtime
  security-utilities_library_Development
)
if (SECURITY_UTILITIES_USE_ICV)
  list(APPEND CPACK_COMPONENTS_ALL security-utilities_icvutil_Runtime)
endif()

set(CPACK_COMPONENT_SECURITY-UTILITIES_LIBRARY_RUNTIME_DESCRIPTION "OpenSSL enhancement wrapper library
OpenSSL wrapper library simplifying use of commonly needed functionality
With extended support for certficate status checking using CRLs and/or OCSP")

set(CPACK_COMPONENT_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_DESCRIPTION "libsecutils C headers and documentation
Development support for libsecutils")

set(CPACK_COMPONENT_SECURITY-UTILITIES_ICVUTIL_RUNTIME_DESCRIPTION "libsecutils helper binaries
Stand-alone helper CLI applications using libsecutils")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(CPACK_GENERATOR "DEB")
  set(EXT "deb")

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

  # help CPackDeb please dpkg-shlibdeps
  if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.20.0")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS "../lib/${CMAKE_INSTALL_FULL_LIBDIR}")
  else()
    set(CMAKE_INSTALL_RPATH # must be done before add_executable()
        "../lib/${CMAKE_INSTALL_FULL_LIBDIR}")
  endif()

  set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
  set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  get_target_property(BINARY_DIR_LIBRARY security-utilities_library BINARY_DIR)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS "${CMAKE_CURRENT_BINARY_DIR}" "${BINARY_DIR_LIBRARY}")
  set(CPACK_DEB_COMPONENT_INSTALL ON)

  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_FILE_NAME DEB-DEFAULT)
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_PACKAGE_SECTION "libs")
  # see also https://gitlab.kitware.com/cmake/cmake/-/issues/21834
  # CPack Deb does not create postinst when installing to /usr/lib/x86_64-linux-gnu
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/debian/extra/triggers")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)

  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_NAME "${CPACK_PACKAGE_NAME}-dev")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_FILE_NAME DEB-DEFAULT)
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_ARCHITECTURE "all")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_SECTION "devel")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_DEPENDS "libsecutils (>= ${security-utilities_VERSION})")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_SUGGESTS "libssl-dev, libuta-dev")

  set(CPACK_DEBIAN_SECURITY-UTILITIES_ICVUTIL_RUNTIME_PACKAGE_NAME "${CPACK_PACKAGE_NAME}-bin")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_ICVUTIL_RUNTIME_FILE_NAME DEB-DEFAULT)
  set(CPACK_DEBIAN_SECURITY-UTILITIES_ICVUTIL_RUNTIME_PACKAGE_SECTION "utils")
else(Linux)
  #if(APPLE)
  #  set(CPACK_GENERATOR "Bundle")
  #  set(EXT "bundle")
  #  set(CPACK_BUNDLE_NAME "${CPACK_PACKAGE_NAME}")
  #else()
    set(CPACK_GENERATOR "ZIP")
    set(EXT "zip")
  #endif(APPLE)
endif(CMAKE_SYSTEM_NAME MATCHES "Linux")

set(CPACK_SOURCE_GENERATOR "TGZ")
#set(CPACK_SET_DESTDIR TRUE) # prevents package creation error when using cpack
set(CPACK_VERBATIM_VARIABLES YES)

set(CPACK_SOURCE_IGNORE_FILES
  ${CPACK_IGNORE_FILES}
  ~$
  \\.diff$
  \./\.git/
  \\.git$
  \\.deb$
  \\.gz$
  \\.zip$
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
  /icvutil$
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
    "${CMAKE_CURRENT_SOURCE_DIR}/libsecutils.svg"
    DESTINATION "${CMAKE_INSTALL_DOCDIR}/${COMPONENT_DOC_DIRECTORY}"
    COMPONENT ${component}
  )
  if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    install(FILES
      "${CMAKE_CURRENT_SOURCE_DIR}/debian/copyright"
      "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
      DESTINATION "${CMAKE_INSTALL_DOCDIR}/${COMPONENT_DOC_DIRECTORY}"
      COMPONENT ${component}
    )
  endif()
endforeach()

if(NOT TARGET ${EXT})
  set (pack_full_name
       "${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-dev_${CPACK_PACKAGE_VERSION}_all.${EXT}")
  add_custom_command(
    OUTPUT "${pack_full_name}"
    DEPENDS build
    COMMENT "Building packages possibly including doxygen run"
    COMMAND cpack --config CPackConfig.cmake # -D CPACK_PACKAGING_INSTALL_PREFIX=
    COMMAND cpack --config CPackSourceConfig.cmake
    )
  add_custom_target(${EXT} DEPENDS ${pack_full_name})
endif()
