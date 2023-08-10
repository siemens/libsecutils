cmake_minimum_required(VERSION 3.13)

project(
  security-utilities
  VERSION 2.0.0 # always 3 components for correct versioning
  LANGUAGES C)

message(STATUS "SecurityUtilities version " ${security-utilities_VERSION})

if(DEFINED ENV{NDEBUG})
  message(STATUS "Setting build type to 'Release' because NDEBUG was set.")
  set(CMAKE_BUILD_TYPE
    Release
    CACHE STRING "Choose the type of build." FORCE)
elseif(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'Debug' as none was specified.")
  set(CMAKE_BUILD_TYPE
    Debug
    CACHE STRING "Choose the type of build." FORCE)
endif()

if(NOT("$ENV{OPENSSL_DIR}" STREQUAL ""))
  message(STATUS "Using OpenSSL from " $ENV{OPENSSL_DIR})
  set(OPENSSL_ROOT_DIR "$ENV{OPENSSL_DIR}")
endif()

find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)

if(NOT("$ENV{OPENSSL_LIB}" STREQUAL ""))
  if(TARGET OpenSSL::SSL)
    set_target_properties(OpenSSL::SSL PROPERTIES
      IMPORTED_LOCATION $ENV{OPENSSL_LIB}/libssl.so
    )
  endif()

  if(TARGET OpenSSL::Crypto)
    set_target_properties(OpenSSL::Crypto PROPERTIES
      IMPORTED_LOCATION $ENV{OPENSSL_LIB}/libcrypto.so
    )
  endif()
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
include(GNUInstallDirs)

install(FILES libsecutils.svg
  DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

install(DIRECTORY doc/html/
  OPTIONAL # TODO add build for doc/
  DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

if(NOT TARGET uninstall)
  add_custom_target(uninstall COMMAND xargs -I{} rm -vf $ENV{DESTDIR}{} <install_manifest.txt)
endif()

if(NOT TARGET build)
  add_custom_target(build COMMAND make all)
endif()
