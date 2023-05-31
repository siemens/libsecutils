cmake_minimum_required(VERSION 3.13)

project(
  siemens_secutils
  VERSION 2.0.0 # always 3 components for correct versioning
  LANGUAGES C)

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

find_package(OpenSSL MODULE REQUIRED COMPONENTS SSL)

option(SIEMENS_LIBSECUTILS_USE_UTA "Use UTA API" OFF)
option(SIEMENS_LIBSECUTILS_USE_ICV "Use configuration ICV" OFF)
option(SIEMENS_LIBSECUTILS_NO_TLS "Do not use TLS" OFF)

add_subdirectory(src)
