cmake_minimum_required(VERSION 3.13)

project(
  siemens_secutils
  VERSION 2.0.0 # always 3 components for correct versioning
  LANGUAGES C)

message(STATUS "SecurityUtilities version " ${siemens_secutils_VERSION})

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

add_library(secutils_compilation_options INTERFACE)
target_compile_options(secutils_compilation_options INTERFACE
  -Woverflow -Wswitch -Wmissing-prototypes -Wstrict-prototypes
  -Wtype-limits -Wundef -Wconversion -Wno-shadow -Wno-conversion
  -Wno-sign-conversion -Wno-unused-parameter -Wno-sign-compare # TODO enable -Wsign-conversion -Wsign-compare -Wunused-parameter
  -Wformat -Wformat-security -Wno-declaration-after-statement -Wno-vla # -Wpointer-arith
  -pedantic -Werror
)

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
