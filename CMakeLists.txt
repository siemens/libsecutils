cmake_minimum_required(VERSION 3.13)

project(
  siemens_secutils
  VERSION 2.0.0 # always 3 components for correct versioning
  LANGUAGES C)

find_package(OpenSSL MODULE REQUIRED COMPONENTS SSL)

option(SIEMENS_LIBSECUTILS_USE_UTA "Use UTA API" OFF)
option(SIEMENS_LIBSECUTILS_USE_ICV "Use configuration ICV" OFF)
option(SIEMENS_LIBSECUTILS_NO_TLS "Do not use TLS" OFF)

add_subdirectory(src)
