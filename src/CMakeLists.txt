if(UNIX AND NOT APPLE)
  if(DEFINED ENV{DEB_HOST_MULTIARCH})
    set(_deb_multiarch "$ENV{DEB_HOST_MULTIARCH}")
  else()
    execute_process(
      COMMAND dpkg-architecture -qDEB_HOST_MULTIARCH
      OUTPUT_VARIABLE _deb_multiarch
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
  endif()
  if(_deb_multiarch)
    set(CMAKE_INSTALL_LIBDIR "lib/${_deb_multiarch}" CACHE PATH
      "Object code libraries (multiarch)" FORCE)
  endif()
endif()
include(GNUInstallDirs) # needed for CMAKE_INSTALL_LIBDIR; any CMAKE_INSTALL_PREFIX must be set before

add_library(secutils_compilation_options INTERFACE)
target_compile_options(secutils_compilation_options INTERFACE
    -Wall -Woverflow -Wextra -Wswitch -Wmissing-prototypes -Wstrict-prototypes
    -Wformat -Wformat-security -Wtype-limits -Wundef
    -Wsign-compare -Wpointer-arith -Wunused-parameter
    -pedantic
    # -Werror is enabled only for development and CI using Makefile_v1 without NDEBUG

    # TODO clean up code and re-enable warnings instead:
    -Wno-conversion -Wno-sign-conversion -Wno-c99-extensions
    -Wno-shadow -Wno-declaration-after-statement -Wno-vla -Wno-gnu-folding-constant
)
target_compile_definitions(secutils_compilation_options INTERFACE PEDANTIC)

add_library(security-utlities_sanitizer_options INTERFACE)
set(SANITIZER_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all)
target_compile_options(security-utlities_sanitizer_options INTERFACE ${SANITIZER_FLAGS})
target_link_options(security-utlities_sanitizer_options INTERFACE ${SANITIZER_FLAGS})
target_compile_options(security-utlities_sanitizer_options INTERFACE -O0)  # workaround for -O0 not being added by default

if(SECURITY_UTILITIES_USE_UTA)
    add_library(security-utilities_uta-api INTERFACE)
    target_include_directories(security-utilities_uta-api INTERFACE "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}") # usually expands to /usr/local/include
    target_link_directories(   security-utilities_uta-api INTERFACE "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"    ) # usually expands to /usr/local/lib
    target_link_libraries(security-utilities_uta-api INTERFACE -luta)
endif()

configure_file(security-utilities.pc.in ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc @ONLY)
install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    COMPONENT security-utilities_library_Development
)

add_subdirectory(libsecutils)

if(SECURITY_UTILITIES_USE_ICV)
    add_subdirectory(util)
endif()
