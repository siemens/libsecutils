SET(CPACK_PACKAGE_NAME ${PROJECT_NAME})
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

if(APPLE)
  set(CPACK_GENERATOR "Bundle")
  set(CPACK_BUNDLE_NAME "${PROJECT_NAME}")
else()
  set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
  set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  get_target_property(BINARY_DIR_LIBRARY security-utilities_library BINARY_DIR)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS "${CMAKE_CURRENT_BINARY_DIR}" "${BINARY_DIR_LIBRARY}")
  set(CPACK_DEB_COMPONENT_INSTALL ON)

  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_PACKAGE_NAME "${PROJECT_NAME}")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_FILE_NAME DEB-DEFAULT)
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_PACKAGE_SECTION "libs")
  # see also https://gitlab.kitware.com/cmake/cmake/-/issues/21834
  # CPack Deb does not create postinst when installing to /usr/lib/x86_64-linux-gnu
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/debian/extra/triggers")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_RUNTIME_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)

  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_NAME "${PROJECT_NAME}-dev")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_FILE_NAME DEB-DEFAULT)
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_ARCHITECTURE "all")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_SECTION "devel")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_DEPENDS "libsecutils (>= ${CPACK_PACKAGE_VERSION})")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_LIBRARY_DEVELOPMENT_PACKAGE_SUGGESTS "libssl-dev, libuta-dev")

  set(CPACK_DEBIAN_SECURITY-UTILITIES_ICVUTIL_RUNTIME_PACKAGE_NAME "${PROJECT_NAME}-utils")
  set(CPACK_DEBIAN_SECURITY-UTILITIES_ICVUTIL_RUNTIME_FILE_NAME DEB-DEFAULT)
  set(CPACK_DEBIAN_SECURITY-UTILITIES_ICVUTIL_RUNTIME_PACKAGE_SECTION "utils")
endif() # Apple

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
  \\.dylib$
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