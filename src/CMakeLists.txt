add_subdirectory(libsecutils)

if(SIEMENS_LIBSECUTILS_USE_ICV OR DEFINED ENV{SECUTILS_USE_ICV})
    add_subdirectory(util)
endif()
