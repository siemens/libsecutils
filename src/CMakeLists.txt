add_library(secutils_compilation_options INTERFACE)
target_compile_options(secutils_compilation_options INTERFACE
    -Woverflow -Wswitch -Wmissing-prototypes -Wstrict-prototypes
    -Wtype-limits -Wundef -Wconversion -Wno-shadow -Wno-conversion
    -Wno-sign-conversion -Wno-unused-parameter -Wno-sign-compare # TODO enable -Wsign-conversion -Wsign-compare -Wunused-parameter
    -Wformat -Wformat-security -Wno-declaration-after-statement -Wno-vla # -Wpointer-arith
    -pedantic -Werror
)

add_subdirectory(libsecutils)

if(SIEMENS_LIBSECUTILS_USE_ICV OR DEFINED ENV{SECUTILS_USE_ICV})
    add_subdirectory(util)
endif()
