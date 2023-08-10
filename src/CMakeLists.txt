add_library(secutils_compilation_options INTERFACE)
target_compile_options(secutils_compilation_options INTERFACE
    -Wall -Woverflow -Wextra -Wswitch -Wmissing-prototypes
    -Wstrict-prototypes -Wformat -Wtype-limits -Wundef -Wconversion
    -Wno-shadow -Wno-conversion -Wno-sign-conversion -Wno-sign-compare -Wno-unused-parameter
    -Wformat-security -Wno-declaration-after-statement -Wno-vla
    # TODO clean up code and enable -Wshadow -Wsign-conversion -Wsign-compare -Wunused-parameter
    # -Wpointer-arith -pedantic -DPEDANTIC
    # -Werror
)

add_library(security-utlities_sanitizer_options INTERFACE)
set(SANITIZER_FLAGS -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all)
target_compile_options(security-utlities_sanitizer_options INTERFACE ${SANITIZER_FLAGS})
target_link_options(security-utlities_sanitizer_options INTERFACE ${SANITIZER_FLAGS})

if(SECURITY_UTILITIES_USE_UTA)
    add_library(security-utlities_uta-api INTERFACE)
    target_include_directories(security-utlities_uta-api INTERFACE /usr/local/include)
    target_link_directories(security-utlities_uta-api INTERFACE /usr/local/lib)
    target_link_libraries(security-utlities_uta-api INTERFACE -luta)
endif()

add_subdirectory(libsecutils)

if(SECURITY_UTILITIES_USE_ICV OR DEFINED ENV{SECUTILS_USE_ICV})
    add_subdirectory(util)
endif()
