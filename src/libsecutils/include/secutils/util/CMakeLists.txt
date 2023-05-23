target_sources(siemens_libsecutils PRIVATE
    extensions.h
    log.h
    util.h
)

target_include_directories(siemens_libsecutils PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
)
