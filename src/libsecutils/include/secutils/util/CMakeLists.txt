target_sources(security-utilities_library PRIVATE
    extensions.h
    log.h
    util.h
)

target_include_directories(security-utilities_library PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
)
