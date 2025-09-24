add_library(dscp
    dscp/dscp.cc
    dscp/dscp.h
)

add_executable(test_dscp
    dscp/test_dscp.cc
)

target_link_libraries(test_dscp dscp)
add_test(NAME test_dscp COMMAND test_dscp)

target_include_directories(dscp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/dscp)
