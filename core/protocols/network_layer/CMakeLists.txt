add_library(ipv4
    ipv4/ipv4.c
    ipv4/ipv4.h
)

add_executable(test_ipv4
    ipv4/test_ipv4.c
)

target_link_libraries(test_ipv4 ipv4)
add_test(NAME test_ipv4 COMMAND test_ipv4)

target_link_libraries(ipv4 PUBLIC mac_address)
target_include_directories(ipv4 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ipv4)