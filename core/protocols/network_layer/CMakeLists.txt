add_subdirectory(common)

add_library(ipv4
    ipv4/ipv4.c
    ipv4/ipv4.h
)

add_library(ipv6
    ipv6/ipv6.c
    ipv6/ipv6.h
)

add_executable(test_ipv4
    ipv4/test_ipv4.c
)

target_link_libraries(test_ipv4 ipv4 dscp)
add_test(NAME test_ipv4 COMMAND test_ipv4)
set_tests_properties(test_ipv4 PROPERTIES DEPENDS test_dscp)

add_executable(test_ipv6
    ipv6/test_ipv6.c
)

target_link_libraries(test_ipv6 ipv6 dscp)
add_test(NAME test_ipv6 COMMAND test_ipv6)
set_tests_properties(test_ipv6 PROPERTIES DEPENDS test_dscp)

target_link_libraries(ipv4 PUBLIC mac_address dscp)
target_include_directories(ipv4 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ipv4)

target_link_libraries(ipv6 PUBLIC dscp ipv4)
target_include_directories(ipv6 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ipv6)