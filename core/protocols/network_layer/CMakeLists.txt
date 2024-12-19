add_subdirectory(common)

add_library(ipv4
    ipv4/ipv4.c
    ipv4/ipv4.h
)

add_library(ipv6
    ipv6/ipv6.c
    ipv6/ipv6.h
)

add_library(arp
    arp/arp.c
    arp/arp.h
)

add_library(icmp
    icmp/icmp.c
    icmp/icmp.h
)

add_library(icmpv6
    icmpv6/icmpv6.c
    icmpv6/icmpv6.h
)

add_executable(test_ipv4
    ipv4/test_ipv4.c
)

target_link_libraries(test_ipv4 ipv4 dscp)
add_test(NAME test_ipv4 COMMAND test_ipv4)
set_tests_properties(test_ipv4 PROPERTIES DEPENDS test_dscp)
set_tests_properties(test_ipv4 PROPERTIES DEPENDS test_check_sum)

add_executable(test_ipv6
    ipv6/test_ipv6.c
)

target_link_libraries(test_ipv6 ipv6)
add_test(NAME test_ipv6 COMMAND test_ipv6)
set_tests_properties(test_ipv6 PROPERTIES DEPENDS test_dscp)

add_executable(test_arp
    arp/test_arp.c
)

target_link_libraries(test_arp arp)
add_test(NAME test_arp COMMAND test_arp)
set_tests_properties(test_arp PROPERTIES DEPENDS test_mac_address)
set_tests_properties(test_arp PROPERTIES DEPENDS test_ethernet)

add_executable(test_icmp
    icmp/test_icmp.c
)

target_link_libraries(test_icmp icmp)
add_test(NAME test_icmp COMMAND test_icmp)
set_tests_properties(test_icmp PROPERTIES DEPENDS test_ipv4)


add_executable(test_icmpv6
    icmpv6/test_icmpv6.c
)

target_link_libraries(test_icmpv6 icmpv6)
add_test(NAME test_icmpv6 COMMAND test_icmpv6)


target_link_libraries(ipv4 PUBLIC mac_address dscp check_sum)
target_include_directories(ipv4 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ipv4)

target_link_libraries(ipv6 PUBLIC dscp ipv4)
target_include_directories(ipv6 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ipv6)

target_link_libraries(arp PUBLIC mac_address ethernet)
target_include_directories(arp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/arp)

target_link_libraries(icmp PUBLIC check_sum ipv4)
target_include_directories(icmp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/icmp)

target_link_libraries(icmpv6 PUBLIC ipv6 check_sum)
target_include_directories(icmpv6 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/icmpv6)