add_library(dhcp_bootp
    dhcp_bootp/dhcp_bootp.c
    dhcp_bootp/dhcp_bootp.h
    dhcp_bootp/lib_bootp.h
)

add_library(dns
    dns/dns.cc
    dns/dns.h
)

add_executable(test_dhcp_bootp
    dhcp_bootp/test_dhcp_bootp.c
)

target_link_libraries(test_dhcp_bootp dhcp_bootp arp ethernet mac_address linked_list)
add_test(NAME test_dhcp_bootp COMMAND test_dhcp_bootp)

add_executable(test_dns
    dns/test_dns.cc
)

target_link_libraries(test_dns dns)
add_test(NAME test_dns COMMAND test_dns)


target_link_libraries(dhcp_bootp PUBLIC arp ethernet mac_address linked_list)
target_include_directories(dhcp_bootp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/dhcp_bootp)

target_link_libraries(dns PUBLIC linked_list)
target_include_directories(dns PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/dns)