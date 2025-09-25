add_library(tcp
    tcp/tcp.cc
    tcp/tcp.h
)

add_library(udp
    udp/udp.cc
    udp/udp.h
)

add_executable(test_udp
    udp/test_udp.cc
)

target_link_libraries(test_udp udp)
add_test(NAME test_udp COMMAND test_udp)

add_executable(test_tcp
    tcp/test_tcp.cc
)

target_link_libraries(test_tcp tcp)
add_test(NAME test_tcp COMMAND test_tcp)

target_link_libraries(udp PUBLIC ipv4 ipv6 check_sum)
target_include_directories(udp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/udp)

target_link_libraries(tcp PUBLIC ipv4 ipv6 check_sum)
target_include_directories(tcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tcp)