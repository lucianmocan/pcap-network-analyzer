# Minimum CMake version
cmake_minimum_required(VERSION 3.12)

# Add the executable for the CLI module
add_executable(pcapna
    cli.c
    cli.h
    cli_helper.c
    cli_helper.h
    cli_parser.c
    cli_parser.h
)

# Link the CLI executable to the API library
target_link_libraries(pcapna PUBLIC interface ethernet ipv4 ipv6 icmp icmpv6 tcp udp dhcp_bootp dns arp)


# Link dependencies (e.g., core and api modules)
# target_link_libraries(pcap_cli PRIVATE core_module api_module)