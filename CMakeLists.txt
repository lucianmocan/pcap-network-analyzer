cmake_minimum_required(VERSION 3.12)
project(pcap_analyzer)

# Enable testing
enable_testing()

# Set C standard
set(CMAKE_C_STANDARD 99)

# Add utils
add_subdirectory(utils)

# Add core modules
add_subdirectory(core)

# Add api module
add_subdirectory(api)

# Add cli module
add_subdirectory(cli)

# Add tests
add_subdirectory(tests)