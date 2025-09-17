cmake_minimum_required(VERSION 3.12)
project(pcap_analyzer LANGUAGES C CXX)

# Enable testing
enable_testing()

# Set C standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 23)

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