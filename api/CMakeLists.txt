# Minimum CMake version
cmake_minimum_required(VERSION 3.12)

# Add the library for the API module
add_library(api
    api.c
    api.h
)

add_library(interface
    interface/interface.c
    interface/interface.h
)

# Specify include directories for the API library
# PUBLIC: Makes the include path available to targets that link against `api`.
target_include_directories(api PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(interface PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/interface)

target_link_libraries(api PUBLIC linked_list interface)

target_link_libraries(interface PRIVATE pcap)
target_link_libraries(interface PUBLIC linked_list)

# Create the test executable for the API module
add_executable(test_interface
    interface/test_interface.c
)

target_link_libraries(test_interface interface)

add_test(NAME test_interface COMMAND test_interface)