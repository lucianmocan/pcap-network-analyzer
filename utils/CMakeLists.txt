# Add the linked list library
add_library(linked_list
    linked_list/linked_list.c
    linked_list/linked_list.h
)

add_library(mac_address
    mac_address/mac_address.c
    mac_address/mac_address.h
)

add_library(check_sum
    check_sum/check_sum.c
    check_sum/check_sum.h
)

# Include the directory containing the header files
target_include_directories(linked_list PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/linked_list)
target_include_directories(mac_address PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mac_address)
target_include_directories(check_sum PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/check_sum)

# Create the test executable for linked list
add_executable(test_linked_list
    linked_list/test_linked_list.c
)
add_executable(test_mac_address
    mac_address/test_mac_address.c
)

add_executable(test_check_sum
    check_sum/test_check_sum.c
)

# Link the test executable with the linked list library
target_link_libraries(test_linked_list linked_list)
target_link_libraries(test_mac_address mac_address)
target_link_libraries(test_check_sum check_sum)

# Add the test executable to the list of tests
add_test(NAME test_linked_list COMMAND test_linked_list)
add_test(NAME test_mac_address COMMAND test_mac_address)
add_test(NAME test_check_sum COMMAND test_check_sum)

