include(CheckFunctionExists)

# Check for strlcpy and strlcat
check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(strlcat HAVE_STRLCAT)

# Add these definitions globally
if (NOT HAVE_STRLCPY)
    add_definitions(-DNEED_STRLCPY)
endif()

if (NOT HAVE_STRLCAT)
    add_definitions(-DNEED_STRLCAT)
endif()

# Add a library only if we need to define the functions
if (NOT HAVE_STRLCPY OR NOT HAVE_STRLCAT)
    add_library(bsd_string
        bsd_string/bsd_string.h
        bsd_string/strlcpy.c
        bsd_string/strlcat.c
    )
    target_include_directories(bsd_string PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/bsd_string)
endif()

# Add the linked list library
add_library(linked_list
    linked_list/linked_list.c
    linked_list/linked_list.h
)

# Include the directory containing the header files
target_include_directories(linked_list PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/linked_list)

# Create the test executable for linked list
add_executable(test_linked_list
    linked_list/test_linked_list.c
)

# Link the test executable with the linked list library
target_link_libraries(test_linked_list linked_list)

# Add the test executable to the list of tests
add_test(NAME test_linked_list COMMAND test_linked_list)

