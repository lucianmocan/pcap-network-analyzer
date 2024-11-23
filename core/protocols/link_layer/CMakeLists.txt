add_library(ethernet
    ethernet/ethernet.c
    ethernet/ethernet.h
)

add_executable(test_ethernet
    ethernet/test_ethernet.c
)

target_link_libraries(test_ethernet ethernet)
add_test(NAME test_ethernet COMMAND test_ethernet)

target_link_libraries(ethernet PUBLIC mac_address)
target_include_directories(ethernet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ethernet)