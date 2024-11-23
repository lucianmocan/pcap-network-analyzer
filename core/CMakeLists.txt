add_subdirectory(protocols)

add_library(parser
    parser.c
    parser.h
)

add_executable(test_parser
    test_parser.c
)

target_link_libraries(test_parser parser)

target_include_directories(parser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
