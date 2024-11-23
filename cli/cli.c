#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli_helper.h"


int 
main(int argc, char** argv)
{
    if (argc == 1){
        display_welcome_message();
        return 0;
    }
    if (argc == 2){
        if (strcmp(argv[1], "--help") == 0){
            display_help();
            return 0;
        }
        if (strcmp(argv[1], "--version") == 0){
            printf("pcapna CLI 0.0.1\n");
            return 0;
        }
        if (strcmp(argv[1], "--list-interfaces") == 0){
            printf("Listing interfaces...\n");
            display_interfaces();
            return 0;
        }
    }
    // get_program_options(argc, argv);
    // getopt 

    return 0;
}