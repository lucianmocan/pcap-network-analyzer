#include "cli_helper.h"
#include "cli.h"


int 
main(int argc, char** argv)
{
    char interface[CMD_ARG_SIZE] = {0};
    char filename[CMD_ARG_SIZE] = {0};
    char filter[CMD_ARG_SIZE] = {0};
    int verbosity = 0;

    if (argc == 1){
        display_welcome_message();
        return 0;
    }
    // get the arguments
    get_arguments(argc, argv, interface, filename, filter, &verbosity);

    // prepare for departure
    check_all(interface, filename, filter, verbosity);

    return 0;
}