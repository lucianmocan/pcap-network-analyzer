
#include "cli_helper.h"
#include "cli.h"


int 
main(int argc, char** argv)
{
    char *interface = NULL;
    char *filename = NULL;
    char *filter = NULL;
    int verbosity = 0;

    if (argc == 1){
        display_welcome_message();
        return 0;
    }

    get_arguments(argc, argv, interface, filename, filter, &verbosity);



    return 0;
}


/**
 * @brief Get the arguments from the command line
 * 
 * @param argc 
 * @param argv 
 * @param interface 
 * @param filename 
 * @param filter 
 * @param verbosity 
 */
void 
get_arguments(int argc, char** argv, char *interface, char *filename, char *filter, int *verbosity){
    int opt;
    int option_index = 0;
    struct option long_options[4] = {
        {"help", no_argument, 0, 0},
        {"version", no_argument, 0, 0},
        {"list-interfaces", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "i:o:f:v:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 0:
                if (strcmp("help", long_options[option_index].name) == 0) {
                    display_help();
                    exit(EXIT_SUCCESS);
                } else if (strcmp("version", long_options[option_index].name) == 0) {
                    printf("pcapna CLI 0.0.1\n");
                    exit(EXIT_SUCCESS);
                } else if (strcmp("list-interfaces", long_options[option_index].name) == 0) {
                    printf("Listing interfaces...\n");
                    display_interfaces();
                    exit(EXIT_SUCCESS);
                }
                break;
            case 'i':
                interface = optarg;
                break;
            case 'o':
                filename = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 'v':
                *verbosity = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [--help] [--version] [--list-interfaces] [-i interface] [-o filename] [-f filter] [-v verbosity]\n", argv[0]);
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}