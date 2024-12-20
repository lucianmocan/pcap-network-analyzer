#include "cli_helper.h"

void 
display_welcome_message()
{
    printf("Welcome to pcapna CLI 0.0.1!\n");
    printf("Live long and prosper!\n");
    printf("Run 'pcapna --help' to get started.\n");
}

void 
display_help()
{
    printf("usage: ./pcapna [options]\n");
    printf("Options and arguments:\n");
    printf("  -i <interface> : choose the interface to capture\n");
    printf("  -f <filter>    : BPF filter (optional)\n");
    printf("  -o <file>      : input file for offline capture\n");
    printf("  -v <1..3>      : verbose level (1=concise ; 2=summary ; 3=full)\n");
    printf("  --help: display this help message\n");
    printf("  --list-interfaces: list all available interfaces\n");
    printf("  --version: display the version of pcapna CLI\n");
}

void 
display_interfaces()
{
    // Get all interfaces using the API (pcap)
    pcap_if_t *alldevsp;
    if ((alldevsp = get_interfaces()) == NULL){
        fprintf(stderr, "Can't find any devices\n");
        return;
    };

    // Display all interfaces + infos
    pcap_if_t *alldevsp_head = alldevsp;
    for (; alldevsp != NULL; alldevsp = alldevsp->next){
            printf("-----------------------------------\n");
            dev_interface_t dev = get_interface_infos(alldevsp);
            printf("%s: %s\n", dev->name, dev->description ? dev->description : "");
            printf("\t%s\n", dev->flags);
            node_t *addresses = dev->addresses;
            for (; addresses != NULL; addresses = addresses->next){
                printf("\t%s\n", (char*)addresses->data);
            }
            free_interface_infos(dev);
    }

    free_interfaces(alldevsp_head);
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
                strcpy(interface, optarg);
                break;
            case 'o':
                strcpy(filename, optarg);
                break;
            case 'f':
                strcpy(filter, optarg);
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

/**
 * @brief Checks to see if the given interface exists
 * 
 * @param interface 
 * @return int 
 */
int 
check_interface(char* interface)
{   
    printf("Checking interface... '%s'.\n", interface);
    pcap_if_t *alldevsp;
    if ((alldevsp = get_interfaces()) == NULL){
        fprintf(stderr, "Can't find any interfaces.\n");
        return -1;
    };

    pcap_if_t *alldevsp_head = alldevsp;
    for (; alldevsp != NULL; alldevsp = alldevsp->next){
        if (strcmp(alldevsp->name, interface) == 0){
            free_interfaces(alldevsp_head);
            fprintf(stdout, "Interface '%s' ok.\n", interface);
            return 0;
        }
    }

    free_interfaces(alldevsp_head);
    return -1;
}

/**
 * @brief Checks to see if the given file exists
 * 
 * @param filename 
 * @return int 
 */
int
check_file(char* filename)
{
    printf("Checking file... '%s'\n", filename);
    int fd = open(filename, O_RDONLY);
    if (fd == -1){
        fprintf(stderr, "Can't open file '%s'.\n", filename);
        return -1;
    }
    fprintf(stdout, "File '%s' ok.\n", filename);
    close(fd);
    return 0;
}

/**
 * @brief Check if given filter expression is valid
 * 
 * @param filter 
 * @return int 
 */
int
check_filter(char* filter)
{
    printf("Checking filter... '%s'.\n", filter);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535); // for a fake pcap handle
    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1){
        fprintf(stderr, "Can't compile filter '%s': %s\n", filter, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    fprintf(stdout, "Filter '%s' ok.\n", filter);
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

/**
 * @brief Check that we're good to go!
 * 
 * @param interface 
 * @param filename 
 * @param filter 
 * @param verbosity 
 */
void
check_all(char* interface, char* filename, char* filter, int verbosity)
{
    printf("-----------------------------------\n");

    if ((strcmp(interface, "") != 0) && (strcmp(filename, "") != 0)){
        fprintf(stderr, "Can't choose an interface and a file at the same time.\n");
        fprintf(stderr, "-----------------------------------\n");
        exit(EXIT_FAILURE);
    }

    if (strcmp(interface, "") != 0){
        printf("Chosen interface: '%s'.\n", interface);
        if (check_interface(interface) == -1){
            fprintf(stderr, "Interface '%s' not found.\n", interface);
            printf("-----------------------------------\n");
            exit(EXIT_FAILURE);
        }
        printf("-----------------------------------\n");
    }

    if (strcmp(filename, "") != 0){
        printf("Chosen file: '%s'.\n", filename);
        if (check_file(filename) == -1){
            fprintf(stderr, "File '%s' not found.\n", filename);
            printf("-----------------------------------\n");
            exit(EXIT_FAILURE);
        }
        printf("-----------------------------------\n");
    }

    if (strcmp(filter, "") != 0){
        printf("Chosen filter: '%s'.\n", filter);
        if (check_filter(filter) == -1){
            fprintf(stderr, "Invalid filter: '%s'.\n", filter);
            printf("-----------------------------------\n");
            exit(EXIT_FAILURE);
        }
        printf("-----------------------------------\n");
    }

    if (verbosity < 1 || verbosity > 3){
        fprintf(stderr, "Invalid verbosity level: %d.\n", verbosity);
        printf("-----------------------------------\n");
        exit(EXIT_FAILURE);
    }

    printf("Verbosity level: %d.\n", verbosity);
    printf("-----------------------------------\n");
}