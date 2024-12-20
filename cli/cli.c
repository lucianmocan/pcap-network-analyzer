#include "cli.h"

pcap_t *capture;

int 
main(int argc, char** argv)
{
    char interface[CMD_ARG_SIZE] = {0};
    char filename[CMD_ARG_SIZE] = {0};
    char filter[CMD_ARG_SIZE] = {0};
    int verbosity = 1;

    if (argc == 1){
        display_welcome_message();
        return 0;
    }
    // get the arguments
    get_arguments(argc, argv, interface, filename, filter, &verbosity);

    // prepare for departure
    check_all(interface, filename, filter, verbosity);

    // start the capture
    if (strcmp(interface, "") != 0){
        start_capture(interface, filter, verbosity, true);
    } else {
        start_capture(filename, filter, verbosity, false);
    }

    return 0;
}

void 
signal_handler(int sig)
{
    if (capture != NULL){
        pcap_breakloop(capture);
    }
}

void
packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    handler_args_t *handler_args = (handler_args_t*)args;
    int verbosity = handler_args->verbosity;
    parse_cli(header, (uint8_t*)packet, verbosity);
}

void
start_capture(char* source, char* filter, int verbosity, bool is_live)
{   
    char errbuf[PCAP_ERRBUF_SIZE];
    handler_args_t handler_args = {verbosity};

    if (is_live) {
        // get the interface
        pcap_if_t *alldevsp;
        alldevsp = get_interfaces();
        pcap_if_t *dev = get_interface(source, alldevsp);
        if (dev == NULL){
            fprintf(stderr, "Interface '%s' not found.\n", source);
            exit(EXIT_FAILURE);
        }
        // prepare the capture
        capture = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
        free_interfaces(alldevsp);
    } else {
        capture = pcap_open_offline(source, errbuf);
    }

    if (capture == NULL){
        fprintf(stderr, "Can't capture: %s.\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // compile the filter if exists
    set_filter_if_exists(capture, filter);

    // set up ^C, to cleanup before exiting
    signal(SIGINT, signal_handler);

    // start the capture
    pcap_loop(capture, 0, packet_handler, (uint8_t*)&handler_args);

    printf("\nCapture stopped.\n");
    printf("Cleaning up...\n");
    // land the plane
    pcap_close(capture);
    cleanup();
    printf("-----------------------------------\n");
    printf("DONE.\n");
    return;
}

/**
 * @brief Set the filter if it exists / was set by the user
 * 
 * @param capture 
 * @param filter 
 */
void 
set_filter_if_exists(pcap_t *capture, char* filter)
{   
    struct bpf_program fp;
    // if no filter
    if (strcmp(filter, "") != 0) {
        if (pcap_compile(capture, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Can't parse filter '%s': %s\n", filter, pcap_geterr(capture));
            printf("-----------------------------------\n");
            pcap_close(capture);
            exit(EXIT_FAILURE);
        }

        if (pcap_setfilter(capture, &fp) == -1) {
            fprintf(stderr, "Can't install filter '%s': %s\n", filter, pcap_geterr(capture));
            printf("-----------------------------------\n");
            pcap_freecode(&fp);
            pcap_close(capture);
            EXIT_FAILURE;
        }
        // free the filter, no longer needed if we set stuff
        pcap_freecode(&fp);
    } else {
        printf("No filter applied, capturing all packets.\n");
        printf("-----------------------------------\n");
    }
}

void
cleanup()
{
    return;
}