#include "cli_helper.h"
#include "api.h"
#include "interface.h"

#include <pcap.h>
#include <arpa/inet.h>

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
    pcap_if_t *alldevsp;
    if ((alldevsp = get_interfaces()) == NULL){
        fprintf(stderr, "Can't find any devices\n");
        return;
    };

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

    free_interfaces(alldevsp);
}