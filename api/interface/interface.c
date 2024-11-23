#include "interface.h"
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Get the interfaces addresses object
 * 
 * @param addr 
 * @return char** 
 */
dev_interface_t
get_interface_infos(pcap_if_t* dev)
{
    dev_interface_t dev_interface = (dev_interface_t)malloc(sizeof(struct dev_interface));
    if (dev_interface == NULL){
        fprintf(stderr, "Failed to allocate memory for dev_interface\n");
        exit(EXIT_FAILURE);
    }
    // store the interface name
    dev_interface->name = dev->name;

    char tmp[50] = "<";
    if (dev->flags & PCAP_IF_UP) 
        strncat(tmp, "UP", sizeof(tmp) - strlen(tmp) - 1);
    else 
        strncat(tmp, "DOWN", sizeof(tmp) - strlen(tmp) - 1);
    if (dev->flags & PCAP_IF_LOOPBACK) 
        strncat(tmp, ",LOOPBACK", sizeof(tmp) - strlen(tmp) - 1);
    if (dev->flags & PCAP_IF_RUNNING)  
        strncat(tmp, ",RUNNNING", sizeof(tmp) - strlen(tmp) - 1);
    if (dev->flags & PCAP_IF_WIRELESS) 
        strncat(tmp, ",WIRELESS", sizeof(tmp) - strlen(tmp) - 1);

    strncat(tmp, "> ", sizeof(tmp) - strlen(tmp) - 1);  
    switch (dev->flags & PCAP_IF_CONNECTION_STATUS){
        case PCAP_IF_CONNECTION_STATUS_CONNECTED:
            strncat(tmp, "status UP", sizeof(tmp) - strlen(tmp) - 1);
            break;
        case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
            strncat(tmp, "status DOWN", sizeof(tmp) - strlen(tmp) - 1);
            break;
        case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
            strncat(tmp, "status UNKNOWN",sizeof(tmp) - strlen(tmp) - 1);
            break;
        default:
            strncat(tmp, "\n", sizeof(tmp) - strlen(tmp) - 1);
    }
    strncpy(dev_interface->flags, tmp, sizeof(dev_interface->flags) - 1);
    dev_interface->flags[sizeof(dev_interface->flags) - 1] = '\0';

    // print the interface description
    if (dev->description != NULL){
        dev_interface->description = dev->description;
    }

    // set pointer to NULL
    dev_interface->addresses = NULL;
    
    // print the interface addresses
    if (dev->addresses != NULL) {
        for (pcap_addr_t *addr = dev->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr->sa_family == AF_INET) {
                char* ip4 = (char *)malloc(INET_ADDRSTRLEN + sizeof("IPv4: "));
                if (ip4 == NULL){
                    fprintf(stderr, "Failed to allocate memory for ip4\n");
                    exit(EXIT_FAILURE);
                }

                snprintf(ip4, INET_ADDRSTRLEN + sizeof("IPv4: "), "IPv4: ");
                struct sockaddr_in *sin = (struct sockaddr_in *)addr->addr;
                inet_ntop(AF_INET, &(sin->sin_addr), ip4 + sizeof("IPv4: ") - 1, INET_ADDRSTRLEN);
                dev_interface->addresses = add_node(dev_interface->addresses, ip4);
            } else if (addr->addr->sa_family == AF_INET6) {
                char* ip6 = (char *)malloc(INET6_ADDRSTRLEN + sizeof("IPv6: "));
                if (ip6 == NULL){
                    fprintf(stderr, "Failed to allocate memory for ip6\n");
                    exit(EXIT_FAILURE);
                }

                snprintf(ip6, INET6_ADDRSTRLEN + sizeof("IPv6: "), "IPv6: ");
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr->addr;
                inet_ntop(AF_INET6, &(sin6->sin6_addr), ip6 + sizeof("IPv6: ") - 1, INET6_ADDRSTRLEN);
                dev_interface->addresses = add_node(dev_interface->addresses, ip6);
            } 
            // the interface MAC address
            #ifdef __APPLE__
            else if (addr->addr->sa_family == AF_LINK){
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)addr->addr;
                char *mac = (char *)malloc(18+ sizeof("MAC: "));
                if (mac == NULL){
                    fprintf(stderr, "Failed to allocate memory for mac\n");
                    exit(EXIT_FAILURE);
                }
                if (sdl->sdl_alen == 0){
                    free(mac);
                    continue;
                }
                snprintf(mac, 18 + sizeof("MAC: "), "MAC: %s", link_ntoa(sdl));
                dev_interface->addresses = add_node(dev_interface->addresses, mac);
            }
            #endif
            #ifdef __linux__
            else if (addr->addr->sa_family == AF_PACKET){
                struct sockaddr_ll *sll = (struct sockaddr_ll *)addr->addr;
                char *mac = (char *)malloc(18);
                if (mac == NULL){
                    fprintf(stderr, "Failed to allocate memory for mac\n");
                    exit(EXIT_FAILURE);
                }
                for (int i = 0; i < 6; i++){
                    snprintf(mac, 18, "%02x", sll->sll_addr[i]);
                    if (i != 5)
                        strncat(mac, ":", 18);
                }
                dev_interface->addresses = add_node(dev_interface->addresses, mac);
            }
            #endif
        }
    }
    return dev_interface;
}


void
free_interface_infos(dev_interface_t dev)
{
    free_list(dev->addresses);
    free(dev);
}