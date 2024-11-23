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
        strlcat(tmp, "UP", sizeof(tmp));
    else 
        strlcat(tmp, "DOWN", sizeof(tmp));
    if (dev->flags & PCAP_IF_LOOPBACK) 
        strlcat(tmp, ",LOOPBACK", sizeof(tmp));
    if (dev->flags & PCAP_IF_RUNNING)  
        strlcat(tmp, ",RUNNNING", sizeof(tmp));
    if (dev->flags & PCAP_IF_WIRELESS) 
        strlcat(tmp, ",WIRELESS", sizeof(tmp));

    strlcat(tmp, "> ", sizeof(tmp));  
    switch (dev->flags & PCAP_IF_CONNECTION_STATUS){
        case PCAP_IF_CONNECTION_STATUS_CONNECTED:
            strlcat(tmp, "status UP", sizeof(tmp));
            break;
        case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
            strlcat(tmp, "status DOWN", sizeof(tmp));
            break;
        case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
            strlcat(tmp, "status UNKNOWN", sizeof(tmp));
            break;
        default:
            strlcat(tmp, "\n", sizeof(tmp));
    }
    strlcpy(dev_interface->flags, tmp, sizeof(dev_interface->flags));

    // print the interface description
    if (dev->description != NULL){
        dev_interface->description = dev->description;
    }

    // print the interface addresses
    if (dev->addresses != NULL) {
        for (pcap_addr_t *addr = dev->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr->sa_family == AF_INET) {
                char* ip4 = (char *)malloc(INET_ADDRSTRLEN + sizeof("IPv4: "));
                if (ip4 == NULL){
                    fprintf(stderr, "Failed to allocate memory for ip4\n");
                    exit(EXIT_FAILURE);
                }

                strlcat(ip4, "IPv4: ", INET_ADDRSTRLEN + sizeof("IPv4: "));
                struct sockaddr_in *sin = (struct sockaddr_in *)addr->addr;
                inet_ntop(AF_INET, &(sin->sin_addr), ip4 + sizeof("IPv4: ") - 1, INET_ADDRSTRLEN);
                dev_interface->addresses = add_node(dev_interface->addresses, ip4);
            } else if (addr->addr->sa_family == AF_INET6) {
                char* ip6 = (char *)malloc(INET6_ADDRSTRLEN + sizeof("IPv6: "));
                if (ip6 == NULL){
                    fprintf(stderr, "Failed to allocate memory for ip6\n");
                    exit(EXIT_FAILURE);
                }

                strlcat(ip6, "IPv6: ", INET6_ADDRSTRLEN + sizeof("IPv6: "));
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
                strlcat(mac, "MAC: ", 18 + sizeof("MAC: "));
                strlcat(mac, link_ntoa(sdl), 18 + sizeof("MAC: "));
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
                        strlcat(mac, ":", 18);
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
    free(dev->name);
    free(dev->description);
    free_list(dev->addresses);
    free(dev);
}