#ifndef MAC_ADDRESS_H
#define MAC_ADDRESS_H

#include <sys/types.h>
#include <string>
#include <sstream>
#include <iomanip>

std::string write_mac_address(const u_char *mac_address);

#endif