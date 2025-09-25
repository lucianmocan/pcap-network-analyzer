#include "mac_address.h"

std::string
write_mac_address(const u_char *mac_address)
{
    std::ostringstream oss;
    for (int i = 0; i < 6; i++){
        if (i != 0)
            oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac_address[i]);
    }
    return oss.str();
}