#include <assert.h>
#include <pcap.h>
#include "api.h"

// Test for get_interfaces
void test_get_interfaces()
{
    pcap_if_t *alldevsp = get_interfaces();
    assert(alldevsp != NULL);
    free_interfaces(alldevsp);
}

// Test for free_interfaces
void test_free_interfaces()
{
    pcap_if_t *alldevsp = get_interfaces();
    assert(alldevsp != NULL);
    free_interfaces(alldevsp);
    // if it doesn't crash, it's working
}

int main() {
    test_get_interfaces();
    test_free_interfaces();
    return 0;
}