#include <assert.h>
#include <pcap.h>
#include "interface.h"

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
    // should use valgrind, but not available on macOS
}

pcap_if_t mock_dev = {
    .next = NULL,
    .name = "mock_0",
    .description = "mock_0_description",
    .addresses = NULL,
    .flags = PCAP_IF_UP | PCAP_IF_LOOPBACK | PCAP_IF_CONNECTION_STATUS_CONNECTED
};

// Test for get_interface_infos
void test_get_interface_infos()
{
    dev_interface_t dev = get_interface_infos(&mock_dev);
    assert(dev != NULL);
    assert(strcmp(dev->name, "mock_0") == 0);
    assert(strcmp(dev->description, "mock_0_description") == 0);
    assert(strcmp(dev->flags, "<UP,LOOPBACK> status UP") == 0);
    free_interface_infos(dev);
}

// Test for free_interface_infos
void test_free_interface_infos()
{
    dev_interface_t dev = get_interface_infos(&mock_dev);
    assert(dev != NULL);
    free_interface_infos(dev);
    // if it doesn't crash, it's working
    // should use valgrind but not available on macOS
}

int main() {
    test_get_interfaces();
    test_free_interfaces();
    test_get_interface_infos();
    test_free_interface_infos();
    return 0;
}