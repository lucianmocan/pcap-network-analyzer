#include "dscp.h"
#include <cassert>
#include <string>

void
test_dcsp_desc()
{
    std::string dscp_desc;
    get_dscp_desc(CS0, dscp_desc, true);
    assert(dscp_desc == "CS0: Best Effort / Standard");

    get_dscp_desc(CS1, dscp_desc, false);
    assert(dscp_desc == "CS1");

    get_dscp_desc(-1, dscp_desc, true);
    assert(dscp_desc == "Invalid DSCP value");

    get_dscp_desc(AF42, dscp_desc, true);
    assert(dscp_desc == "AF42: Class 4, Medium Drop Probability");
}

void
test_ecn_desc()
{
    std::string ecn_desc;
    
    #ifdef __linux__
    get_ecn_desc(IPTOS_ECN_NOT_ECT, ecn_desc, true);
    #endif

    #ifdef __APPLE__
    get_ecn_desc(IPTOS_ECN_NOTECT, ecn_desc, true);
    #endif

    assert(ecn_desc == "Not-ECT: Not ECN-Capable Transport");
}

void
test_is_valid_dscp()
{
    assert(IS_VALID_DSCP(0) == true);
    assert(IS_VALID_DSCP(63) == true);
    assert(IS_VALID_DSCP(64) == false);
    assert(IS_VALID_DSCP(-1) == false);
}

int main() {
    test_is_valid_dscp();
    test_dcsp_desc();
    test_ecn_desc();
    return 0;
}