#include "dscp.h"
#include <assert.h>
#include <string.h>

void
test_dcsp_desc()
{
    char dscp_desc[DSCP_DESC_SIZE];
    get_dscp_desc(CS0, dscp_desc, true);
    assert(strcmp(dscp_desc, "CS0: Best Effort / Standard") == 0);

    get_dscp_desc(CS1, dscp_desc, false);
    assert(strcmp(dscp_desc, "CS1") == 0);

    get_dscp_desc(-1, dscp_desc, true);
    assert(strcmp(dscp_desc, "Invalid DSCP value") == 0);

    get_dscp_desc(AF42, dscp_desc, true);
    assert(strcmp(dscp_desc, "AF42: Class 4, Medium Drop Probability") == 0);
}

void
test_ecn_desc()
{
    char ecn_desc[ECN_DESC_SIZE];

    #ifdef __linux__
    get_ecn_desc(IPTOS_ECN_NOT_ECT, ecn_desc, true);
    #endif

    #ifdef __APPLE__
    get_ecn_desc(IPTOS_ECN_NOTECT, ecn_desc, true);
    #endif
    
    assert(strcmp(ecn_desc, "Not-ECT: Not ECN-Capable Transport") == 0);
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