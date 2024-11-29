#include "dscp.h"
#include <assert.h>
#include <string.h>

void
test_dcsp_desc()
{
    char dscp_desc[32];
    get_dscp_desc(CS0, dscp_desc, true);
    assert(strcmp(dscp_desc, "CS0: Best Effort / Standard") == 0);

    get_dscp_desc(CS1, dscp_desc, false);
    assert(strcmp(dscp_desc, "CS1") == 0);
    return;
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
    return 0;
}