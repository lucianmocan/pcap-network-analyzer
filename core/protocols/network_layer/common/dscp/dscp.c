#include "dscp.h"

/**
 * @brief Get the ECN description
 * 
 * @param ecn 
 * @param ecn_desc 
 * @param verbose // if true, full description, if false, short description
 */
void 
get_ecn_desc(uint8_t ecn, char *ecn_desc, bool verbose)
{
    if (!IS_VALID_ECN(ecn)){
        snprintf(ecn_desc, ECN_DESC_SIZE, "Invalid ECN value");
        return;
    }
    switch(ecn){
        case IPTOS_ECN_NOTECT:
            if (verbose)
                snprintf(ecn_desc, ECN_DESC_SIZE, "Not-ECT: Not ECN-Capable Transport");
            else
                snprintf(ecn_desc, ECN_DESC_SIZE, "Not-ECT");
            break;
        case IPTOS_ECN_ECT0:
            if (verbose)
                snprintf(ecn_desc, ECN_DESC_SIZE, "ECT(0): ECN-Capable Transport (0)");
            else
                snprintf(ecn_desc, ECN_DESC_SIZE, "ECT(0)");
            break;
        case IPTOS_ECN_ECT1:
            if (verbose)
                snprintf(ecn_desc, ECN_DESC_SIZE, "ECT(1): ECN-Capable Transport (1)");
            else
                snprintf(ecn_desc, ECN_DESC_SIZE, "ECT(1)");
            break;
        case IPTOS_ECN_CE:
            if (verbose)
                snprintf(ecn_desc, ECN_DESC_SIZE, "CE: Congestion Experienced");
            else
                snprintf(ecn_desc, ECN_DESC_SIZE, "CE");
            break;
    }
}


/**
 * @brief Get the DSCP description
 * 
 * @param dscp 
 * @param verbose // if true, full description, if false, short description
 * @return char* 
 */
void
get_dscp_desc(uint8_t dscp, char *dscp_desc, bool verbose)
{
    if (!IS_VALID_DSCP(dscp)){
        snprintf(dscp_desc, DSCP_DESC_SIZE, "Invalid DSCP value");
        return;
    }
    switch(dscp){
        /*
        DSCP Class Selector - informations based on:
        https://datatracker.ietf.org/doc/html/rfc4594 [Page 19]
        */
        case CS0:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS0: Best Effort / Standard");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS0");
            break;
        case CS1:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS1: Low-Priority Data");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS1");
            break;
        case CS2:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS2: Network operations, administration, and management (OAM)");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS2");
            break;
        case CS3:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS3: Broadcast Video");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS3");
        case CS4:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS4: Real-Time Interactive");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS4");
            break;
        case CS5:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS5: Signaling");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS5");
            break;
        case CS6:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS6: Network Control");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS6");
            break;
        case CS7:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS7: Reserved for future use");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "CS7");
            break;
        /*
        DSCP Assured Forwarding - informations based on:
        https://datatracker.ietf.org/doc/html/rfc2597 [Page 6]
        */
        case AF11:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF11: Class 1, Low Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF11");
            break;
        case AF12:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF12: Class 1, Medium Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF12");
            break;
        case AF13:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF13: Class 1, High Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF13");
            break;
        case AF21:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF21: Class 2, Low Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF21");
        case AF22:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF22: Class 2, Medium Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF22");
            break;
        case AF23:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF23: Class 2, High Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF23");
        case AF31:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF31: Class 3, Low Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF31");
            break;
        case AF32:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF32: Class 3, Medium Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF32");
            break;
        case AF33:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF33: Class 3, High Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF33");
            break;
        case AF41:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF41: Class 4, Low Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF41");
        case AF42:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF42: Class 4, Medium Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF42");
            break;
        case AF43:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF43: Class 4, High Drop Probability");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "AF43");
            break;
        /*
        DSCP Expedited Forwarding
        */
        case EF:
            if (verbose)
                snprintf(dscp_desc, DSCP_DESC_SIZE, "EF: Expedited Forwarding");
            else
                snprintf(dscp_desc, DSCP_DESC_SIZE, "EF");
            break;
        /*
        DSCP Voice Admit
        */
        case VOICE_ADMIT:
            snprintf(dscp_desc, DSCP_DESC_SIZE, "Voice Admit");
            break;
        /*
        DSCP Low Effort
        */
        case LE:
            snprintf(dscp_desc, DSCP_DESC_SIZE, "Low Effort");
            break;
    }
}
