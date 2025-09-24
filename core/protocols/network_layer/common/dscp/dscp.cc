#include "dscp.h"

/**
 * @brief Get the ECN description
 * 
 * @param ecn 
 * @param ecn_desc 
 * @param verbose // if true, full description, if false, short description
 */
void 
get_ecn_desc(uint8_t ecn, std::string& ecn_desc, bool verbose)
{
    if (!IS_VALID_ECN(ecn)){
        ecn_desc = "Invalid ECN value";
        return;
    }
    switch(ecn){
        #ifdef __APPLE__
        case IPTOS_ECN_NOTECT:
        #endif
        #ifdef __linux__
        case IPTOS_ECN_NOT_ECT:
        #endif
            if (verbose)
                ecn_desc = "Not-ECT: Not ECN-Capable Transport";
            else
                ecn_desc = "Not-ECT";
            break;
        case IPTOS_ECN_ECT0:
            if (verbose)
                ecn_desc = "ECT(0): ECN-Capable Transport (0)";
            else
                ecn_desc = "ECT(0)";
            break;
        case IPTOS_ECN_ECT1:
            if (verbose)
                ecn_desc = "ECT(1): ECN-Capable Transport (1)";
            else
                ecn_desc = "ECT(1)";
            break;
        case IPTOS_ECN_CE:
            if (verbose)
                ecn_desc = "CE: Congestion Experienced";
            else
                ecn_desc = "CE";
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
get_dscp_desc(uint8_t dscp, std::string& dscp_desc, bool verbose)
{
    if (!IS_VALID_DSCP(dscp)){
        dscp_desc = "Invalid DSCP value";
        return;
    }
    switch(dscp){
        /*
        DSCP Class Selector - informations based on:
        https://datatracker.ietf.org/doc/html/rfc4594 [Page 19]
        */
        case CS0:
            if (verbose)
                dscp_desc = "CS0: Best Effort / Standard";
            else
                dscp_desc = "CS0";
            break;
        case CS1:
            if (verbose)
                dscp_desc = "CS1: Low-Priority Data";
            else
                dscp_desc = "CS1";
            break;
        case CS2:
            if (verbose)
                dscp_desc = "CS2: Network OAM";
            else
                dscp_desc = "CS2";
            break;
        case CS3:
            if (verbose)
                dscp_desc = "CS3: Broadcast Video";
            else
                dscp_desc = "CS3";
            break;
        case CS4:
            if (verbose)
                dscp_desc = "CS4: Real-Time Interactive";
            else
                dscp_desc = "CS4";
            break;
        case CS5:
            if (verbose)
                dscp_desc = "CS5: Signaling";
            else
                dscp_desc = "CS5";
            break;
        case CS6:
            if (verbose)
                dscp_desc = "CS6: Network Control";
            else
                dscp_desc = "CS6";
            break;
        case CS7:
            if (verbose)
                dscp_desc = "CS7: Reserved for future use";
            else
                dscp_desc = "CS7";
            break;
        /*
        DSCP Assured Forwarding - informations based on:
        https://datatracker.ietf.org/doc/html/rfc2597 [Page 6]
        */
        case AF11:
            if (verbose)
                dscp_desc = "AF11: Class 1, Low Drop Probability";
            else
                dscp_desc = "AF11";
            break;
        case AF12:
            if (verbose)
                dscp_desc = "AF12: Class 1, Medium Drop Probability";
            else
                dscp_desc = "AF12";
            break;
        case AF13:
            if (verbose)
                dscp_desc = "AF13: Class 1, High Drop Probability";
            else
                dscp_desc = "AF13";
            break;
        case AF21:
            if (verbose)
                dscp_desc = "AF21: Class 2, Low Drop Probability";
            else
                dscp_desc = "AF21";
        case AF22:
            if (verbose)
                dscp_desc = "AF22: Class 2, Medium Drop Probability";
            else
                dscp_desc = "AF22";
            break;
        case AF23:
            if (verbose)
                dscp_desc = "AF23: Class 2, High Drop Probability";
            else
                dscp_desc = "AF23";
        case AF31:
            if (verbose)
                dscp_desc = "AF31: Class 3, Low Drop Probability";
            else
                dscp_desc = "AF31";
            break;
        case AF32:
            if (verbose)
                dscp_desc = "AF32: Class 3, Medium Drop Probability";
            else
                dscp_desc = "AF32";
            break;
        case AF33:
            if (verbose)
                dscp_desc = "AF33: Class 3, High Drop Probability";
            else
                dscp_desc = "AF33";
            break;
        case AF41:
            if (verbose)
                dscp_desc = "AF41: Class 4, Low Drop Probability";
            else
                dscp_desc = "AF41";
        case AF42:
            if (verbose)
                dscp_desc = "AF42: Class 4, Medium Drop Probability";
            else
                dscp_desc = "AF42";
            break;
        case AF43:
            if (verbose)
                dscp_desc = "AF43: Class 4, High Drop Probability";
            else
                dscp_desc = "AF43";
            break;
        /*
        DSCP Expedited Forwarding
        */
        case EF:
            if (verbose)
                dscp_desc = "EF: Expedited Forwarding";
            else
                dscp_desc = "EF";
            break;
        /*
        DSCP Voice Admit
        */
        case VOICE_ADMIT:
            dscp_desc = "Voice Admit";
            break;
        /*
        DSCP Low Effort
        */
        case LE:
            dscp_desc = "Low Effort";
            break;
    }
}
