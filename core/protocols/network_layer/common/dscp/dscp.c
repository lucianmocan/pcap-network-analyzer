#include "dscp.h"

/**
 * @brief Get the DSCP description
 * 
 * @param dscp_value 
 * @param verbose // if true, full description, if false, short description
 * @return char* 
 */
void
get_dscp_desc(uint8_t dscp, char *dscp_desc, bool verbose)
{
    switch(dscp){
        /*
        DSCP Class Selector - informations based on:
        https://datatracker.ietf.org/doc/html/rfc4594 [Page 19]
        */
        case CS0:
            if (verbose)
                snprintf(dscp_desc, 32, "CS0: Best Effort / Standard");
            else
                snprintf(dscp_desc, 32, "CS0");
            break;
        case CS1:
            if (verbose)
                snprintf(dscp_desc, 32, "CS1: Low-Priority Data");
            else
                snprintf(dscp_desc, 32, "CS1");
            break;
        case CS2:
            if (verbose)
                snprintf(dscp_desc, 32, "CS2: Network operations, administration, and management (OAM)");
            else
                snprintf(dscp_desc, 32, "CS2");
            break;
        case CS3:
            if (verbose)
                snprintf(dscp_desc, 32, "CS3: Broadcast Video");
            else
                snprintf(dscp_desc, 32, "CS3");
        case CS4:
            if (verbose)
                snprintf(dscp_desc, 32, "CS4: Real-Time Interactive");
            else
                snprintf(dscp_desc, 32, "CS4");
            break;
        case CS5:
            if (verbose)
                snprintf(dscp_desc, 32, "CS5: Signaling");
            else
                snprintf(dscp_desc, 32, "CS5");
            break;
        case CS6:
            if (verbose)
                snprintf(dscp_desc, 32, "CS6: Network Control");
            else
                snprintf(dscp_desc, 32, "CS6");
            break;
        case CS7:
            if (verbose)
                snprintf(dscp_desc, 32, "CS7: Reserved for future use");
            else
                snprintf(dscp_desc, 32, "CS7");
            break;
        /*
        DSCP Assured Forwarding - informations based on:
        https://datatracker.ietf.org/doc/html/rfc2597 [Page 6]
        */
        case AF11:
            if (verbose)
                snprintf(dscp_desc, 32, "AF11: Class 1, Low Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF11");
            break;
        case AF12:
            if (verbose)
                snprintf(dscp_desc, 32, "AF12: Class 1, Medium Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF12");
            break;
        case AF13:
            if (verbose)
                snprintf(dscp_desc, 32, "AF13: Class 1, High Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF13");
            break;
        case AF21:
            if (verbose)
                snprintf(dscp_desc, 32, "AF21: Class 2, Low Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF21");
        case AF22:
            if (verbose)
                snprintf(dscp_desc, 32, "AF22: Class 2, Medium Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF22");
            break;
        case AF23:
            if (verbose)
                snprintf(dscp_desc, 32, "AF23: Class 2, High Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF23");
        case AF31:
            if (verbose)
                snprintf(dscp_desc, 32, "AF31: Class 3, Low Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF31");
            break;
        case AF32:
            if (verbose)
                snprintf(dscp_desc, 32, "AF32: Class 3, Medium Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF32");
            break;
        case AF33:
            if (verbose)
                snprintf(dscp_desc, 32, "AF33: Class 3, High Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF33");
            break;
        case AF41:
            if (verbose)
                snprintf(dscp_desc, 32, "AF41: Class 4, Low Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF41");
        case AF42:
            if (verbose)
                snprintf(dscp_desc, 32, "AF42: Class 4, Medium Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF42");
            break;
        case AF43:
            if (verbose)
                snprintf(dscp_desc, 32, "AF43: Class 4, High Drop Probability");
            else
                snprintf(dscp_desc, 32, "AF43");
            break;
        /*
        DSCP Expedited Forwarding
        */
        case EF:
            if (verbose)
                snprintf(dscp_desc, 32, "EF: Expedited Forwarding");
            else
                snprintf(dscp_desc, 32, "EF");
            break;
        /*
        DSCP Voice Admit
        */
        case VOICE_ADMIT:
            snprintf(dscp_desc, 32, "Voice Admit");
            break;
        /*
        DSCP Low Effort
        */
        case LE:
            snprintf(dscp_desc, 32, "Low Effort");
            break;
    }
}
