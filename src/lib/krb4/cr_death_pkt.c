/*
 * cr_death_pkt.c
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "krb.h"
#include "prot.h"
#include <string.h>

/*
 * This routine creates a packet to type AUTH_MSG_DIE which is sent to
 * the Kerberos server to make it shut down.  It is used only in the
 * development environment.
 *
 * It takes a string "a_name" which is sent in the packet.  A pointer
 * to the packet is returned.
 *
 * The format of the killer packet is:
 *
 * type			variable		data
 *			or constant
 * ----			-----------		----
 *
 * unsigned char	KRB_PROT_VERSION	protocol version number
 * 
 * unsigned char	AUTH_MSG_DIE		message type
 * 
 * [least significant	HOST_BYTE_ORDER		byte order of sender
 *  bit of above field]
 * 
 * string		a_name			presumably, name of
 * 						principal sending killer
 * 						packet
 */

#ifdef DEBUG
KTEXT
krb_create_death_packet(a_name)
    char *a_name;
{
    static KTEXT_ST pkt_st;
    KTEXT pkt = &pkt_st;

    unsigned char *v =  pkt->dat;
    unsigned char *t =  (pkt->dat+1);
    *v = (unsigned char) KRB_PROT_VERSION;
    *t = (unsigned char) AUTH_MSG_DIE;
    *t |= HOST_BYTE_ORDER;
    (void) strncpy((char *) (pkt->dat+2),a_name,sizeof(pkt->dat) - 3);
    pkt->dat[sizeof(pkt->dat) - 1] = '\0';
    pkt->length = 3 + strlen(pkt->dat+2);
    return pkt;
}
#endif /* DEBUG */
