/*
 * lib/krb4/cr_death_pkt.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2000 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

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
    unsigned char *p;
    size_t namelen;

    p = pkt->dat;
    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_DIE;
    namelen = strlen(a_name) + 1;
    if (1 + 1 + namelen > sizeof(pkt->dat))
	return NULL;
    memcpy(p, a_name, namelen);
    p += namelen;
    pkt->length = p - pkt->dat;
    return pkt;
}
#endif /* DEBUG */
