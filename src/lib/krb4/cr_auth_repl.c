/*
 * lib/krb4/cr_auth_repl.c
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
 * This routine is called by the Kerberos authentication server
 * to create a reply to an authentication request.  The routine
 * takes the user's name, instance, and realm, the client's
 * timestamp, the number of tickets, the user's key version
 * number and the ciphertext containing the tickets themselves.
 * It constructs a packet and returns a pointer to it.
 *
 * Notes: The packet returned by this routine is static.  Thus, if you
 * intend to keep the result beyond the next call to this routine, you
 * must copy it elsewhere.
 *
 * The packet is built in the following format:
 * 
 * 			variable
 * type			or constant	   data
 * ----			-----------	   ----
 * 
 * unsigned char	KRB_PROT_VERSION   protocol version number
 * 
 * unsigned char	AUTH_MSG_KDC_REPLY protocol message type
 * 
 * [least significant	HOST_BYTE_ORDER	   sender's (server's) byte
 *  bit of above field]			   order
 * 
 * string		pname		   principal's name
 * 
 * string		pinst		   principal's instance
 * 
 * string		prealm		   principal's realm
 * 
 * unsigned long	time_ws		   client's timestamp
 * 
 * unsigned char	n		   number of tickets
 * 
 * unsigned long	x_date		   expiration date
 * 
 * unsigned char	kvno		   master key version
 * 
 * short		w_1		   cipher length
 * 
 * ---			cipher->dat	   cipher data
 */

KTEXT
create_auth_reply(pname, pinst, prealm, time_ws, n, x_date, kvno, cipher)
    char *pname;                /* Principal's name */
    char *pinst;                /* Principal's instance */
    char *prealm;               /* Principal's authentication domain */
    long time_ws;               /* Workstation time */
    int n;                      /* Number of tickets */
    unsigned long x_date;	/* Principal's expiration date */
    int kvno;                   /* Principal's key version number */
    KTEXT cipher;               /* Cipher text with tickets and
				 * session keys */
{
    static KTEXT_ST pkt_st;
    KTEXT pkt = &pkt_st;
    unsigned char *p;
    size_t pnamelen, pinstlen, prealmlen;

    /* Create fixed part of packet */
    p = pkt->dat;
    /* This is really crusty. */
    if (n != 0)
	*p++ = 3;
    else
	*p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_KDC_REPLY;	/* always big-endian */

    /* Make sure the response will actually fit into its buffer. */
    pnamelen = strlen(pname) + 1;
    pinstlen = strlen(pinst) + 1;
    prealmlen = strlen(prealm) + 1;
    if (sizeof(pkt->dat) < (1 + 1 + pnamelen + pinstlen + prealmlen
			    + 4 + 1 + 4 + 1 + 2 + cipher->length)
	|| cipher->length > 65535 || cipher->length < 0) {
	pkt->length = 0;
        return NULL;
    }
    /* Add the basic info */
    memcpy(p, pname, pnamelen);
    p += pnamelen;
    memcpy(p, pinst, pinstlen);
    p += pinstlen;
    memcpy(p, prealm, prealmlen);
    p += prealmlen;

    /* Workstation timestamp */
    KRB4_PUT32BE(p, time_ws);

    *p++ = n;

    /* Expiration date */
    KRB4_PUT32BE(p, x_date);

    /* Now send the ciphertext and info to help decode it */
    *p++ = kvno;
    KRB4_PUT16BE(p, cipher->length);
    memcpy(p, cipher->dat, (size_t)cipher->length);
    p += cipher->length;

    /* And return the packet */
    pkt->length = p - pkt->dat;
    return pkt;
}
