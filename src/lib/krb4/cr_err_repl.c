/*
 * lib/krb4/cr_err_repl.c
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
 * This routine is used by the Kerberos authentication server to
 * create an error reply packet to send back to its client.
 *
 * It takes a pointer to the packet to be built, the name, instance,
 * and realm of the principal, the client's timestamp, an error code
 * and an error string as arguments.  Its return value is undefined.
 *
 * The packet is built in the following format:
 * 
 * type			variable	   data
 *			or constant
 * ----			-----------	   ----
 *
 * unsigned char	req_ack_vno	   protocol version number
 * 
 * unsigned char	AUTH_MSG_ERR_REPLY protocol message type
 * 
 * [least significant	HOST_BYTE_ORDER	   sender's (server's) byte
 * bit of above field]			   order
 * 
 * string		pname		   principal's name
 * 
 * string		pinst		   principal's instance
 * 
 * string		prealm		   principal's realm
 * 
 * unsigned long	time_ws		   client's timestamp
 * 
 * unsigned long	e		   error code
 * 
 * string		e_string	   error text
 */

void
cr_err_reply(pkt,pname,pinst,prealm,time_ws,e,e_string)
    KTEXT pkt;
    char *pname;		/* Principal's name */
    char *pinst;		/* Principal's instance */
    char *prealm;		/* Principal's authentication domain */
    u_long time_ws;		/* Workstation time */
    u_long e;			/* Error code */
    char *e_string;		/* Text of error */
{
    unsigned char *p;
    size_t pnamelen, pinstlen, prealmlen, e_stringlen;

    p = pkt->dat;
    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_ERR_REPLY;

    /* Make sure the reply will fit into the buffer. */
    pnamelen = strlen(pname) + 1;
    pinstlen = strlen(pinst) + 1;
    prealmlen = strlen(prealm) + 1;
    e_stringlen = strlen(e_string) + 1;
    if(sizeof(pkt->dat) < (1 + 1 + pnamelen + pinstlen + prealmlen
			   + 4 + 4 + e_stringlen)) {
        pkt->length = 0;
	return;
    }
    /* Add the basic info */
    memcpy(p, pname, pnamelen);
    p += pnamelen;
    memcpy(p, pinst, pinstlen);
    p += pinstlen;
    memcpy(p, prealm, prealmlen);
    p += prealmlen;
    /* ws timestamp */
    KRB4_PUT32BE(p, time_ws);
    /* err code */
    KRB4_PUT32BE(p, e);
    /* err text */
    memcpy(p, e_string, e_stringlen);
    p += e_stringlen;

    /* And return */
    pkt->length = p - pkt->dat;
    return;
}
