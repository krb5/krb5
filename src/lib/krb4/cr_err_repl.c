/*
 * cr_err_repl.c
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
 * This is only needed for backwards compatibility for Kerberos V3 (!)
 * and it causes problems for shared libraries.  So I've yanked it.
 */
#if 0
extern int req_act_vno;		/* this is defined in the kerberos
				 * server code */
#endif

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
    u_char *v = (u_char *) pkt->dat; /* Prot vers number */
    u_char *t = (u_char *)(pkt->dat+1); /* Prot message type */

    /* Create fixed part of packet */
#if 0
    *v = (unsigned char) req_act_vno; /* KRB_PROT_VERSION; */
#else
    *v = (unsigned char) KRB_PROT_VERSION;
#endif
    *t = (unsigned char) AUTH_MSG_ERR_REPLY;
    *t |= HOST_BYTE_ORDER;

    /* Make sure the reply will fit into the buffer. */
    if(sizeof(pkt->dat) < 3 + strlen(pname) +
		    	  1 + strlen(pinst) +
			  1 + strlen(prealm) +
			  4 + 4 +
			  1 + strlen(e_string)) {
        pkt->length = 0;
	return;
    }
    /* Add the basic info */
    (void) strcpy((char *) (pkt->dat+2),pname);
    pkt->length = 3 + strlen(pname);
    (void) strcpy((char *)(pkt->dat+pkt->length),pinst);
    pkt->length += 1 + strlen(pinst);
    (void) strcpy((char *)(pkt->dat+pkt->length),prealm);
    pkt->length += 1 + strlen(prealm);
    /* ws timestamp */
    memcpy((char *)(pkt->dat+pkt->length), (char *) &time_ws, 4);
    pkt->length += 4;
    /* err code */
    memcpy((char *)(pkt->dat+pkt->length), (char *) &e, 4);
    pkt->length += 4;
    /* err text */
    (void) strcpy((char *)(pkt->dat+pkt->length),e_string);
    pkt->length += 1 + strlen(e_string);

    /* And return */
    return;
}
