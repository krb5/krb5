/*
 * lib/krb425/rd_safe.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb_rd_safe for krb425
 */


#include "krb425.h"
#ifndef hpux
#include <arpa/inet.h>
#endif
#include <netinet/in.h>

long
krb_rd_safe(in, in_length, key, sender, receiver, msg)
u_char *in;
u_long in_length;
des_cblock key;
struct sockaddr_in *sender;
struct sockaddr_in *receiver;
MSG_DAT *msg;
{
	krb5_data inbuf;
	krb5_data out;
	krb5_keyblock keyb;
	krb5_address saddr, *saddr2;
	krb5_address raddr;
	krb5_error_code r;
	char sa[4], ra[4];
	krb5_rcache rcache;
	char *cachename;

	keyb.enctype = ENCTYPE_DES;
	keyb.length = sizeof(des_cblock);
	keyb.contents = (krb5_octet *)key;

	saddr.addrtype = ADDRTYPE_INET;
	saddr.length = 4;
	saddr.contents = (krb5_octet *)sa;

	raddr.addrtype = ADDRTYPE_INET;
	raddr.length = 4;
	raddr.contents = (krb5_octet *)ra;

	memcpy(sa, (char *)&sender->sin_addr, 4);
	memcpy(ra, (char *)&receiver->sin_addr, 4);

	inbuf.data = (char *)in;
	inbuf.length = in_length;

	if (r = krb5_gen_portaddr(&saddr, (krb5_pointer)&sender->sin_port,
				  &saddr2)) {
#ifdef	EBUG
	    ERROR(r);
#endif
	    return(krb425error(r));
	}
	if (cachename = calloc(1, strlen(inet_ntoa(sender->sin_addr)+1+1+5)))
	    /* 1 for NUL, 1 for rc_., 5 for digits of port
		       (unsigned 16bit, no greater than 65535) */
	    sprintf(cachename, "%s.%u", inet_ntoa(sender->sin_addr),
		    ntohs(receiver->sin_port));
	else {
#ifdef	EBUG
	    ERROR(ENOMEM);
#endif
	    return(krb425error(ENOMEM));
	}
	    
	out.data = cachename;
	out.length = strlen(cachename);
	if (r = krb5_get_server_rcache(&out,
				       &rcache)) {
	    krb5_free_address(saddr2);
#ifdef	EBUG
	    ERROR(r);
#endif
	    return(-1);
	}
	free(cachename);
	r = krb5_rd_safe(&inbuf, &keyb, saddr2, &raddr,
			 0, 0, rcache, &out);
	krb5_rc_close(rcache);

	krb5_free_address(saddr2);

	if (r) {
#ifdef	EBUG
		ERROR(r);
#endif
		return(krb425error(r));
	}

	msg->app_data = (u_char *)out.data;
	msg->app_length = out.length;
	msg->hash = 0L;
	msg->swap = 0;
	msg->time_sec = 0;
	msg->time_5ms = 0;
	return(KSUCCESS);
}
