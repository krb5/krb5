/*
 * lib/krb425/mk_priv.c
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
 * krb_mk_priv for krb425
 */


#include "krb425.h"
#ifndef hpux
#include <arpa/inet.h>
#endif

long
krb_mk_priv(in, out, in_length, sched, key, sender, receiver)
u_char *in;
u_char *out;
u_long in_length;
Key_schedule sched;	/* ignored */
des_cblock key;
struct sockaddr_in *sender;
struct sockaddr_in *receiver;
{
	krb5_data inbuf;
	krb5_data out5;
	krb5_keyblock keyb;
	krb5_address saddr, *saddr2;
	krb5_address raddr;
	krb5_error_code r;
	char sa[4], ra[4];
	krb5_rcache rcache;

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
	    return(-1);
	}


	out5.data = inet_ntoa(sender->sin_addr);
	out5.length = strlen(out5.data);
	if (r = krb5_get_server_rcache(&out5,
				       &rcache)) {
	    krb5_free_address(saddr2);
#ifdef	EBUG
	    ERROR(r);
#endif
	    return(-1);
	}
	r = krb5_mk_priv(&inbuf,
			 ENCTYPE_DES,
			 &keyb,
			 saddr2, &raddr,
			 0,		/* no sequence number */
			 0,		/* default flags (none) */
			 rcache,
			 0,		/* ignore ivec */
			 &out5);
	krb5_rc_close(rcache);
	krb5_free_address(saddr2);

	if (r) {
#ifdef	EBUG
		ERROR(r);
#endif
		return(-1);
	}

	memcpy((char *)out, out5.data, out5.length);
	free(out5.data);
	return(out5.length);
}
