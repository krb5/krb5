/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_mk_safe for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_mk_safe_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "krb425.h"
#include <arpa/inet.h>

long
krb_mk_safe(in, out, in_length, key, sender, receiver)
u_char *in;
u_char *out;
u_long in_length;
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

	keyb.keytype = KEYTYPE_DES;
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

	if (r = krb5_get_server_rcache(inet_ntoa(sender->sin_addr),
				       &rcache)) {
	    krb5_free_addr(saddr2);
#ifdef	EBUG
	    ERROR(r);
#endif
	    return(-1);
	}
	r = krb5_mk_safe(&inbuf,
			 CKSUMTYPE_RSA_MD4_DES,
			 &keyb,
			 saddr2, &raddr,
			 0,		/* no sequence number */
			 0,		/* default flags (none) */
			 rcache,
			 &out5);
	krb5_rc_close(rcache);
	xfree(rcache);
	krb5_free_addr(saddr2);

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
