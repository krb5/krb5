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
 * krb_rd_priv for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rd_priv_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "krb425.h"
#include <arpa/inet.h>

long
krb_rd_priv(in, in_length, sched, key, sender, receiver, msg)
u_char *in;
u_long in_length;
Key_schedule sched;	/* ignored */
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
	    return(krb425error(r));
	}
	if (rcache = (krb5_rcache) malloc(sizeof(*rcache))) {
	    if (!(r = krb5_rc_resolve_type(&rcache, "dfl"))) {
		char *cachename;
		extern krb5_deltat krb5_clockskew;
		char *insender = inet_ntoa(sender->sin_addr);

		if (cachename = calloc(1, strlen(insender)+1+4+5)) {
		    /* 1 for NUL, 4 for rc_., 5 for digits of port
		       (unsigned 16bit, no greater than 65535) */
		    sprintf(cachename, "rc_%s.%u", insender,
			    ntohs(receiver->sin_port));

		    if (!(r = krb5_rc_resolve(rcache, cachename))) {
			if (!((r = krb5_rc_recover(rcache)) &&
			      (r = krb5_rc_initialize(rcache,
						      krb5_clockskew)))) {
			    r = krb5_rd_priv(&inbuf, &keyb, saddr2, &raddr,
					     0, 0, 0, rcache, &out);
			    krb5_rc_close(rcache);
			}
		    }
		    free(cachename);
		} else
		    r = ENOMEM;
	    }
	    xfree(rcache);
	} else {
	    krb5_free_addr(saddr2);
#ifdef	EBUG
	    ERROR(ENOMEM);
#endif
	    return(krb425error(ENOMEM));
	}
	krb5_free_addr(saddr2);

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
