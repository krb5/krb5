/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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

#include <krb5/copyright.h>
#include "krb425.h"

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
	krb5_address saddr;
	krb5_address raddr;
	krb5_error_code r;
	char sa[4], ra[4];

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

	if (r = krb5_rd_priv(&inbuf, &keyb, &saddr, &raddr, 0, 0, 0, &out)) {
#ifdef	EBUG
		ERROR(r)
#endif
		return(-1);
	}

	msg->app_data = (u_char *)out.data;
	msg->app_length = out.length;
	msg->hash = 0L;
	msg->swap = 0;
	msg->time_sec = 0;
	msg->time_5ms = 0;
	return(KSUCCESS);
}
