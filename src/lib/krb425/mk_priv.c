/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_mk_priv for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_mk_priv_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include "krb425.h"

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

	if (r = krb5_mk_priv(&inbuf,
			     KEYTYPE_DES,
			     &keyb,
			     &saddr, &raddr,
			     0,		/* no sequence number */
			     0,		/* default flags (none) */
			     0, &out5)) {
#ifdef	EBUG
		ERROR(r);
#endif
		return(-1);
	}

	memcpy((char *)out, out5.data, out5.length);
	free(out5.data);
	return(out5.length);
}
