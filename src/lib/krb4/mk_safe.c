/*
 * lib/krb4/mk_req.c
 *
 * Copyright 1986, 1987, 1988, 2000 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
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
 *
 * This routine constructs a Kerberos 'safe msg', i.e. authenticated
 * using a private session key to seed a checksum. Msg is NOT
 * encrypted.
 *
 * Returns either <0 ===> error, or resulting size of message
 *
 * Steve Miller    Project Athena  MIT/DEC
 */

#include <stdio.h>
#include <string.h>

#include "krb.h"
#include "des.h"
#include "prot.h"
#include "lsb_addr_cmp.h"
#include "port-sockets.h"

extern int krb_debug;

/*
 * krb_mk_safe() constructs an AUTH_MSG_SAFE message.  It takes some
 * user data "in" of "length" bytes and creates a packet in "out"
 * consisting of the user data, a timestamp, and the sender's network
 * address, followed by a checksum computed on the above, using the
 * given "key".  The length of the resulting packet is returned.
 *
 * The "out" packet consists of:
 *
 * Size			Variable		Field
 * ----			--------		-----
 *
 * 1 byte		KRB_PROT_VERSION	protocol version number
 * 1 byte		AUTH_MSG_SAFE |		message type plus local
 *			HOST_BYTE_ORDER		byte order in low bit
 *
 * ===================== begin checksum ================================
 * 
 * 4 bytes		length			length of user data
 * length		in			user data
 * 1 byte		msg_time_5ms		timestamp milliseconds
 * 4 bytes		sender->sin.addr.s_addr	sender's IP address
 *
 * 4 bytes		msg_time_sec or		timestamp seconds with
 *			-msg_time_sec		direction in sign bit
 *
 * ======================= end checksum ================================
 *
 * 16 bytes		big_cksum		quadratic checksum of
 *						above using "key"
 */

long KRB5_CALLCONV
krb_mk_safe(in, out, length, key, sender, receiver)
    u_char *in;			/* application data */
    u_char *out;		/*
				 * put msg here, leave room for header!
				 * breaks if in and out (header stuff)
				 * overlap
				 */
    unsigned KRB4_32 length;	/* of in data */
    C_Block *key;		/* encryption key for seed and ivec */
    struct sockaddr_in *sender;	/* sender address */
    struct sockaddr_in *receiver; /* receiver address */
{
    register u_char     *p,*q;

    unsigned KRB4_32 cksum;
    unsigned KRB4_32 big_cksum[4];
    unsigned KRB4_32 msg_secs;
    unsigned KRB4_32 msg_usecs;
    u_char msg_time_5ms;
    KRB4_32 msg_time_sec;
    int i;

    /* Be really paranoid. */
    if (sizeof(sender->sin_addr.s_addr) != 4)
	return -1;
    /*
     * get the current time to use instead of a sequence #, since
     * process lifetime may be shorter than the lifetime of a session
     * key.
     */
    msg_secs = TIME_GMT_UNIXSEC_US(&msg_usecs);
    msg_time_sec = msg_secs;
    msg_time_5ms = msg_usecs / 5000; /* 5ms quanta */

    p = out;

    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_SAFE;

    q = p;			/* start for checksum stuff */
    /* stuff input length */
    KRB4_PUT32BE(p, length);

    /* make all the stuff contiguous for checksum */
    memcpy(p, in, length);
    p += length;

    /* stuff time 5ms */
    *p++ = msg_time_5ms;

    /* stuff source address */
    if (sender->sin_family == AF_INET)
	memcpy(p, &sender->sin_addr.s_addr, sizeof(sender->sin_addr.s_addr));
#ifdef KRB5_USE_INET6
    else if (sender->sin_family == AF_INET6
	     && IN6_IS_ADDR_V4MAPPED (&((struct sockaddr_in6 *)sender)->sin6_addr))
	memcpy(p, 12+(char*)&((struct sockaddr_in6 *)sender)->sin6_addr, 4);
#endif
    else
	/* The address isn't one we can encode in 4 bytes -- but
	   that's okay if the receiver doesn't care.  */
	memset(p, 0, 4);
    p += sizeof(sender->sin_addr.s_addr);

    /*
     * direction bit is the sign bit of the timestamp.  Ok until
     * 2038??
     */
    if (krb4int_address_less (sender, receiver) == 1)
	msg_time_sec = -msg_time_sec;
    /* stuff time sec */
    KRB4_PUT32BE(p, msg_time_sec);

#ifdef NOENCRYPTION
    cksum = 0;
    memset(big_cksum, 0, sizeof(big_cksum));
#else /* Do encryption */
    /* calculate the checksum of length, timestamps, and input data */
    cksum = quad_cksum(q, (unsigned KRB4_32 *)big_cksum,
		       p - q, 2, key);
#endif /* NOENCRYPTION */
    DEB(("\ncksum = %u",cksum));

    /* stuff checksum */
    for (i = 0; i < 4; i++)
	KRB4_PUT32BE(p, big_cksum[i]);

    return p - out;		/* resulting size */
}
