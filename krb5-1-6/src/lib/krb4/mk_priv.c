/*
 * lib/krb4/mk_priv.c
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
 * This routine constructs a Kerberos 'private msg', i.e.
 * cryptographically sealed with a private session key.
 *
 * Returns either < 0 ===> error, or resulting size of message
 *
 * Steve Miller    Project Athena  MIT/DEC
 */

#include <stdio.h>
#include <string.h>

#include "krb.h"
#include "prot.h"
#include "des.h"
#include "lsb_addr_cmp.h"
#include "port-sockets.h"

extern int krb_debug;

/*
 * krb_mk_priv() constructs an AUTH_MSG_PRIVATE message.  It takes
 * some user data "in" of "length" bytes and creates a packet in "out"
 * consisting of the user data, a timestamp, and the sender's network
 * address.
#ifndef NOENCRYTION
 * The packet is encrypted by pcbc_encrypt(), using the given
 * "key" and "schedule".
#endif
 * The length of the resulting packet "out" is
 * returned.
 *
 * It is similar to krb_mk_safe() except for the additional key
 * schedule argument "schedule" and the fact that the data is encrypted
 * rather than appended with a checksum.  Also, the protocol version
 * number is "private_msg_ver", defined in krb_rd_priv.c, rather than
 * KRB_PROT_VERSION, defined in "krb.h".
 *
 * The "out" packet consists of:
 *
 * Size			Variable		Field
 * ----			--------		-----
 *
 * 1 byte		private_msg_ver		protocol version number
 * 1 byte		AUTH_MSG_PRIVATE |	message type plus local
 *			HOST_BYTE_ORDER		byte order in low bit
 *
#ifdef NOENCRYPTION
 * 4 bytes		c_length		length of data
#else
 * 4 bytes		c_length		length of encrypted data
 *
 * ===================== begin encrypt ================================
#endif
 * 
 * 4 bytes		length			length of user data
 * length		in			user data
 * 1 byte		msg_time_5ms		timestamp milliseconds
 * 4 bytes		sender->sin.addr.s_addr	sender's IP address
 *
 * 4 bytes		msg_time_sec or		timestamp seconds with
 *			-msg_time_sec		direction in sign bit
 *
 * 0<=n<=7  bytes	pad to 8 byte multiple	zeroes
#ifndef NOENCRYPTION
 *			(done by pcbc_encrypt())
 *
 * ======================= end encrypt ================================
#endif
 */

/* Utility function:

   Determine order of addresses, if SENDER less than RECEIVER return 1
   so caller will negate timestamp.  Return -1 for failure.  */
int
krb4int_address_less (struct sockaddr_in *sender, struct sockaddr_in *receiver)
{
    unsigned long sender_addr, receiver_addr;
    unsigned short sender_port, receiver_port;
    switch (sender->sin_family) {
    case AF_INET:
	sender_addr = sender->sin_addr.s_addr;
	sender_port = sender->sin_port;
	break;
#ifdef KRB5_USE_INET6
    case AF_INET6:
    {
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) sender;
	if (IN6_IS_ADDR_V4MAPPED (&s6->sin6_addr)) {
	    struct sockaddr_in sintmp = { 0 };
	    memcpy (&sintmp.sin_addr.s_addr,
		    12+(char*)&s6->sin6_addr.s6_addr,
		    4);
	    sender_addr = sintmp.sin_addr.s_addr;
	} else
	    return -1;
	sender_port = s6->sin6_port;
	break;
    }
#endif
    default:
	return -1;
    }
    switch (receiver->sin_family) {
    case AF_INET:
	receiver_addr = receiver->sin_addr.s_addr;
	receiver_port = receiver->sin_port;
	break;
#ifdef KRB5_USE_INET6
    case AF_INET6:
    {
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) receiver;
	if (IN6_IS_ADDR_V4MAPPED (&s6->sin6_addr)) {
	    struct sockaddr_in sintmp = { 0 };
	    memcpy (&sintmp.sin_addr.s_addr,
		    12+(char*)&s6->sin6_addr.s6_addr,
		    4);
	    receiver_addr = sintmp.sin_addr.s_addr;
	} else
	    return -1;
	receiver_port = s6->sin6_port;
	break;
    }
#endif
    default:
	return -1;
    }
    /* For compatibility with broken old code, compares are done in
       VAX byte order (LSBFIRST).  */
    if (lsb_net_ulong_less(sender_addr, receiver_addr) == -1
	|| (lsb_net_ulong_less(sender_addr, receiver_addr) == 0
	    && lsb_net_ushort_less(sender_port, receiver_port) == -1))
	return 1;
    return 0;
    /*
     * all that for one tiny bit!  Heaven help those that talk to
     * themselves.
     */
}

long KRB5_CALLCONV
krb_mk_priv(in, out, length, schedule, key, sender, receiver)
    u_char *in;		/* application data */
    u_char *out;		/* put msg here, leave room for
				 * header! breaks if in and out
				 * (header stuff) overlap */
    unsigned KRB4_32 length;	/* of in data */
    Key_schedule schedule;	/* precomputed key schedule */
    C_Block *key;		/* encryption key for seed and ivec */
    struct sockaddr_in *sender;   /* sender address */
    struct sockaddr_in *receiver; /* receiver address */
{
    register u_char     *p,*q;
    u_char *c_length_ptr;
    extern int private_msg_ver; /* in krb_rd_priv.c */

    unsigned KRB4_32 c_length, c_length_raw;
    u_char msg_time_5ms;
    unsigned KRB4_32 msg_time_sec;
    unsigned KRB4_32 msg_time_usec;

    /* Be really paranoid. */
    if (sizeof(sender->sin_addr.s_addr) != 4)
	return -1;
    /*
     * get the current time to use instead of a sequence #, since
     * process lifetime may be shorter than the lifetime of a session
     * key.
     */
    msg_time_sec = TIME_GMT_UNIXSEC_US(&msg_time_usec);
    msg_time_5ms = msg_time_usec / 5000; /* 5ms quanta */

    p = out;

    /* Cruftiness below! */
    *p++ = private_msg_ver ? private_msg_ver : KRB_PROT_VERSION;
    *p++ = AUTH_MSG_PRIVATE;

    /* save ptr to cipher length */
    c_length_ptr = p;
    p += 4;

#ifndef NOENCRYPTION
    /* start for encrypted stuff */
#endif
    q = p;

    /* stuff input length */
    KRB4_PUT32BE(p, length);

#ifdef NOENCRYPTION
    /* make all the stuff contiguous for checksum */
#else
    /* make all the stuff contiguous for checksum and encryption */
#endif
    memcpy(p, in, (size_t)length);
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
     * direction bit is the sign bit of the timestamp.  Ok
     * until 2038??
     */
    switch (krb4int_address_less (sender, receiver)) {
    case 1:
	msg_time_sec = -msg_time_sec;
	break;
    case -1:
	/* Which way should we go in this case?  */
    case 0:
	break;
    }

    /* stuff time sec */
    KRB4_PUT32BE(p, msg_time_sec);

    /*
     * All that for one tiny bit!  Heaven help those that talk to
     * themselves.
     */

#ifdef notdef
    /*
     * calculate the checksum of the length, address, sequence, and
     * inp data
     */
    cksum = quad_cksum(q,NULL,p-q,0,key);
    DEB (("\ncksum = %u",cksum));
    /* stuff checksum */
    memcpy(p, &cksum, sizeof(cksum));
    p += sizeof(cksum);
#endif

#ifdef NOENCRYPTION
    /*
     * All the data have been assembled, compute length
     */
#else
    /*
     * All the data have been assembled, compute length and encrypt
     * starting with the length, data, and timestamps use the key as
     * an ivec.
     */
#endif

    c_length_raw = p - q;
    c_length = ((c_length_raw + sizeof(C_Block) -1)
		/ sizeof(C_Block)) * sizeof(C_Block);
    /* stuff the length */
    p = c_length_ptr;
    KRB4_PUT32BE(p, c_length);

#ifndef NOENCRYPTION
    /* pcbc encrypt, pad as needed, use key as ivec */
    pcbc_encrypt((C_Block *)q,(C_Block *)q, (long)c_length_raw,
		 schedule, key, ENCRYPT);
#endif /* NOENCRYPTION */

    return q - out + c_length;	/* resulting size */
}
