/*
 * mk_safe.c
 *
 * Copyright 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * This routine constructs a Kerberos 'safe msg', i.e. authenticated
 * using a private session key to seed a checksum. Msg is NOT
 * encrypted.
 *
 * Returns either <0 ===> error, or resulting size of message
 *
 * Steve Miller    Project Athena  MIT/DEC
 */

#include "mit-copyright.h"
#include <stdio.h>
#include <string.h>

#define	DEFINE_SOCKADDR		/* Ask for sockets declarations from krb.h. */
#include "krb.h"
#include "des.h"
#include "prot.h"
#include "lsb_addr_cmp.h"

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

KRB5_DLLIMP long KRB5_CALLCONV
krb_mk_safe(in,out,length,key,sender,receiver)
    u_char *in;			/* application data */
    u_char *out;		/*
				 * put msg here, leave room for header!
				 * breaks if in and out (header stuff)
				 * overlap
				 */
    unsigned KRB4_32 length;	/* of in data */
    C_Block key;		/* encryption key for seed and ivec */
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

    /*
     * get the current time to use instead of a sequence #, since
     * process lifetime may be shorter than the lifetime of a session
     * key.
     */
	 
    msg_secs = TIME_GMT_UNIXSEC_US(&msg_usecs);
    msg_time_sec = msg_secs;
    msg_time_5ms = msg_usecs/5000; /* 5ms quanta */

    p = out;

    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_SAFE | HOST_BYTE_ORDER;

    q = p;			/* start for checksum stuff */
    /* stuff input length */
    memcpy((char *)p, (char *)&length, sizeof(length));
    p += sizeof(length);

    /* make all the stuff contiguous for checksum */
    memcpy((char *)p, (char *)in, (int) length);
    p += length;

    /* stuff time 5ms */
    memcpy((char *)p, (char *)&msg_time_5ms, sizeof(msg_time_5ms));
    p += sizeof(msg_time_5ms);

    /* stuff source address */
    memcpy((char *)p, (char *) &sender->sin_addr.s_addr, 
	   sizeof(sender->sin_addr.s_addr));
    p += sizeof(sender->sin_addr.s_addr);

    /*
     * direction bit is the sign bit of the timestamp.  Ok until
     * 2038??
     */
    /* For compatibility with broken old code, compares are done in VAX 
       byte order (LSBFIRST) */ 
    if (lsb_net_ulong_less(sender->sin_addr.s_addr, /* src < recv */ 
			  receiver->sin_addr.s_addr)==-1) 
        msg_time_sec =  -msg_time_sec; 
    else if (lsb_net_ulong_less(sender->sin_addr.s_addr, 
				receiver->sin_addr.s_addr)==0) 
        if (lsb_net_ushort_less(sender->sin_port,receiver->sin_port) == -1) 
            msg_time_sec = -msg_time_sec; 
    /*
     * all that for one tiny bit!  Heaven help those that talk to
     * themselves.
     */

    /* stuff time sec */
    memcpy((char *)p, (char *)&msg_time_sec, sizeof(msg_time_sec));
    p += sizeof(msg_time_sec);

#ifdef NOENCRYPTION
    cksum = 0;
    memset((char*) big_cksum, 0, sizeof(big_cksum));
#else /* Do encryption */
    /* calculate the checksum of length, timestamps, and input data */
    cksum = quad_cksum(q, (unsigned KRB4_32 *)big_cksum,
		       p-q, 2, (C_Block *)key);
#endif /* NOENCRYPTION */
    DEB (("\ncksum = %u",cksum));

    /* stuff checksum */
    memcpy((char *)p, (char *)big_cksum, sizeof(big_cksum));
    p += sizeof(big_cksum);

    return ((long)(p - out));	/* resulting size */
}
