/*
 * mk_priv.c
 *
 * CopKRB4_32right 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * This routine constructs a Kerberos 'private msg', i.e.
 * cryptographically sealed with a private session key.
 *
 * Returns either < 0 ===> error, or resulting size of message
 *
 * Steve Miller    Project Athena  MIT/DEC
 */

#include "mit-copyright.h"

#include <stdio.h>
#include <string.h>

#define	DEFINE_SOCKADDR		/* Ask for sockets declarations from krb.h. */
#include "krb.h"
#include "prot.h"
#include "des.h"
#include "lsb_addr_cmp.h"

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

KRB5_DLLIMP long KRB5_CALLCONV
krb_mk_priv(in,out,length,schedule,key,sender,receiver)
    u_char FAR *in;		/* application data */
    u_char FAR *out;		/* put msg here, leave room for
				 * header! breaks if in and out
				 * (header stuff) overlap */
    unsigned KRB4_32 length;	/* of in data */
    Key_schedule schedule;	/* precomputed key schedule */
    C_Block key;		/* encryption key for seed and ivec */
    struct sockaddr_in FAR *sender;   /* sender address */
    struct sockaddr_in FAR *receiver; /* receiver address */
{
    register u_char     *p,*q;
    u_char *c_length_ptr;
    extern int private_msg_ver; /* in krb_rd_priv.c */

    unsigned KRB4_32 c_length;
    u_char msg_time_5ms;
    unsigned KRB4_32 msg_time_sec;
    unsigned KRB4_32 msg_time_usec;

    /*
     * get the current time to use instead of a sequence #, since
     * process lifetime may be shorter than the lifetime of a session
     * key.
     */
    msg_time_sec = TIME_GMT_UNIXSEC_US (&msg_time_usec);
    msg_time_5ms = msg_time_usec/5000; /* 5ms quanta */

    p = out;

    *p++ = private_msg_ver?private_msg_ver:KRB_PROT_VERSION;
    *p++ = AUTH_MSG_PRIVATE | HOST_BYTE_ORDER;

    /* calculate cipher length */
    c_length_ptr = p;
    p += sizeof(c_length);

#ifndef NOENCRYPTION
    /* start for encrypted stuff */
#endif
    q = p;

    /* stuff input length */
    memcpy((char *)p, (char *)&length, sizeof(length));
    p += sizeof(length);

#ifdef NOENCRYPTION
    /* make all the stuff contiguous for checksum */
#else
    /* make all the stuff contiguous for checksum and encryption */
#endif
    memcpy((char *)p, (char *)in, (int) length);
    p += length;

    /* stuff time 5ms */
    memcpy((char *)p, (char *)&msg_time_5ms, sizeof(msg_time_5ms));
    p += sizeof(msg_time_5ms);

    /* stuff source address */
    memcpy((char *)p, (char *)&sender->sin_addr.s_addr, 
	   sizeof(sender->sin_addr.s_addr));
    p += sizeof(sender->sin_addr.s_addr);

    /*
     * direction bit is the sign bit of the timestamp.  Ok
     * until 2038??
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
    /* stuff time sec */
    memcpy((char *)p, (char *)&msg_time_sec, sizeof(msg_time_sec));
    p += sizeof(msg_time_sec);

    /*
     * All that for one tiny bit!  Heaven help those that talk to
     * themselves.
     */

#ifdef notdef
    /*
     * calculate the checksum of the length, address, sequence, and
     * inp data
     */
    cksum =  quad_cksum(q,NULL,p-q,0,key);
    DEB (("\ncksum = %u",cksum));
    /* stuff checksum */
    memcpy((char *) p, (char *) &cksum, sizeof(cksum));
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

    c_length = p - q;
    c_length = ((c_length + sizeof(C_Block) -1)/sizeof(C_Block)) *
        sizeof(C_Block);
    /* stuff the length */
    memcpy((char *)c_length_ptr, (char *) &c_length, sizeof(c_length));

#ifndef NOENCRYPTION
    /* pcbc encrypt, pad as needed, use key as ivec */
    pcbc_encrypt((C_Block *) q,(C_Block *) q, (long) (p-q), schedule,
                 (C_Block *)key, ENCRYPT);
#endif /* NOENCRYPTION */

    return (q - out + c_length);        /* resulting size */
}
