/*
 * rd_priv.c
 *
 * CopKRB4_32right 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * This routine dissects a a Kerberos 'private msg', decrypting it,
 * checking its integrity, and returning a pointer to the application
 * data contained and its length.
 *
 * Returns 0 (RD_AP_OK) for success or an error code (RD_AP_...).  If
 * the return value is RD_AP_TIME, then either the times are too far
 * out of synch, OR the packet was modified.
 *
 * Steve Miller    Project Athena  MIT/DEC
 */

#include "mit-copyright.h"

/* system include files */
#include <stdio.h>
#include <string.h>

/* application include files */
#define	DEFINE_SOCKADDR		/* Ask for sockets declarations from krb.h. */
#include "krb.h"
#include "prot.h"
#include "des.h"
#include "lsb_addr_cmp.h"

extern int krb_debug;

/* This one is exported, for use by krb_mk_priv.  */
int private_msg_ver = KRB_PROT_VERSION;

/*
#ifdef NOENCRPYTION
 * krb_rd_priv() checks the integrity of an
#else
 * krb_rd_priv() decrypts and checks the integrity of an
#endif
 * AUTH_MSG_PRIVATE message.  Given the message received, "in",
 * the length of that message, "in_length", the key "schedule"
#ifdef NOENCRYPTION
 * and "key", and the network addresses of the
#else
 * and "key" to decrypt with, and the network addresses of the
#endif
 * "sender" and "receiver" of the message, krb_rd_safe() returns
 * RD_AP_OK if the message is okay, otherwise some error code.
 *
 * The message data retrieved from "in" are returned in the structure
#ifdef NOENCRYPTION
 * "m_data".  The pointer to the application data
#else
 * "m_data".  The pointer to the decrypted application data
#endif
 * (m_data->app_data) refers back to the appropriate place in "in".
 *
 * See the file "mk_priv.c" for the format of the AUTH_MSG_PRIVATE
 * message.  The structure containing the extracted message
 * information, MSG_DAT, is defined in "krb.h".
 */

KRB5_DLLIMP long KRB5_CALLCONV
krb_rd_priv(in,in_length,schedule,key,sender,receiver,m_data)
    u_char *in;			/* pointer to the msg received */
    unsigned KRB4_32 in_length; /* length of "in" msg */
    Key_schedule schedule;	/* precomputed key schedule */
    C_Block key;		/* encryption key for seed and ivec */
    struct sockaddr_in *sender;
    struct sockaddr_in *receiver;
    MSG_DAT *m_data;		/*various input/output data from msg */
{
    register u_char *p,*q;
    unsigned KRB4_32 src_addr;
    unsigned KRB4_32 c_length;
    int swap_bytes;
    unsigned KRB4_32 t_local;
    KRB4_32 delta_t;		/* Difference between timestamps */

    p = in;			/* beginning of message */
    swap_bytes = 0;

    if (*p++ != KRB_PROT_VERSION && *(p-1) != 3)
        return RD_AP_VERSION;
    private_msg_ver = *(p-1);
    if (((*p) & ~1) != AUTH_MSG_PRIVATE)
        return RD_AP_MSG_TYPE;
    if ((*p++ & 1) != HOST_BYTE_ORDER)
        swap_bytes++;

    /* get cipher length */
    memcpy((char *)&c_length, (char *)p, sizeof(c_length));
    if (swap_bytes)
        swap_u_long(c_length);
    p += sizeof(c_length);
    /* check for rational length so we don't go comatose */
    if (VERSION_SZ + MSG_TYPE_SZ + c_length > in_length)
        return RD_AP_MODIFIED;

#ifndef NOENCRYPTION
    /*
     * decrypt to obtain length, timestamps, app_data, and checksum
     * use the session key as an ivec
     */
#endif

    q = p;			/* mark start of encrypted stuff */

#ifndef NOENCRYPTION
    /* pcbc decrypt, use key as ivec */
    pcbc_encrypt((C_Block *)q, (C_Block *)q, (long)c_length,
                 schedule, (C_Block *)key, DECRYPT);
#endif

    /* safely get application data length */
    memcpy((char *)&(m_data->app_length), (char *) p, 
	   sizeof(m_data->app_length));
    if (swap_bytes)
        swap_u_long(m_data->app_length);
    p += sizeof(m_data->app_length);    /* skip over */

    if (m_data->app_length + sizeof(c_length) + sizeof(in_length) +
        sizeof(m_data->time_sec) + sizeof(m_data->time_5ms) +
        sizeof(src_addr) + VERSION_SZ + MSG_TYPE_SZ
        > in_length)
        return RD_AP_MODIFIED;

#ifndef NOENCRYPTION
    /* we're now at the decrypted application data */
#endif
    m_data->app_data = p;

    p += m_data->app_length;

    /* safely get time_5ms */
    memcpy((char *)&(m_data->time_5ms), (char *) p, 
	   sizeof(m_data->time_5ms));
    /*  don't need to swap-- one byte for now */
    p += sizeof(m_data->time_5ms);

    /* safely get src address */
    memcpy((char *)&src_addr, (char *) p, sizeof(src_addr));
    /* don't swap, net order always */
    p += sizeof(src_addr);

    if (!krb_ignore_ip_address && src_addr != (u_long) sender->sin_addr.s_addr)
	return RD_AP_MODIFIED;

    /* safely get time_sec */
    memcpy((char *)&(m_data->time_sec), (char *) p, 
	  sizeof(m_data->time_sec));
    if (swap_bytes) swap_u_long(m_data->time_sec);

    p += sizeof(m_data->time_sec);

    /* check direction bit is the sign bit */
    /* For compatibility with broken old code, compares are done in VAX 
       byte order (LSBFIRST) */ 
    /* However, if we don't have good ip addresses anyhow, just clear
       the bit. This makes it harder to detect replay of sent packets
       back to the receiver, but most higher level protocols can deal
       with that more directly. */
    if (krb_ignore_ip_address) {
        if (m_data->time_sec <0)
            m_data->time_sec = -m_data->time_sec;
    } else if (lsb_net_ulong_less(sender->sin_addr.s_addr,
			   receiver->sin_addr.s_addr)==-1) 
	/* src < recv */ 
	m_data->time_sec =  - m_data->time_sec; 
    else if (lsb_net_ulong_less(sender->sin_addr.s_addr, 
				receiver->sin_addr.s_addr)==0) 
	if (lsb_net_ushort_less(sender->sin_port,receiver->sin_port)==-1)
	    /* src < recv */
	    m_data->time_sec =  - m_data->time_sec; 
    /*
     * all that for one tiny bit!
     * Heaven help those that talk to themselves.
     */

    /* check the time integrity of the msg */
    t_local = TIME_GMT_UNIXSEC;
    delta_t = t_local - m_data->time_sec;
    if (delta_t < 0) delta_t = -delta_t;  /* Absolute value of difference */
    if (delta_t > CLOCK_SKEW) {
        return(RD_AP_TIME);		/* XXX should probably be better
					   code */
    }
    DEB (("\ndelta_t = %d",delta_t));

    /*
     * caller must check timestamps for proper order and
     * replays, since server might have multiple clients
     * each with its own timestamps and we don't assume
     * tightly synchronized clocks.
     */

#ifdef notdef
    memcpy((char *)&cksum, (char *) p, sizeof(cksum));
    if (swap_bytes) swap_u_long(cksum)
    /*
     * calculate the checksum of the length, sequence,
     * and input data, on the sending byte order!!
     */
    calc_cksum = quad_cksum(q, NULL, p-q, 0, key);

    DEB (("\ncalc_cksum = %u, received cksum = %u",
	       calc_cksum, cksum));
    if (cksum != calc_cksum)
	return RD_AP_MODIFIED;
#endif
    return RD_AP_OK;        /* OK == 0 */
}
