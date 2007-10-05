/*
 * lib/krb4/rd_priv.c
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

/* system include files */
#include <stdio.h>
#include <string.h>

/* application include files */
#include "krb.h"
#include "prot.h"
#include "des.h"
#include "lsb_addr_cmp.h"
#include "port-sockets.h"

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

long KRB5_CALLCONV
krb_rd_priv(in, in_length, schedule, key, sender, receiver, m_data)
    u_char *in;			/* pointer to the msg received */
    unsigned KRB4_32 in_length; /* length of "in" msg */
    Key_schedule schedule;	/* precomputed key schedule */
    C_Block *key;		/* encryption key for seed and ivec */
    struct sockaddr_in *sender;
    struct sockaddr_in *receiver;
    MSG_DAT *m_data;		/*various input/output data from msg */
{
    register u_char *p,*q;
    int v, t, le;
    struct in_addr src_addr;
    unsigned KRB4_32 c_length;
    int swap_bytes;
    unsigned KRB4_32 t_local;
    KRB4_32 delta_t;		/* Difference between timestamps */

    p = in;			/* beginning of message */
#define IN_REMAIN (in_length - (p - in))
    swap_bytes = 0;

    if (IN_REMAIN < 1 + 1 + 4)
	return RD_AP_MODIFIED;
    v = *p++;
    if (v != KRB_PROT_VERSION && v != 3)
        return RD_AP_VERSION;
    private_msg_ver = v;
    t = *p++;
    if ((t & ~1) != AUTH_MSG_PRIVATE)
        return RD_AP_MSG_TYPE;
    le = t & 1;

    /* get cipher length */
    KRB4_GET32(c_length, p, le);
    /* check for rational length so we don't go comatose */
    if (IN_REMAIN < c_length)
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
                 schedule, key, DECRYPT);
#endif

    /* safely get application data length */
    KRB4_GET32(m_data->app_length, p, le);

    if (IN_REMAIN < m_data->app_length + 4 + 1 + 4)
	return RD_AP_MODIFIED;

#ifndef NOENCRYPTION
    /* we're now at the decrypted application data */
#endif
    m_data->app_data = p;

    p += m_data->app_length;

    /* safely get time_5ms */
    m_data->time_5ms = *p++;

    /* safely get src address */
    memcpy(&src_addr.s_addr, p, sizeof(src_addr.s_addr));
    /* don't swap, net order always */
    p += sizeof(src_addr.s_addr);

    if (!krb_ignore_ip_address) {
	switch (sender->sin_family) {
	case AF_INET:
	    if (src_addr.s_addr != sender->sin_addr.s_addr)
		return RD_AP_MODIFIED;
	    break;
#ifdef KRB5_USE_INET6
	case AF_INET6:
	    if (IN6_IS_ADDR_V4MAPPED (&((struct sockaddr_in6 *)sender)->sin6_addr)
		&& !memcmp (&src_addr.s_addr,
			    12 + (char *) &((struct sockaddr_in6 *)sender)->sin6_addr,
			    4))
		break;
	    /* Not v4 mapped?  Not ignoring addresses?  You lose.  */
	    return RD_AP_MODIFIED;
#endif
	default:
	    return RD_AP_MODIFIED;
	}
    }

    /* safely get time_sec */
    KRB4_GET32(m_data->time_sec, p, le);

    /* check direction bit is the sign bit */
    /* For compatibility with broken old code, compares are done in VAX 
       byte order (LSBFIRST) */ 
    /* However, if we don't have good ip addresses anyhow, just clear
       the bit. This makes it harder to detect replay of sent packets
       back to the receiver, but most higher level protocols can deal
       with that more directly. */
    if (krb_ignore_ip_address) {
	if (m_data->time_sec < 0)
	    m_data->time_sec = -m_data->time_sec;
    } else
	switch (krb4int_address_less (sender, receiver)) {
	case 1:
	    m_data->time_sec = -m_data->time_sec;
	    break;
	case -1:
	    if (m_data->time_sec < 0)
		m_data->time_sec = -m_data->time_sec;
	    break;
	}

    /* check the time integrity of the msg */
    t_local = TIME_GMT_UNIXSEC;
    delta_t = t_local - m_data->time_sec;
    if (delta_t < 0)
	delta_t = -delta_t;	/* Absolute value of difference */
    if (delta_t > CLOCK_SKEW)
        return RD_AP_TIME;	/* XXX should probably be better code */
    DEB(("\ndelta_t = %d", delta_t));

    /*
     * caller must check timestamps for proper order and
     * replays, since server might have multiple clients
     * each with its own timestamps and we don't assume
     * tightly synchronized clocks.
     */

#ifdef notdef
    memcpy((char *)&cksum, (char *) p, sizeof(cksum));
    if (swap_bytes) cksum = krb4_swab32(cksum)
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
