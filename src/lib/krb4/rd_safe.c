/*
 * lib/krb4/rd_safe.c
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
 * This routine dissects a a Kerberos 'safe msg', checking its
 * integrity, and returning a pointer to the application data
 * contained and its length.
 *
 * Returns 0 (RD_AP_OK) for success or an error code (RD_AP_...)
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

/*
 * krb_rd_safe() checks the integrity of an AUTH_MSG_SAFE message.
 * Given the message received, "in", the length of that message,
 * "in_length", the "key" to compute the checksum with, and the
 * network addresses of the "sender" and "receiver" of the message,
 * krb_rd_safe() returns RD_AP_OK if message is okay, otherwise
 * some error code.
 *
 * The message data retrieved from "in" is returned in the structure
 * "m_data".  The pointer to the application data (m_data->app_data)
 * refers back to the appropriate place in "in".
 *
 * See the file "mk_safe.c" for the format of the AUTH_MSG_SAFE
 * message.  The structure containing the extracted message
 * information, MSG_DAT, is defined in "krb.h".
 */

long KRB5_CALLCONV
krb_rd_safe(in,in_length,key,sender,receiver,m_data)
    u_char *in;			/* pointer to the msg received */
    unsigned KRB4_32 in_length;		/* length of "in" msg */
    C_Block *key;			/* encryption key for seed and ivec */
    struct sockaddr_in *sender;	/* sender's address */
    struct sockaddr_in *receiver;	/* receiver's address -- me */
    MSG_DAT *m_data;		/* where to put message information */
{
    int i;
    unsigned KRB4_32 calc_cksum[4];
    unsigned KRB4_32 big_cksum[4];
    int le;

    u_char     *p,*q;
    int t;
    struct in_addr src_addr;
    unsigned KRB4_32 t_local;	/* Local time in our machine */
    KRB4_32 delta_t;		/* Difference between timestamps */

    /* Be very conservative */
    if (sizeof(src_addr.s_addr) != 4) {
#ifdef DEBUG
	fprintf(stderr, "\nkrb_rd_safe protocol err "
		"sizeof(src_addr.s_addr) != 4\n");
#endif
	return RD_AP_VERSION;
    }

    p = in;                     /* beginning of message */
#define IN_REMAIN (in_length - (p - in))
    if (IN_REMAIN < 1 + 1 + 4)
	return RD_AP_MODIFIED;

    if (*p++ != KRB_PROT_VERSION)
	return RD_AP_VERSION;
    t = *p++;
    if ((t & ~1) != AUTH_MSG_SAFE)
	return RD_AP_MSG_TYPE;
    le = t & 1;

    q = p;                      /* mark start of cksum stuff */

    /* safely get length */
    KRB4_GET32(m_data->app_length, p, le);

    if (IN_REMAIN < m_data->app_length + 1 + 4 + 4 + 4 * 4)
	return RD_AP_MODIFIED;

    m_data->app_data = p;       /* we're now at the application data */

    /* skip app data */
    p += m_data->app_length;

    /* safely get time_5ms */
    m_data->time_5ms = *p++;

    /* safely get src address */
    (void)memcpy(&src_addr.s_addr, p, sizeof(src_addr.s_addr));
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
    if (delta_t < 0) delta_t = -delta_t;  /* Absolute value of difference */
    if (delta_t > CLOCK_SKEW) {
        return(RD_AP_TIME);		/* XXX should probably be better
					   code */
    }

    /*
     * caller must check timestamps for proper order and replays, since
     * server might have multiple clients each with its own timestamps
     * and we don't assume tightly synchronized clocks.
     */

#ifdef NOENCRYPTION
    memset(calc_cksum, 0, sizeof(calc_cksum));
#else /* Do encryption */
    /* calculate the checksum of the length, timestamps, and
     * input data, on the sending byte order !! */
    quad_cksum(q,calc_cksum,p-q,2,key);
#endif /* NOENCRYPTION */

    for (i = 0; i < 4; i++)
	KRB4_GET32(big_cksum[i], p, le);

    DEB (("\n0: calc %l big %lx\n1: calc %lx big %lx\n2: calc %lx big %lx\n3: calc %lx big %lx\n",
               calc_cksum[0], big_cksum[0],
               calc_cksum[1], big_cksum[1],
               calc_cksum[2], big_cksum[2],
               calc_cksum[3], big_cksum[3]));
    for (i = 0; i < 4; i++)
	if (big_cksum[i] != calc_cksum[i])
	    return RD_AP_MODIFIED;

    return RD_AP_OK;		/* OK == 0 */
}
