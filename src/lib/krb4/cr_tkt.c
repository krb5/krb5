/*
 * lib/krb4/cr_tkt.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2000 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
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
 */

#include <krb5.h>
#include "des.h"
#include "krb.h"
#include "prot.h"
#include <string.h>
#include "port-sockets.h"

static int
krb_cr_tkt_int (KTEXT tkt, unsigned int flags_in, char *pname, 
		char *pinstance, char *prealm, long paddress,
		char *session, int life, long time_sec, 
		char *sname, char *sinstance);

/*
 * Create ticket takes as arguments information that should be in a
 * ticket, and the KTEXT object in which the ticket should be
 * constructed.  It then constructs a ticket and returns, leaving the
 * newly created ticket in tkt.
#ifndef NOENCRYPTION
 * The data in tkt->dat is encrypted in the server's key.
#endif
 * The length of the ticket is a multiple of
 * eight bytes and is in tkt->length.
 *
 * If the ticket is too long, the ticket will contain nulls.
 * The return value of the routine is undefined.
 *
 * The corresponding routine to extract information from a ticket it
 * decomp_ticket.  When changes are made to this routine, the
 * corresponding changes should also be made to that file.
 *
 * The packet is built in the following format:
 * 
 * 			variable
 * type			or constant	   data
 * ----			-----------	   ----
 *
 * tkt->length		length of ticket (multiple of 8 bytes)
 * 
#ifdef NOENCRYPTION
 * tkt->dat:
#else
 * tkt->dat:		(encrypted in server's key)
#endif
 * 
 * unsigned char	flags		   namely, HOST_BYTE_ORDER
 * 
 * string		pname		   client's name
 * 
 * string		pinstance	   client's instance
 * 
 * string		prealm		   client's realm
 * 
 * 4 bytes		paddress	   client's address
 * 
 * 8 bytes		session		   session key
 * 
 * 1 byte		life		   ticket lifetime
 * 
 * 4 bytes		time_sec	   KDC timestamp
 * 
 * string		sname		   service's name
 * 
 * string		sinstance	   service's instance
 * 
 * <=7 bytes		null		   null pad to 8 byte multiple
 *
 */
int
krb_create_ticket(tkt, flags, pname, pinstance, prealm, paddress,
		  session, life, time_sec, sname, sinstance, key)
    KTEXT   tkt;                /* Gets filled in by the ticket */
    unsigned int flags;         /* Various Kerberos flags */
    char    *pname;             /* Principal's name */
    char    *pinstance;         /* Principal's instance */
    char    *prealm;            /* Principal's authentication domain */
    long    paddress;           /* Net address of requesting entity */
    char    *session;           /* Session key inserted in ticket */
    int     life;               /* Lifetime of the ticket */
    long    time_sec;           /* Issue time and date */
    char    *sname;             /* Service Name */
    char    *sinstance;         /* Instance Name */
    C_Block key;                /* Service's secret key */
{
    int kerr;
    Key_schedule key_s;

    kerr = krb_cr_tkt_int(tkt, flags, pname, pinstance, prealm, paddress,
			  session, life, time_sec, sname, sinstance);
    if (kerr)
	return kerr;

    /* Encrypt the ticket in the services key */
    key_sched(key, key_s);
    pcbc_encrypt((C_Block *)tkt->dat, (C_Block *)tkt->dat,
		 (long)tkt->length, key_s, (C_Block *)key, 1);
    memset(key_s, 0, sizeof(key_s));
    return 0;
}

int
krb_cr_tkt_krb5(tkt, flags, pname, pinstance, prealm, paddress,
		  session, life, time_sec, sname, sinstance, k5key)
    KTEXT   tkt;                /* Gets filled in by the ticket */
    unsigned int flags;         /* Various Kerberos flags */
    char    *pname;             /* Principal's name */
    char    *pinstance;         /* Principal's instance */
    char    *prealm;            /* Principal's authentication domain */
    long    paddress;           /* Net address of requesting entity */
    char    *session;           /* Session key inserted in ticket */
    int     life;               /* Lifetime of the ticket */
    long    time_sec;           /* Issue time and date */
    char    *sname;             /* Service Name */
    char    *sinstance;         /* Instance Name */
    krb5_keyblock *k5key;	/* NULL if not present */
{
    int kerr;
    krb5_data in;
    krb5_enc_data out;
    krb5_error_code ret;
    size_t enclen;

    kerr = krb_cr_tkt_int(tkt, flags, pname, pinstance, prealm,
			  paddress, session, life, time_sec,
			  sname, sinstance);
    if (kerr)
	return kerr;

    /* Encrypt the ticket in the services key */
    in.length = tkt->length;
    in.data = (char *)tkt->dat;
    /* XXX assumes context arg is ignored */
    ret = krb5_c_encrypt_length(NULL, k5key->enctype,
				(size_t)in.length, &enclen);
    if (ret)
	return KFAILURE;
    out.ciphertext.length = enclen;
    out.ciphertext.data = malloc(enclen);
    if (out.ciphertext.data == NULL)
	return KFAILURE;	/* XXX maybe ENOMEM? */

    /* XXX assumes context arg is ignored */
    ret = krb5_c_encrypt(NULL, k5key, KRB5_KEYUSAGE_KDC_REP_TICKET,
			 NULL, &in, &out);
    if (ret) {
	free(out.ciphertext.data);
	return KFAILURE;
    } else {
	tkt->length = out.ciphertext.length;
	memcpy(tkt->dat, out.ciphertext.data, out.ciphertext.length);
	memset(out.ciphertext.data, 0, out.ciphertext.length);
	free(out.ciphertext.data);
    }
    return 0;
}

static int
krb_cr_tkt_int(tkt, flags_in, pname, pinstance, prealm, paddress,
	       session, life, time_sec, sname, sinstance)
    KTEXT   tkt;                /* Gets filled in by the ticket */
    unsigned int flags_in;      /* Various Kerberos flags */
    char    *pname;             /* Principal's name */
    char    *pinstance;         /* Principal's instance */
    char    *prealm;            /* Principal's authentication domain */
    long    paddress;           /* Net address of requesting entity */
    char    *session;           /* Session key inserted in ticket */
    int     life;               /* Lifetime of the ticket */
    long    time_sec;           /* Issue time and date */
    char    *sname;             /* Service Name */
    char    *sinstance;         /* Instance Name */
{
    register unsigned char *data; /* running index into ticket */
    size_t pnamelen, pinstlen, prealmlen, snamelen, sinstlen;
    struct in_addr paddr;

    /* Be really paranoid. */
    if (sizeof(paddr.s_addr) != 4)
	return KFAILURE;

    tkt->length = 0;            /* Clear previous data  */

    /* Check length of ticket */
    pnamelen = strlen(pname) + 1;
    pinstlen = strlen(pinstance) + 1;
    prealmlen = strlen(prealm) + 1;
    snamelen = strlen(sname) + 1;
    sinstlen = strlen(sinstance) + 1;
    if (sizeof(tkt->dat) / 8 < ((1 + pnamelen + pinstlen + prealmlen
				 + 4 /* address */
				 + 8 /* session */
				 + 1 /* life */
				 + 4 /* issue time */
				 + snamelen + sinstlen
				 + 7) / 8) /* roundoff */
	|| life > 255 || life < 0) {
        memset(tkt->dat, 0, sizeof(tkt->dat));
        return KFAILURE /* XXX */;
    }

    data = tkt->dat;
    *data++ = flags_in;
    memcpy(data, pname, pnamelen);
    data += pnamelen;
    memcpy(data, pinstance, pinstlen);
    data += pinstlen;
    memcpy(data, prealm, prealmlen);
    data += prealmlen;

    paddr.s_addr = paddress;
    memcpy(data, &paddr.s_addr, sizeof(paddr.s_addr));
    data += sizeof(paddr.s_addr);

    memcpy(data, session, 8);
    data += 8;
    *data++ = life;
    /* issue time */
    KRB4_PUT32BE(data, time_sec);

    memcpy(data, sname, snamelen);
    data += snamelen;
    memcpy(data, sinstance, sinstlen);
    data += sinstlen;

    /* guarantee null padded ticket to multiple of 8 bytes */
    memset(data, 0, 7);
    tkt->length = ((data - tkt->dat + 7) / 8) * 8;
    return 0;
}
