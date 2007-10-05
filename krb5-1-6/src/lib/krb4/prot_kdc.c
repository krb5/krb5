/*
 * lib/krb4/prot_kdc.c
 *
 * Copyright 1985--1988, 2000, 2001 by the Massachusetts Institute of
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
 * Contains the protocol encoders and decoders used by the KDC.
 */

#include "krb.h"
#include "prot.h"
#include <string.h>
#include "port-sockets.h"

/*
 * encode_kdc_reply
 *
 * Encodes a reply from the KDC to the client.
 *
 * Returns KRB4PROT_OK on success, non-zero on failure.
 *
 * Caller is responsible for cleaning up OUTBUF.
 *
 * This packet layout description was originally in cr_auth_repl.c:
 *
 * 			variable
 * type			or constant	   data
 * ----			-----------	   ----
 * unsigned char	KRB_PROT_VERSION   protocol version number
 * 
 * unsigned char	AUTH_MSG_KDC_REPLY protocol message type
 * 
 * [least significant	HOST_BYTE_ORDER	   sender's (server's) byte
 *  bit of above field]			   order
 * 
 * string		pname		   principal's name
 * 
 * string		pinst		   principal's instance
 * 
 * string		prealm		   principal's realm
 * 
 * unsigned long	time_ws		   client's timestamp
 * 
 * unsigned char	n		   number of tickets
 * 
 * unsigned long	x_date		   expiration date
 * 
 * unsigned char	kvno		   master key version
 * 
 * short		cipher->length	   cipher length
 * 
 * binary		cipher->dat	   cipher data
 */
int KRB5_CALLCONV
krb4prot_encode_kdc_reply(char *pname, char *pinst, char *prealm,
			  long time_ws,
			  int n, /* Number of tickets; 0 for krb4 (!) */
			  unsigned long x_date,	/* exp date */
			  int kvno,
			  KTEXT cipher,	/* encrypted ticket */
			  int chklen, /* check input str len? */
			  int le, /* little-endian? */
			  KTEXT outbuf)
{
    unsigned char *p;
    int ret;

    p = outbuf->dat;
    /* This is really crusty. */
    if (n != 0)
	*p++ = 3;
    else
	*p++ = KRB_PROT_VERSION;
    /* little-endianness based on input, usually big-endian, though. */
    *p++ = AUTH_MSG_KDC_REPLY | !!le;

    ret = krb4prot_encode_naminstrlm(pname, pinst, prealm, chklen,
				     outbuf, &p);
    if (ret)
	return ret;

    /* Check lengths */
    if (cipher->length > 65535 || cipher->length < 0)
	return KRB4PROT_ERR_OVERRUN;
    if ((sizeof(outbuf->dat) - (p - outbuf->dat)
	 < (4			/* timestamp */
	    + 1			/* num of tickets */
	    + 4			/* exp date */
	    + 1			/* kvno */
	    + 2			/* cipher->length */
	    + cipher->length)))	/* cipher->dat */
        return KRB4PROT_ERR_OVERRUN;

    /* Workstation timestamp */
    KRB4_PUT32(p, time_ws, le);

    /* Number of tickets */
    *p++ = n;

    /* Expiration date */
    KRB4_PUT32(p, x_date, le);

    /* Now send the ciphertext and info to help decode it */
    *p++ = kvno;
    KRB4_PUT16(p, cipher->length, le);
    memcpy(p, cipher->dat, (size_t)cipher->length);
    p += cipher->length;

    /* And return the packet */
    outbuf->length = p - outbuf->dat;
    return KRB4PROT_OK;
}

/*
 * encode_ciph
 *
 * Encodes a "cipher" that is to be included in a KDC reply message.
 *
 * Caller is responsible for cleaning up CIPH.
 *
 * Returns KRB4PROT_OK on success, non-zero on failure.
 *
 * Packet format below is originally from cr_ciph.c:
 *
 * 			variable
 * type			or constant	data
 * ----			-----------	----
 * 8 bytes		session		session key for client, service
 * 
 * string		service		service name
 * 
 * string		instance	service instance
 * 
 * string		realm		KDC realm
 * 
 * unsigned char	life		ticket lifetime
 * 
 * unsigned char	kvno		service key version number
 * 
 * unsigned char	tkt->length	length of following ticket
 * 
 * data			tkt->dat	ticket for service
 * 
 * 4 bytes		kdc_time	KDC's timestamp
 *
 * <=7 bytes		null		null pad to 8 byte multiple
 */
int KRB5_CALLCONV
krb4prot_encode_ciph(C_Block session,
		     char *name, char *inst, char *realm,
		     unsigned long life, int kvno,
		     KTEXT tkt,	/* ticket */
		     unsigned long kdc_time,
		     int chklen, /* check str lens? */
		     int le,	/* little-endian? */
		     KTEXT ciph) /* output buffer */
{
    unsigned char *p;
    int ret;

    p = ciph->dat;
    /*
     * Assume that there will be >= 8 bytes in a KTEXT.  If there
     * aren't, we have worse problems.
     */
    memcpy(p, session, 8);
    p += 8;

    ret = krb4prot_encode_naminstrlm(name, inst, realm, chklen,
				     ciph, &p);
    if (ret)
	return ret;
    if (tkt->length > 255 || tkt->length < 0)
	return KRB4PROT_ERR_OVERRUN;
    if ((sizeof(ciph->dat) - (p - ciph->dat)) / 8
	< (1			/* life */
	   + 1			/* kvno */
	   + 1			/* tkt->length */
	   + tkt->length	/* tkt->dat */
	   + 4			/* kdc_time */
	   + 7) / 8)		/* roundoff */
	return KRB4PROT_ERR_OVERRUN;

    *p++ = life;
    *p++ = kvno;
    *p++ = tkt->length;

    memcpy(p, tkt->dat, (size_t)tkt->length);
    p += tkt->length;

    KRB4_PUT32(p, kdc_time, le);

    /* Guarantee null pad to multiple of 8 bytes */
    memset(p, 0, 7);
    ciph->length = (((p - ciph->dat) + 7) / 8) * 8;
    return KRB4PROT_OK;
}

/*
 * encode_tkt
 *
 * Encode ticket to include in a "cipher".  Does not encrypt.
 *
 * Caller is responsible for cleaning TKT.
 *
 * The length of the ticket is a multiple of
 * eight bytes and is in tkt->length.
 *
 * If the ticket is not a multiple of eight bytes long, the ticket
 * will contain nulls.
 *
 * Returns KRB4PROT_OK on success, non-zero on failure.
 *
 * The following packet layout is from cr_tkt.c:
 *
 * 			variable
 * type			or constant	   data
 * ----			-----------	   ----
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
 */
int KRB5_CALLCONV
krb4prot_encode_tkt(unsigned int flags,
		    char *pname, char *pinst, char *prealm,
		    unsigned long paddress,
		    char *session,
		    int life, long time_sec,
		    char *sname, char *sinst,
		    int chklen,	/* check str lens? */
		    int le,	/* little-endian? */
		    KTEXT tkt)	/* output buf */
{
    struct in_addr paddr;
    unsigned char *p;
    size_t snamelen, sinstlen;

    /* Be really paranoid. */
    if (sizeof(paddr.s_addr) != 4)
	return KFAILURE;

    p = tkt->dat;
    /*
     * Assume at least one byte in a KTEXT.  If not, we have bigger
     * problems.  Also, bitwise-OR in the little-endian flag.
     */
    *p++ = flags | !!le;

    if (krb4prot_encode_naminstrlm(pname, pinst, prealm, chklen,
				   tkt, &p))
	return KFAILURE;

    snamelen = strlen(sname) + 1;
    sinstlen = strlen(sinst) + 1;
    if (life > 255 || life < 0)
	return KFAILURE;
    if (chklen && (snamelen > ANAME_SZ || sinstlen > INST_SZ))
	return KFAILURE;
    if ((sizeof(tkt->dat) - (p - tkt->dat)) / 8
	< (4			/* address */
	   + 8			/* session */
	   + 1			/* life */
	   + 4			/* issue time */
	   + snamelen + sinstlen
	   + 7) / 8)		/* roundoff */
        return KFAILURE;

    paddr.s_addr = paddress;
    memcpy(p, &paddr.s_addr, sizeof(paddr.s_addr));
    p += sizeof(paddr.s_addr);

    memcpy(p, session, 8);
    p += 8;
    *p++ = life;
    /* issue time */
    KRB4_PUT32(p, time_sec, le);

    memcpy(p, sname, snamelen);
    p += snamelen;
    memcpy(p, sinst, sinstlen);
    p += sinstlen;

    /* guarantee null padded ticket to multiple of 8 bytes */
    memset(p, 0, 7);
    tkt->length = ((p - tkt->dat + 7) / 8) * 8;
    return KSUCCESS;
}

/*
 * encode_err_reply
 *
 * Encode an error reply message from the KDC to the client.
 *
 * Returns KRB4PROT_OK on success, non-zero on error.
 *
 * The following packet layout description is from cr_err_repl.c:
 * 
 * type			variable	   data
 *			or constant
 * ----			-----------	   ----
 * unsigned char	req_ack_vno	   protocol version number
 * 
 * unsigned char	AUTH_MSG_ERR_REPLY protocol message type
 * 
 * [least significant	HOST_BYTE_ORDER	   sender's (server's) byte
 * bit of above field]			   order
 * 
 * string		pname		   principal's name
 * 
 * string		pinst		   principal's instance
 * 
 * string		prealm		   principal's realm
 * 
 * unsigned long	time_ws		   client's timestamp
 * 
 * unsigned long	e		   error code
 * 
 * string		e_string	   error text
 */
int KRB5_CALLCONV
krb4prot_encode_err_reply(char *pname, char *pinst, char *prealm,
			  unsigned long time_ws,
			  unsigned long err, /* error code */
			  char *err_string, /* error text */
			  int chklen, /* check str lens? */
			  int le, /* little-endian? */
			  KTEXT pkt) /* output buf */
{
    unsigned char *p;
    size_t err_stringlen;

    p = pkt->dat;
    /* Assume >= 2 bytes in KTEXT. */
    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_ERR_REPLY | !!le;

    if (krb4prot_encode_naminstrlm(pname, pinst, prealm, chklen,
				   pkt, &p))
	return KFAILURE;

    err_stringlen = strlen(err_string) + 1;
    if ((sizeof(pkt->dat) - (p - pkt->dat))
	< (4			/* timestamp */
	   + 4			/* err code */
	   + err_stringlen))
	return KFAILURE;
    /* ws timestamp */
    KRB4_PUT32(p, time_ws, le);
    /* err code */
    KRB4_PUT32(p, err, le);
    /* err text */
    memcpy(p, err_string, err_stringlen);
    p += err_stringlen;

    /* And return */
    pkt->length = p - pkt->dat;
    return KSUCCESS;
}

/*
 * decode_kdc_request
 *
 * Decode an initial ticket request sent from the client to the KDC.
 *
 * Packet format is described in g_in_tkt.c.
 *
 * Returns KRB4PROT_OK on success, non-zero on failure.
 */
int KRB5_CALLCONV
krb4prot_decode_kdc_request(KTEXT pkt,
			    int *le,
			    char *pname, char *pinst, char *prealm,
			    long *req_time, int *life,
			    char *sname, char *sinst)
{
    unsigned char *p;
    int msg_type, ret, len;

    p = pkt->dat;

    /* Get prot vers and msg type */
    if (pkt->length < 2)
	return KRB4PROT_ERR_UNDERRUN;
    if (*p++ != KRB_PROT_VERSION)
	return KRB4PROT_ERR_PROT_VERS;
    msg_type = *p++;
    *le = msg_type & 1;
    msg_type &= ~1;
    if (msg_type != AUTH_MSG_KDC_REQUEST)
	return KRB4PROT_ERR_MSG_TYPE;

    ret = krb4prot_decode_naminstrlm(pkt, &p, pname, pinst, prealm);
    if (ret)
	return ret;

#define PKT_REMAIN (pkt->length - (p - pkt->dat))

    if (PKT_REMAIN < (4		/* time */
		      + 1))	/* life */
	return KRB4PROT_ERR_UNDERRUN;

    KRB4_GET32(*req_time, p, *le);

    *life = *p++;

    if (PKT_REMAIN <= 0)
	return KRB4PROT_ERR_UNDERRUN;
    len = krb4int_strnlen((char *)p, PKT_REMAIN) + 1;
    if (len <= 0 || len > ANAME_SZ)
	return KRB4PROT_ERR_OVERRUN;
    memcpy(sname, p, (size_t)len);
    p += len;

    if (PKT_REMAIN <= 0)
	return KRB4PROT_ERR_UNDERRUN;
    len = krb4int_strnlen((char *)p, PKT_REMAIN) + 1;
    if (len <= 0 || len > INST_SZ)
	return KRB4PROT_ERR_OVERRUN;
    memcpy(sinst, p, (size_t)len);
    p += len;

    /* XXX krb4 preauth? */
    return KRB4PROT_OK;
}
