/*
 * lib/krb4/prot_client.c
 *
 * Copyright 2001 by the Massachusetts Institute of Technology.  All
 * Rights Reserved.
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
 * Contains protocol encoders and decoders used by a krb4 client.
 */

#include "krb.h"
#include "prot.h"
#include <string.h>

/*
 * encode_kdc_request
 *
 * Packet format is originally from g_in_tkt.c.
 *
 * Size			Variable		Field
 * ----			--------		-----
 * 1 byte		KRB_PROT_VERSION	protocol version number
 * 1 byte		AUTH_MSG_KDC_REQUEST |	message type
 *			HOST_BYTE_ORDER		local byte order in lsb
 * string		user			client's name
 * string		instance		client's instance
 * string		realm			client's realm
 * 4 bytes		tlocal.tv_sec		timestamp in seconds
 * 1 byte		life			desired lifetime
 * string		service			service's name
 * string		sinstance		service's instance
 */
int KRB5_CALLCONV
krb4prot_encode_kdc_request(char *pname, char *pinst, char *prealm,
			    KRB4_32 tlocal, int life,
			    char *sname, char *sinst,
			    char *preauth, int preauthlen,
			    int chklen,	/* check input str len? */
			    int le, /* little-endian? */
			    KTEXT pkt)
{
    unsigned char *p;
    int ret;
    size_t snamelen, sinstlen;

    p = pkt->dat;

    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_KDC_REQUEST | !!le;

    ret = krb4prot_encode_naminstrlm(pname, pinst, prealm, chklen,
				     pkt, &p);
    if (ret)
	return ret;

    snamelen = strlen(sname) + 1;
    sinstlen = strlen(sinst) + 1;
    if (chklen && (snamelen > ANAME_SZ || sinstlen > INST_SZ))
	return KRB4PROT_ERR_OVERRUN;
    if ((sizeof(pkt->dat) - (p - pkt->dat))
	< (4 + 1 + snamelen + sinstlen + preauthlen))
	return KRB4PROT_ERR_OVERRUN;

    /* timestamp */
    KRB4_PUT32(p, tlocal, le);

    *p++ = life;

    memcpy(p, sname, snamelen);
    p += snamelen;
    memcpy(p, sinst, sinstlen);
    p += sinstlen;

    if (preauthlen)
	memcpy(p, preauth, (size_t)preauthlen);
    p += preauthlen;

    pkt->length = p - pkt->dat;
    return KRB4PROT_OK;
}

/*
 * decode_kdc_reply
 */
int KRB5_CALLCONV
krb4prot_decode_kdc_reply(KTEXT pkt,
			  int *le,
			  char *pname, char *pinst, char *prealm,
			  long *time_ws, int *n,
			  unsigned long *x_date, int *kvno,
			  KTEXT ciph)
{
    unsigned char *p;
    int msg_type;
    int ret;
    unsigned int ciph_len;

    p = pkt->dat;
    if (pkt->length < 2)
	return KRB4PROT_ERR_UNDERRUN;
    if (*p++ != KRB_PROT_VERSION)
	return KRB4PROT_ERR_PROT_VERS;
    msg_type = *p++;
    *le = msg_type & 1;
    msg_type &= ~1;
    if (msg_type != AUTH_MSG_KDC_REPLY)
	return KRB4PROT_ERR_MSG_TYPE;

    ret = krb4prot_decode_naminstrlm(ciph, &p, pname, pinst, prealm);
    if (ret)
	return ret;

#define PKT_REMAIN (pkt->length - (p - pkt->dat))

    if (PKT_REMAIN < (4		/* time */
		      + 1	/* number of tickets */
		      + 4	/* exp date */
		      + 1	/* kvno */
		      + 2))	/* ciph length */
	return KRB4PROT_ERR_UNDERRUN;
    if (time_ws != NULL)
	KRB4_GET32(*time_ws, p, *le); /* XXX signed/unsigned */
    else
	p += 4;
    if (n != NULL)
	*n = *p++;
    else
	p++;
    if (x_date != NULL)
	KRB4_GET32(*x_date, p, *le);
    else
	p += 4;
    if (kvno != NULL)
	*kvno = *p++;
    else
	p++;
    KRB4_GET16(ciph_len, p, *le);
    if (PKT_REMAIN < ciph_len)
	return KRB4PROT_ERR_UNDERRUN;
    ciph->length = ciph_len;
    memcpy(ciph->dat, p, (size_t)ciph->length);
    return KRB4PROT_OK;
#undef PKT_REMAIN
}

int KRB5_CALLCONV
krb4prot_decode_ciph(KTEXT ciph, int le,
		     C_Block session,
		     char *name, char *inst, char *realm,
		     int *life, int *kvno,
		     KTEXT tkt, unsigned long *kdc_time)
{
    unsigned char *p;
    int ret;

    p = ciph->dat;
    if (ciph->length < 8)
	return KRB4PROT_ERR_UNDERRUN;
    memcpy(session, p, 8);
    p += 8;
    ret = krb4prot_decode_naminstrlm(ciph, &p, name, inst, realm);
    if (ret)
	return ret;
#define CIPH_REMAIN (ciph->length - (p - ciph->dat))
    if (CIPH_REMAIN < (1	/* life */
		       + 1	/* kvno */
		       + 1))	/* tkt->length */
	return KRB4PROT_ERR_UNDERRUN;
    if (life != NULL)
	*life = *p++;
    else
	p++;
    if (kvno != NULL)
	*kvno = *p++;
    else
	p++;
    tkt->length = *p++;
    if (CIPH_REMAIN < (tkt->length
		       + 4))	/* kdc_time */
	return KRB4PROT_ERR_UNDERRUN;
    memcpy(tkt->dat, p, (size_t)tkt->length);
    p += tkt->length;

    if (kdc_time != NULL)
	KRB4_GET32(*kdc_time, p, le);

    return KRB4PROT_OK;
#undef CIPH_REMAIN
}

/*
 * encode_apreq
 *
 * The following was originally from mk_req.c.
 *
 * unsigned char	KRB_PROT_VERSION	protocol version no.
 * unsigned char	AUTH_MSG_APPL_REQUEST	message type
 * (least significant
 * bit of above)	HOST_BYTE_ORDER		local byte ordering
 * unsigned char	kvno from ticket	server's key version
 * string		realm			server's realm
 * unsigned char	tl			ticket length
 * unsigned char	idl			request id length
 * binary		ticket->dat		ticket for server
 * binary		req_id->dat		request id
 */
int KRB5_CALLCONV
krb4prot_encode_apreq(int kvno, char *realm,
		      KTEXT tkt, KTEXT req_id,
		      int chklen, /* check str len? */
		      int le,	/* little-endian? */
		      KTEXT pkt)
{
    unsigned char *p;
    size_t realmlen;

    p = pkt->dat;
    /* Assume >= 3 bytes in a KTEXT. */
    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_APPL_REQUEST | !!le;

    *p++ = kvno;

    realmlen = strlen(realm) + 1;
    if (chklen && realmlen > REALM_SZ)
	return KRB4PROT_ERR_OVERRUN;
    if (tkt->length > 255 || req_id->length > 255)
	return KRB4PROT_ERR_OVERRUN;
    if ((sizeof(pkt->dat) - (p - pkt->dat))
	< (realmlen
	   + 1			/* tkt->length */
	   + 1			/* req_id->length */
	   + tkt->length + req_id->length))
	return KRB4PROT_ERR_OVERRUN;

    memcpy(p, realm, realmlen);
    p += realmlen;

    *p++ = tkt->length;
    *p++ = req_id->length;
    memcpy(p, tkt->dat, (size_t)tkt->length);
    p += tkt->length;
    memcpy(p, req_id->dat, (size_t)req_id->length);
    p += req_id->length;

    pkt->length = p - pkt->dat;
    return KRB4PROT_OK;
}

/*
 * encode_authent
 *
 * Encodes an authenticator (called req_id in some of the code for
 * some weird reason).  Does not encrypt.
 *
 * The following packet layout is originally from mk_req.c.  It is
 * rounded up to the next multiple of 8 bytes.
 *
 * string		cr.pname		{name, instance, and
 * string		cr.pinst		realm of principal
 * string		myrealm			making this request}
 * 4 bytes		checksum		checksum argument given
 * unsigned char	time_usecs		time (microseconds)
 * 4 bytes		time_secs		time (seconds)
 */
int KRB5_CALLCONV
krb4prot_encode_authent(char *pname, char *pinst, char *prealm,
			KRB4_32 checksum,
			int time_usec, long time_sec,
			int chklen, /* check str lens? */
			int le,	/* little-endian? */
			KTEXT pkt)
{
    unsigned char *p;
    int ret;

    p = pkt->dat;
    ret = krb4prot_encode_naminstrlm(pname, pinst, prealm, chklen,
				     pkt, &p);
    if (ret)
	return ret;
    if ((sizeof(pkt->dat) - (p - pkt->dat)) / 8
	< (4			/* checksum */
	   + 1			/* microsec */
	   + 4			/* time */
	   + 7) / 8)		/* roundoff */
	return KRB4PROT_ERR_OVERRUN;

    KRB4_PUT32(p, checksum, le);
    *p++ = time_usec;
    KRB4_PUT32(p, time_sec, le);

    memset(p, 0, 7);		/* nul-pad */
    pkt->length = (((p - pkt->dat) + 7) / 8) * 8;
    return KRB4PROT_OK;
}

/*
 * decode_error
 *
 * Decodes an error reply from the KDC.
 */
int KRB5_CALLCONV
krb4prot_decode_error(KTEXT pkt, int *le,
		      char *pname, char *pinst, char *prealm,
		      unsigned long *time_ws,
		      unsigned long *err, char *err_string)
{
    unsigned char *p;
    int msg_type, ret, errstrlen;

    p = pkt->dat;
    if (pkt->length < 2)
	return KRB4PROT_ERR_UNDERRUN;
    if (*p++ != KRB_PROT_VERSION)
	return KRB4PROT_ERR_PROT_VERS;
    msg_type = *p++;
    *le = msg_type & 1;
    msg_type &= ~1;
    if (msg_type != AUTH_MSG_ERR_REPLY)
	return KRB4PROT_ERR_MSG_TYPE;

    ret = krb4prot_decode_naminstrlm(pkt, &p, pname, pinst, prealm);
    if (ret)
	return ret;

#define PKT_REMAIN (pkt->length - (p - pkt->dat))
    if (PKT_REMAIN < (4		/* time */
		      + 4))	/* err code */
	return KRB4PROT_ERR_UNDERRUN;

    if (time_ws != NULL)
	KRB4_GET32(*time_ws, p, le);
    else
	p += 4;
    if (err != NULL)
	KRB4_GET32(*err, p, le);
    else
	p += 4;

    if (PKT_REMAIN <= 0)	/* allow for missing error string */
	return KRB4PROT_OK;

    errstrlen = krb4int_strnlen((char *)p, PKT_REMAIN) + 1;
    if (errstrlen <= 0)		/* If it's there, it must be nul-terminated. */
	return KRB4PROT_ERR_OVERRUN;
    if (err_string != NULL)
	memcpy(err_string, p, (size_t)errstrlen);

    return KRB4PROT_OK;
#undef PKT_REMAIN
}
