/*
 * lib/krb4/g_in_tkt.c
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
 */

#include "krb.h"
#include "des.h"
#include "prot.h"

#include <string.h>

/* Define a couple of function types including parameters.  These
   are needed on MS-Windows to convert arguments of the function pointers
   to the proper types during calls.  These declarations are found
   in <krb-sed.h>, but the code below is too opaque if you can't also
   see them here.  */
#ifndef	KEY_PROC_TYPE_DEFINED
typedef int (*key_proc_type) PROTOTYPE ((char *, char *, char *,
					     char *, C_Block));
#endif
#ifndef	DECRYPT_TKT_TYPE_DEFINED
typedef int (*decrypt_tkt_type) PROTOTYPE ((char *, char *, char *, char *,
				     key_proc_type, KTEXT *));
#endif

/*
 * decrypt_tkt(): Given user, instance, realm, passwd, key_proc
 * and the cipher text sent from the KDC, decrypt the cipher text
 * using the key returned by key_proc.
 */

static int
decrypt_tkt(user, instance, realm, arg, key_proc, cipp)
    char *user;
    char *instance;
    char *realm;
    char *arg;
    key_proc_type key_proc;
    KTEXT *cipp;
{
    KTEXT cip = *cipp;
    C_Block key;		/* Key for decrypting cipher */
    Key_schedule key_s;
    register int rc;

#ifndef NOENCRYPTION
    /* Attempt to decrypt it */
#endif
    /* generate a key from the supplied arg or password.  */
    rc = (*key_proc)(user, instance, realm, arg, key);
    if (rc)
	return rc;

#ifndef NOENCRYPTION
    key_sched(key, key_s);
    pcbc_encrypt((C_Block *)cip->dat, (C_Block *)cip->dat,
		 (long)cip->length, key_s, (C_Block *)key, 0);
#endif /* !NOENCRYPTION */
    /* Get rid of all traces of key */
    memset(key, 0, sizeof(key));
    memset(key_s, 0, sizeof(key_s));

    return 0;
}

/*
 * krb_get_in_tkt() gets a ticket for a given principal to use a given
 * service and stores the returned ticket and session key for future
 * use.
 *
 * The "user", "instance", and "realm" arguments give the identity of
 * the client who will use the ticket.  The "service" and "sinstance"
 * arguments give the identity of the server that the client wishes
 * to use.  (The realm of the server is the same as the Kerberos server
 * to whom the request is sent.)  The "life" argument indicates the
 * desired lifetime of the ticket; the "key_proc" argument is a pointer
 * to the routine used for getting the client's private key to decrypt
 * the reply from Kerberos.  The "decrypt_proc" argument is a pointer
 * to the routine used to decrypt the reply from Kerberos; and "arg"
 * is an argument to be passed on to the "key_proc" routine.
 *
 * If all goes well, krb_get_in_tkt() returns INTK_OK, otherwise it
 * returns an error code:  If an AUTH_MSG_ERR_REPLY packet is returned
 * by Kerberos, then the error code it contains is returned.  Other
 * error codes returned by this routine include INTK_PROT to indicate
 * wrong protocol version, INTK_BADPW to indicate bad password (if
 * decrypted ticket didn't make sense), INTK_ERR if the ticket was for
 * the wrong server or the ticket store couldn't be initialized.
 *
 * The format of the message sent to Kerberos is as follows:
 *
 * Size			Variable		Field
 * ----			--------		-----
 *
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

int
krb_mk_in_tkt_preauth(user, instance, realm, service, sinstance, life,
		      preauth_p, preauth_len, cip, byteorder)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    char *preauth_p;
    int   preauth_len;
    KTEXT cip;
    int  *byteorder;
{
    KTEXT_ST pkt_st;
    KTEXT pkt = &pkt_st;	/* Packet to KDC */
    KTEXT_ST rpkt_st;
    KTEXT rpkt = &rpkt_st;	/* Returned packet */
    unsigned char *p;
    size_t userlen, instlen, realmlen, servicelen, sinstlen;
    unsigned KRB4_32 t_local;

    int msg_byte_order;
    int kerror;
#if 0
    unsigned long exp_date;
#endif
    unsigned long rep_err_code;
    unsigned long cip_len;
    unsigned int t_switch;
    int i, len;

    /* BUILD REQUEST PACKET */

    p = pkt->dat;

    userlen = strlen(user) + 1;
    instlen = strlen(instance) + 1;
    realmlen = strlen(realm) + 1;
    servicelen = strlen(service) + 1;
    sinstlen = strlen(sinstance) + 1;
    /* Make sure the ticket data will fit into the buffer. */
    if (sizeof(pkt->dat) < (1 + 1 + userlen + instlen + realmlen
			    + 4 + 1 + servicelen + sinstlen
			    + preauth_len)) {
        pkt->length = 0;
	return INTK_ERR;
    }

    /* Set up the fixed part of the packet */
    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_KDC_REQUEST;

    /* Now for the variable info */
    memcpy(p, user, userlen);
    p += userlen;
    memcpy(p, instance, instlen);
    p += instlen;
    memcpy(p, realm, realmlen);
    p += realmlen;

    /* timestamp */
    t_local = TIME_GMT_UNIXSEC;
    KRB4_PUT32(p, t_local);

    *p++ = life;

    memcpy(p, service, servicelen);
    p += servicelen;
    memcpy(p, sinstance, sinstlen);
    p += sinstlen;

    if (preauth_len)
	memcpy(p, preauth_p, (size_t)preauth_len);
    p += preauth_len;

    pkt->length = p - pkt->dat;

    /* SEND THE REQUEST AND RECEIVE THE RETURN PACKET */
    rpkt->length = 0;
    kerror = send_to_kdc(pkt, rpkt, realm);
    if (kerror)
	return kerror;

    p = rpkt->dat;
#define RPKT_REMAIN (rpkt->length - (p - rpkt->dat))

    /* check packet version of the returned packet */
    if (RPKT_REMAIN < 1 + 1)
	return INTK_PROT;
    if (*p++ != KRB_PROT_VERSION)
        return INTK_PROT;

    /* This used to be
         switch (pkt_msg_type(rpkt) & ~1) {
       but SCO 3.2v4 cc compiled that incorrectly.  */
    t_switch = *p++;
    /* Check byte order */
    msg_byte_order = t_switch & 1;
    t_switch &= ~1;
    switch (t_switch) {
    case AUTH_MSG_KDC_REPLY:
        break;
    case AUTH_MSG_ERR_REPLY:
	if (RPKT_REMAIN < 4)
	    return INTK_PROT;
	KRB4_GET32(rep_err_code, p, msg_byte_order);
	return rep_err_code;
    default:
        return INTK_PROT;
    }

    /* EXTRACT INFORMATION FROM RETURN PACKET */

    /*
     * Skip over some stuff (3 strings and various integers -- see
     * cr_auth_repl.c for details).
     */
    for (i = 0; i < 3; i++) {
	len = krb_strnlen((char *)p, RPKT_REMAIN) + 1;
	if (len <= 0)
	    return INTK_PROT;
	p += len;
    }
    if (RPKT_REMAIN < 4 + 1 + 4 + 1)
	return INTK_PROT;
    p += 4 + 1 + 4 + 1;

    /* Extract the ciphertext */
    if (RPKT_REMAIN < 2)
	return INTK_PROT;
    KRB4_GET16(cip_len, p, msg_byte_order);
    if (RPKT_REMAIN < cip_len)
	return INTK_ERR;
    /*
     * RPKT_REMAIN will always be non-negative and at most the maximum
     * possible value of cip->length, so this assignment is safe.
     */
    cip->length = cip_len;
    memcpy(cip->dat, p, (size_t)cip->length);
    p += cip->length;

    *byteorder = msg_byte_order;
    return INTK_OK;
}

int
krb_parse_in_tkt(user, instance, realm, service, sinstance, life, cip,
		 byteorder)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    KTEXT cip;
    int byteorder;
{
    unsigned char *ptr;
    C_Block ses;                /* Session key for tkt */
    int len;
    int kvno;			/* Kvno for session key */
    char s_name[SNAME_SZ];
    char s_instance[INST_SZ];
    char rlm[REALM_SZ];
    KTEXT_ST tkt_st;
    KTEXT tkt = &tkt_st;	/* Current ticket */
    unsigned long kdc_time;   /* KDC time */
    unsigned KRB4_32 t_local;	/* Must be 4 bytes long for memcpy below! */
    KRB4_32 t_diff;	/* Difference between timestamps */
    int kerror;
    int lifetime;

    ptr = cip->dat;
    /* Assume that cip->length >= 0 for now. */
#define CIP_REMAIN (cip->length - (ptr - cip->dat))

    /* Skip session key for now */
    if (CIP_REMAIN < 8)
	return INTK_BADPW;
    ptr += 8;

    /* extract server's name */
    len = krb_strnlen((char *)ptr, CIP_REMAIN) + 1;
    if (len <= 0 || len > sizeof(s_name))
	return INTK_BADPW;
    memcpy(s_name, ptr, (size_t)len);
    ptr += len;

    /* extract server's instance */
    len = krb_strnlen((char *)ptr, CIP_REMAIN) + 1;
    if (len <= 0 || len > sizeof(s_instance))
	return INTK_BADPW;
    memcpy(s_instance, ptr, (size_t)len);
    ptr += len;

    /* extract server's realm */
    len = krb_strnlen((char *)ptr, CIP_REMAIN) + 1;
    if (len <= 0 || len > sizeof(rlm))
	return INTK_BADPW;
    memcpy(rlm, ptr, (size_t)len);
    ptr += len;

    /* extract ticket lifetime, server key version, ticket length */
    /* be sure to avoid sign extension on lifetime! */
    if (CIP_REMAIN < 3)
	return INTK_BADPW;
    lifetime = *ptr++;
    kvno = *ptr++;
    tkt->length = *ptr++;

    /* extract ticket itself */
    if (CIP_REMAIN < tkt->length)
	return INTK_BADPW;
    memcpy(tkt->dat, ptr, (size_t)tkt->length);
    ptr += tkt->length;

    if (strcmp(s_name, service) || strcmp(s_instance, sinstance)
	|| strcmp(rlm, realm))	/* not what we asked for */
	return INTK_ERR;	/* we need a better code here XXX */

    /* check KDC time stamp */
    if (CIP_REMAIN < 4)
	return INTK_BADPW;
    KRB4_GET32(kdc_time, ptr, byteorder);

    t_local = TIME_GMT_UNIXSEC;
    t_diff = t_local - kdc_time;
    if (t_diff < 0)
	t_diff = -t_diff;	/* Absolute value of difference */
    if (t_diff > CLOCK_SKEW) {
        return RD_AP_TIME;	/* XXX should probably be better code */
    }

    /* initialize ticket cache */
    if (in_tkt(user,instance) != KSUCCESS)
	return INTK_ERR;
    /* stash ticket, session key, etc. for future use */
    memcpy(ses, cip->dat, 8);
    kerror = krb_save_credentials(s_name, s_instance, rlm, ses,
				  lifetime, kvno,
				  tkt, (KRB4_32)t_local);
    memset(ses, 0, 8);
    if (kerror)
	return kerror;

    return INTK_OK;
}

int
krb_get_in_tkt_preauth(user, instance, realm, service, sinstance, life,
		       key_proc, decrypt_proc, arg, preauth_p, preauth_len)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    key_proc_type key_proc;
    decrypt_tkt_type decrypt_proc;
    char *arg;
    char *preauth_p;
    int   preauth_len;
{
    KTEXT_ST cip_st;
    KTEXT cip = &cip_st;	/* Returned Ciphertext */
    int kerror;
    int byteorder;

    kerror = krb_mk_in_tkt_preauth(user, instance, realm, 
				   service, sinstance,
				   life, preauth_p, preauth_len,
				   cip, &byteorder);
    if (kerror)
	return kerror;
    /* Attempt to decrypt the reply. */
    if (decrypt_proc == NULL)
	decrypt_tkt (user, instance, realm, arg, key_proc, &cip);
    else
	(*decrypt_proc)(user, instance, realm, arg, key_proc, &cip);

    kerror = krb_parse_in_tkt(user, instance, realm,
			      service, sinstance,
			      life, cip, byteorder);
    /* stomp stomp stomp */
    memset(cip->dat, 0, (size_t)cip->length);
    return kerror;
}

int
krb_get_in_tkt(user, instance, realm, service, sinstance, life,
               key_proc, decrypt_proc, arg)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    key_proc_type key_proc;
    decrypt_tkt_type decrypt_proc;
    char *arg;
{
    return krb_get_in_tkt_preauth(user, instance, realm,
				  service, sinstance, life,
			   	  key_proc, decrypt_proc, arg,
				  (char *)NULL, 0);
}
