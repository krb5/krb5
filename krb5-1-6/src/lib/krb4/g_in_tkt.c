/*
 * lib/krb4/g_in_tkt.c
 *
 * Copyright 1986-2002 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
#include "krb4int.h"
#include "prot.h"

#include "port-sockets.h"
#include <string.h>

/* Define a couple of function types including parameters.  These
   are needed on MS-Windows to convert arguments of the function pointers
   to the proper types during calls.  These declarations are found
   in <krb-sed.h>, but the code below is too opaque if you can't also
   see them here.  */
#ifndef	KEY_PROC_TYPE_DEFINED
typedef int (*key_proc_type) (char *, char *, char *,
					     char *, C_Block);
#endif
#ifndef	DECRYPT_TKT_TYPE_DEFINED
typedef int (*decrypt_tkt_type) (char *, char *, char *, char *,
				     key_proc_type, KTEXT *);
#endif

static int decrypt_tkt(char *, char *, char *, char *, key_proc_type, KTEXT *);
static int krb_mk_in_tkt_preauth(char *, char *, char *, char *, char *,
				 int, char *, int, KTEXT, int *, struct sockaddr_in *);			
static int krb_parse_in_tkt_creds(char *, char *, char *, char *, char *,
				  int, KTEXT, int, CREDENTIALS *);

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

static int
krb_mk_in_tkt_preauth(user, instance, realm, service, sinstance, life,
		      preauth_p, preauth_len, cip, byteorder, local_addr)
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
    struct sockaddr_in *local_addr;
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
    socklen_t addrlen;
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
    KRB4_PUT32BE(p, t_local);

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
    addrlen = sizeof(struct sockaddr_in);
    kerror = krb4int_send_to_kdc_addr(pkt, rpkt, realm,
				      (struct sockaddr *)local_addr,
				      &addrlen);
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

    /* EXTRACT INFORMATION FROM RETURN PACKET */

    /*
     * Skip over some stuff (3 strings and various integers -- see
     * cr_auth_repl.c for details).
     */
    for (i = 0; i < 3; i++) {
	len = krb4int_strnlen((char *)p, RPKT_REMAIN) + 1;
	if (len <= 0)
	    return INTK_PROT;
	p += len;
    }
    switch (t_switch) {
    case AUTH_MSG_KDC_REPLY:
	if (RPKT_REMAIN < 4 + 1 + 4 + 1)
	    return INTK_PROT;
	p += 4 + 1 + 4 + 1;
        break;
    case AUTH_MSG_ERR_REPLY:
	if (RPKT_REMAIN < 8)
	    return INTK_PROT;
	p += 4;
	KRB4_GET32(rep_err_code, p, msg_byte_order);
	return rep_err_code;
    default:
        return INTK_PROT;
    }

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

static int
krb_parse_in_tkt_creds(user, instance, realm, service, sinstance, life, cip,
		       byteorder, creds)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    KTEXT cip;
    int byteorder;
    CREDENTIALS *creds;
{
    unsigned char *ptr;
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
    int lifetime;

    ptr = cip->dat;
    /* Assume that cip->length >= 0 for now. */
#define CIP_REMAIN (cip->length - (ptr - cip->dat))

    /* Skip session key for now */
    if (CIP_REMAIN < 8)
	return INTK_BADPW;
    ptr += 8;

    /* extract server's name */
    len = krb4int_strnlen((char *)ptr, CIP_REMAIN) + 1;
    if (len <= 0 || len > sizeof(s_name))
	return INTK_BADPW;
    memcpy(s_name, ptr, (size_t)len);
    ptr += len;

    /* extract server's instance */
    len = krb4int_strnlen((char *)ptr, CIP_REMAIN) + 1;
    if (len <= 0 || len > sizeof(s_instance))
	return INTK_BADPW;
    memcpy(s_instance, ptr, (size_t)len);
    ptr += len;

    /* extract server's realm */
    len = krb4int_strnlen((char *)ptr, CIP_REMAIN) + 1;
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

    /* stash ticket, session key, etc. for future use */
    strncpy(creds->service, s_name, sizeof(creds->service));
    strncpy(creds->instance, s_instance, sizeof(creds->instance));
    strncpy(creds->realm, rlm, sizeof(creds->realm));
    memmove(creds->session, cip->dat, sizeof(C_Block));
    creds->lifetime = lifetime;
    creds->kvno = kvno;
    creds->ticket_st.length = tkt->length;
    memmove(creds->ticket_st.dat, tkt->dat, (size_t)tkt->length);
    creds->issue_date = t_local;
    strncpy(creds->pname, user, sizeof(creds->pname));
    strncpy(creds->pinst, instance, sizeof(creds->pinst));

    return INTK_OK;
}

int
krb_get_in_tkt_preauth_creds(user, instance, realm, service, sinstance, life,
			     key_proc, decrypt_proc,
			     arg, preauth_p, preauth_len, creds, laddrp)
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
    CREDENTIALS *creds;
    KRB_UINT32 *laddrp;
{
    int ok;
    char key_string[BUFSIZ];
    KTEXT_ST cip_st;
    KTEXT cip = &cip_st;	/* Returned Ciphertext */
    int kerror;
    int byteorder;
    key_proc_type *keyprocs = krb_get_keyprocs (key_proc);
    int i = 0;
    struct sockaddr_in local_addr;

    kerror = krb_mk_in_tkt_preauth(user, instance, realm, 
				   service, sinstance,
				   life, preauth_p, preauth_len,
				   cip, &byteorder, &local_addr);
    if (kerror)
	return kerror;

    /* If arg is null, we have to prompt for the password.  decrypt_tkt, by
       way of the *_passwd_to_key functions, will prompt if the password is
       NULL, but that means that each separate encryption type will prompt
       separately.  Obtain the password first so that we can try multiple
       encryption types without re-prompting.

       Don't, however, prompt on a Windows or Macintosh environment, since
       that's harder.  Rely on our caller to do it. */
#if !(defined(_WIN32) || defined(USE_LOGIN_LIBRARY))
    if (arg == NULL) {
        ok = des_read_pw_string(key_string, sizeof(key_string), "Password", 0);
        if (ok != 0)
            return ok;
        arg = key_string;
    }
#endif
    
    /* Attempt to decrypt the reply.  Loop trying password_to_key algorithms 
       until we succeed or we get an error other than "bad password" */
    do {
	KTEXT_ST cip_copy_st;
	memcpy(&cip_copy_st, &cip_st, sizeof(cip_st));
	cip = &cip_copy_st;
        if (decrypt_proc == NULL) {
            decrypt_tkt (user, instance, realm, arg, keyprocs[i], &cip);
        } else {
            (*decrypt_proc)(user, instance, realm, arg, keyprocs[i], &cip);
        }
        kerror = krb_parse_in_tkt_creds(user, instance, realm,
                    service, sinstance, life, cip, byteorder, creds);
    } while ((keyprocs [++i] != NULL) && (kerror == INTK_BADPW));
    cip = &cip_st;

    /* Fill in the local address if the caller wants it */
    if (laddrp != NULL) {
        *laddrp = local_addr.sin_addr.s_addr;
    }

    /* stomp stomp stomp */
    memset(key_string, 0, sizeof(key_string));
    memset(cip->dat, 0, (size_t)cip->length);
    return kerror;
}

int KRB5_CALLCONV
krb_get_in_tkt_creds(user, instance, realm, service, sinstance, life,
		     key_proc, decrypt_proc, arg, creds)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    key_proc_type key_proc;
    decrypt_tkt_type decrypt_proc;
    char *arg;
    CREDENTIALS *creds;
{
#if TARGET_OS_MAC
    KRB_UINT32 *laddrp = &creds->address;
#else
    KRB_UINT32 *laddrp = NULL; /* Only the Mac stores the address */
#endif
    
    return krb_get_in_tkt_preauth_creds(user, instance, realm,
					service, sinstance, life,
					key_proc, decrypt_proc, arg,
					NULL, 0, creds, laddrp);
}

int KRB5_CALLCONV
krb_get_in_tkt_preauth(user, instance, realm, service, sinstance, life,
		       key_proc, decrypt_proc,
		       arg, preauth_p, preauth_len)
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
    int retval;
    KRB_UINT32 laddr;
    CREDENTIALS creds;

    do {
	retval = krb_get_in_tkt_preauth_creds(user, instance, realm,
					      service, sinstance, life,
					      key_proc, decrypt_proc,
					      arg, preauth_p, preauth_len,
					      &creds, &laddr);
	if (retval != KSUCCESS) break;
	if (krb_in_tkt(user, instance, realm) != KSUCCESS) {
	    retval = INTK_ERR;
	    break;
	}
	retval = krb4int_save_credentials_addr(creds.service, creds.instance,
					       creds.realm, creds.session,
					       creds.lifetime, creds.kvno,
					       &creds.ticket_st,
					       creds.issue_date, laddr);
	if (retval != KSUCCESS) break;
    } while (0);
    memset(&creds, 0, sizeof(creds));
    return retval;
}

int KRB5_CALLCONV
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
				  NULL, 0);
}
