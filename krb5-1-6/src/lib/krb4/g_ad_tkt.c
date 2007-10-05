/*
 * lib/krb4/g_ad_tkt.c
 *
 * Copyright 1986, 1987, 1988, 2000, 2001 by the Massachusetts
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

#include "krb.h"
#include "des.h"
#include "krb4int.h"
#include "prot.h"
#include <string.h>

#include <stdio.h>

extern int krb_debug;
extern int swap_bytes;

/*
 * get_ad_tkt obtains a new service ticket from Kerberos, using
 * the ticket-granting ticket which must be in the ticket file.
 * It is typically called by krb_mk_req() when the client side
 * of an application is creating authentication information to be
 * sent to the server side.
 *
 * get_ad_tkt takes four arguments: three pointers to strings which
 * contain the name, instance, and realm of the service for which the
 * ticket is to be obtained; and an integer indicating the desired
 * lifetime of the ticket.
 *
 * It returns an error status if the ticket couldn't be obtained,
 * or AD_OK if all went well.  The ticket is stored in the ticket
 * cache.
 *
 * The request sent to the Kerberos ticket-granting service looks
 * like this:
 *
 * pkt->dat
 *
 * TEXT			original contents of	authenticator+ticket
 *			pkt->dat		built in krb_mk_req call
 * 
 * 4 bytes		time_ws			always 0 (?)  FIXME!
 * char			lifetime		lifetime argument passed
 * string		service			service name argument
 * string		sinstance		service instance arg.
 *
 * See "prot.h" for the reply packet layout and definitions of the
 * extraction macros like pkt_version(), pkt_msg_type(), etc.
 */

/*
 * g_ad_tk_parse()
 *
 * Parse the returned packet from the KDC.
 *
 * Note that the caller is responsible for clearing the returned
 * session key if there is an error; that makes the error handling
 * code a little less hairy.
 */
static int
g_ad_tkt_parse(KTEXT rpkt, C_Block tgtses, C_Block ses,
	       char *s_name, char *s_instance, char *rlm,
	       char *service, char *sinstance, char *realm,
	       int *lifetime, int *kvno, KTEXT tkt,
	       unsigned KRB4_32 *kdc_time,
	       KRB4_32 *t_local)
{
    unsigned char *ptr;
    unsigned int t_switch;
    int msg_byte_order;
    unsigned long rep_err_code;
    unsigned long cip_len;
    KTEXT_ST cip_st;
    KTEXT cip = &cip_st;	/* Returned Ciphertext */
    Key_schedule key_s;
    int len, i;
    KRB4_32 t_diff;		/* Difference between timestamps */

    ptr = rpkt->dat;
#define RPKT_REMAIN (rpkt->length - (ptr - rpkt->dat))
    if (RPKT_REMAIN < 1 + 1)
	return INTK_PROT;
    /* check packet version of the returned packet */
    if (*ptr++ != KRB_PROT_VERSION)
	return INTK_PROT;

    /* This used to be
         switch (pkt_msg_type(rpkt) & ~1) {
       but SCO 3.2v4 cc compiled that incorrectly.  */
    t_switch = *ptr++;
    /* Check byte order (little-endian == 1) */
    msg_byte_order = t_switch & 1;
    t_switch &= ~1;
    /*
     * Skip over some stuff (3 strings and various integers -- see
     * cr_auth_repl.c for details).  Maybe we should actually verify
     * these?
     */
    for (i = 0; i < 3; i++) {
	len = krb4int_strnlen((char *)ptr, RPKT_REMAIN) + 1;
	if (len <= 0)
	    return INTK_PROT;
	ptr += len;
    }
    switch (t_switch) {
    case AUTH_MSG_KDC_REPLY:
	if (RPKT_REMAIN < 4 + 1 + 4 + 1)
	    return INTK_PROT;
	ptr += 4 + 1 + 4 + 1;
	break;
    case AUTH_MSG_ERR_REPLY:
	if (RPKT_REMAIN < 8)
	    return INTK_PROT;
	ptr += 4;
	KRB4_GET32(rep_err_code, ptr, msg_byte_order);
	return rep_err_code;

    default:
	return INTK_PROT;
    }

    /* Extract the ciphertext */
    if (RPKT_REMAIN < 2)
	return INTK_PROT;
    KRB4_GET16(cip_len, ptr, msg_byte_order);
    if (RPKT_REMAIN < cip_len)
	return INTK_PROT;
    /*
     * RPKT_REMAIN will always be non-negative and at most the maximum
     * possible value of cip->length, so this assignment is safe.
     */
    cip->length = cip_len;
    memcpy(cip->dat, ptr, (size_t)cip->length);
    ptr += cip->length;

#ifndef NOENCRYPTION
    /* Attempt to decrypt it */

    key_sched(tgtses, key_s);
    DEB (("About to do decryption ..."));
    pcbc_encrypt((C_Block *)cip->dat, (C_Block *)cip->dat,
                 (long)cip->length, key_s, (C_Block *)tgtses, 0);
#endif /* !NOENCRYPTION */
    /*
     * Stomp on key schedule.  Caller should stomp on tgtses.
     */
    memset(key_s, 0, sizeof(key_s));

    ptr = cip->dat;
#define CIP_REMAIN (cip->length - (ptr - cip->dat))
    if (CIP_REMAIN < 8)
	return RD_AP_MODIFIED;
    memcpy(ses, ptr, 8);
    /*
     * Stomp on decrypted session key immediately after copying it.
     */
    memset(ptr, 0, 8);
    ptr += 8;

    len = krb4int_strnlen((char *)ptr, CIP_REMAIN) + 1;
    if (len <= 0 || len > SNAME_SZ)
	return RD_AP_MODIFIED;
    memcpy(s_name, ptr, (size_t)len);
    ptr += len;

    len = krb4int_strnlen((char *)ptr, CIP_REMAIN) + 1;
    if (len <= 0 || len > INST_SZ)
	return RD_AP_MODIFIED;
    memcpy(s_instance, ptr, (size_t)len);
    ptr += len;

    len = krb4int_strnlen((char *)ptr, CIP_REMAIN) + 1;
    if (len <= 0 || len > REALM_SZ)
	return RD_AP_MODIFIED;
    memcpy(rlm, ptr, (size_t)len);
    ptr += len;

    if (strcmp(s_name, service) || strcmp(s_instance, sinstance)
	|| strcmp(rlm, realm))	/* not what we asked for */
	return INTK_ERR;	/* we need a better code here XXX */

    if (CIP_REMAIN < 1 + 1 + 1)
	return RD_AP_MODIFIED;
    *lifetime = *ptr++;
    *kvno = *ptr++;
    tkt->length = *ptr++;

    if (CIP_REMAIN < tkt->length)
	return RD_AP_MODIFIED;
    memcpy(tkt->dat, ptr, (size_t)tkt->length);
    ptr += tkt->length;

    /* Time (coarse) */
    if (CIP_REMAIN < 4)
	return RD_AP_MODIFIED;
    KRB4_GET32(*kdc_time, ptr, msg_byte_order);

    /* check KDC time stamp */
    *t_local = TIME_GMT_UNIXSEC;
    t_diff = *t_local - *kdc_time;
    if (t_diff < 0)
	t_diff = -t_diff;	/* Absolute value of difference */
    if (t_diff > CLOCK_SKEW)
	return RD_AP_TIME;	/* XXX should probably be better code */

    return 0;
}

int KRB5_CALLCONV
get_ad_tkt(service, sinstance, realm, lifetime)
    char    *service;
    char    *sinstance;
    char    *realm;
    int     lifetime;
{
    KTEXT_ST pkt_st;
    KTEXT pkt = & pkt_st;	/* Packet to KDC */
    KTEXT_ST rpkt_st;
    KTEXT rpkt = &rpkt_st;	/* Returned packet */
    KTEXT_ST tkt_st;
    KTEXT tkt = &tkt_st;	/* Current ticket */
    C_Block ses;                /* Session key for tkt */
    CREDENTIALS cr;
    int kvno;			/* Kvno for session key */
    int kerror;
    char lrealm[REALM_SZ];
    KRB4_32 time_ws = 0;
    char s_name[SNAME_SZ];
    char s_instance[INST_SZ];
    char rlm[REALM_SZ];
    unsigned char *ptr;
    KRB4_32 t_local;
    struct sockaddr_in laddr;
    socklen_t addrlen;
    unsigned KRB4_32 kdc_time;   /* KDC time */
    size_t snamelen, sinstlen;

    kerror = krb_get_tf_realm(TKT_FILE, lrealm);
#if USE_LOGIN_LIBRARY
    if (kerror == GC_NOTKT) {
        /* No tickets... call krb_get_cred (KLL will prompt) and try again. */
        if ((kerror = krb_get_cred ("krbtgt", realm, realm, &cr)) == KSUCCESS) {
            /* Now get the realm again. */
            kerror = krb_get_tf_realm (TKT_FILE, lrealm);
        }
    }
#endif
    if (kerror != KSUCCESS)
	return kerror;

    /* Create skeleton of packet to be sent */
    pkt->length = 0;

    /*
     * Look for the session key (and other stuff we don't need)
     * in the ticket file for krbtgt.realm@lrealm where "realm" 
     * is the service's realm (passed in "realm" argument) and 
     * "lrealm" is the realm of our initial ticket (the local realm).
     * If that fails, and the server's realm and the local realm are
     * the same thing, give up - no TGT available for local realm.
     *
     * If the server realm and local realm are different, though,
     * try getting a ticket-granting ticket for the server's realm,
     * i.e. a ticket for "krbtgt.alienrealm@lrealm", by calling get_ad_tkt().
     * If that succeeds, the ticket will be in ticket cache, get it
     * into the "cr" structure by calling krb_get_cred().
     */
    kerror = krb_get_cred("krbtgt", realm, lrealm, &cr);
    if (kerror != KSUCCESS) {
	/*
	 * If realm == lrealm, we have no hope, so let's not even try.
	 */
	if (strncmp(realm, lrealm, sizeof(lrealm)) == 0)
	    return AD_NOTGT;
	else {
	    kerror = get_ad_tkt("krbtgt", realm, lrealm, lifetime);
	    if (kerror != KSUCCESS) {
		if (kerror == KDC_PR_UNKNOWN)	/* no cross-realm ticket */
		    return AD_NOTGT;		/* So call it no ticket */
		return kerror;
	    }
	    kerror = krb_get_cred("krbtgt",realm,lrealm,&cr);
	    if (kerror != KSUCCESS)
		return kerror;
	}
    }

    /*
     * Make up a request packet to the "krbtgt.realm@lrealm".
     * Start by calling krb_mk_req() which puts ticket+authenticator
     * into "pkt".  Then tack other stuff on the end.
     */
    kerror = krb_mk_req(pkt, "krbtgt", realm, lrealm, 0L);
    if (kerror) {
	/* stomp stomp stomp */
	memset(cr.session, 0, sizeof(cr.session));
	return AD_NOTGT;
    }

    ptr = pkt->dat + pkt->length;

    snamelen = strlen(service) + 1;
    sinstlen = strlen(sinstance) + 1;
    if (sizeof(pkt->dat) - (ptr - pkt->dat) < (4 + 1
					       + snamelen
					       + sinstlen)) {
	/* stomp stomp stomp */
	memset(cr.session, 0, sizeof(cr.session));
	return INTK_ERR;
    }

    /* timestamp */   /* FIXME -- always 0 now, should we fill it in??? */
    KRB4_PUT32BE(ptr, time_ws);

    *ptr++ = lifetime;

    memcpy(ptr, service, snamelen);
    ptr += snamelen;
    memcpy(ptr, sinstance, sinstlen);
    ptr += sinstlen;

    pkt->length = ptr - pkt->dat;

    /* Send the request to the local ticket-granting server */
    rpkt->length = 0;
    addrlen = sizeof(laddr);
    kerror = krb4int_send_to_kdc_addr(pkt, rpkt, realm,
				      (struct sockaddr *)&laddr, &addrlen);

    if (!kerror) {
	/* No error; parse return packet from KDC. */
	kerror = g_ad_tkt_parse(rpkt, cr.session, ses,
				s_name, s_instance, rlm,
				service, sinstance, realm,
				&lifetime, &kvno, tkt,
				&kdc_time, &t_local);
    }
    /*
     * Unconditionally stomp on cr.session because we don't need it
     * anymore.
     */
    memset(cr.session, 0, sizeof(cr.session));
    if (kerror) {
	/*
	 * Stomp on ses for good measure, since g_ad_tkt_parse()
	 * doesn't do that for us.
	 */
	memset(ses, 0, sizeof(ses));
	return kerror;
    }

    kerror = krb4int_save_credentials_addr(s_name, s_instance, rlm,
					   ses, lifetime, kvno, tkt,
					   t_local,
					   laddr.sin_addr.s_addr);
    /*
     * Unconditionally stomp on ses because we don't need it anymore.
     */
    memset(ses, 0, sizeof(ses));
    if (kerror)
	return kerror;
    return AD_OK;
}
