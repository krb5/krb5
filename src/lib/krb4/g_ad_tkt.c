/*
 * g_ad_tkt.c
 *
 * Copyright 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "krb.h"
#include "des.h"
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

get_ad_tkt(service,sinstance,realm,lifetime)
    char    *service;
    char    *sinstance;
    char    *realm;
    int     lifetime;
{
    unsigned long rep_err_code;

    KTEXT_ST pkt_st;
    KTEXT pkt = & pkt_st;	/* Packet to KDC */
    KTEXT_ST rpkt_st;
    KTEXT rpkt = &rpkt_st;	/* Returned packet */
    KTEXT_ST cip_st;
    KTEXT cip = &cip_st;	/* Returned Ciphertext */
    KTEXT_ST tkt_st;
    KTEXT tkt = &tkt_st;	/* Current ticket */
    C_Block ses;                /* Session key for tkt */
    CREDENTIALS cr;
    int kvno;			/* Kvno for session key */
    char lrealm[REALM_SZ];
    Key_schedule key_s;
    KRB4_32 time_ws = 0;
    char s_name[SNAME_SZ];
    char s_instance[INST_SZ];
    int msg_byte_order;
    int kerror;
    char rlm[REALM_SZ];
    char *ptr;
    unsigned KRB4_32 t_local;	/* Must be 4 bytes long for memcpy below! */
    KRB4_32 t_diff;		/* Difference between timestamps */
    unsigned KRB4_32 kdc_time;   /* KDC time */
    unsigned int t_switch;

    if ((kerror = krb_get_tf_realm(TKT_FILE, lrealm)) != KSUCCESS)
	return(kerror);

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
    
    if ((kerror = krb_get_cred("krbtgt",realm,lrealm,&cr)) != KSUCCESS) {
	/*
	 * If realm == lrealm, we have no hope, so let's not even try.
	 */
	if ((strncmp(realm, lrealm, REALM_SZ)) == 0)
	    return(AD_NOTGT);
	else{
	    if ((kerror = 
		 get_ad_tkt("krbtgt",realm,lrealm,lifetime)) != KSUCCESS) {
		if (kerror == KDC_PR_UNKNOWN)	/* no cross-realm ticket */
		    return AD_NOTGT;		/* So call it no ticket */
		return(kerror);
	    }
	    if ((kerror = krb_get_cred("krbtgt",realm,lrealm,&cr)) != KSUCCESS)
		return(kerror);
	}
    }
    
    /*
     * Make up a request packet to the "krbtgt.realm@lrealm".
     * Start by calling krb_mk_req() which puts ticket+authenticator
     * into "pkt".  Then tack other stuff on the end.
     */
    
    kerror = krb_mk_req(pkt,"krbtgt",realm,lrealm,0L);

    if (kerror)
	return(AD_NOTGT);

    /* timestamp */   /* FIXME -- always 0 now, should we fill it in??? */
    memcpy((char *) (pkt->dat+pkt->length), (char *) &time_ws, 4);
    pkt->length += 4;
    *(pkt->dat+(pkt->length)++) = (char) lifetime;
    (void) strcpy((char *) (pkt->dat+pkt->length),service);
    pkt->length += 1 + strlen(service);
    (void) strcpy((char *)(pkt->dat+pkt->length),sinstance);
    pkt->length += 1 + strlen(sinstance);

    rpkt->length = 0;

    /* Send the request to the local ticket-granting server */
    if (kerror = send_to_kdc(pkt, rpkt, realm)) return(kerror);

    /* check packet version of the returned packet */
    if (pkt_version(rpkt) != KRB_PROT_VERSION )
        return(INTK_PROT);

    /* Check byte order */
    msg_byte_order = pkt_msg_type(rpkt) & 1;
    swap_bytes = 0;
    if (msg_byte_order != HOST_BYTE_ORDER)
	swap_bytes++;

    /* This used to be
         switch (pkt_msg_type(rpkt) & ~1) {
       but SCO 3.2v4 cc compiled that incorrectly.  */
    t_switch = pkt_msg_type(rpkt);
    t_switch &= ~1;
    switch (t_switch) {
    case AUTH_MSG_KDC_REPLY:
	break;
    case AUTH_MSG_ERR_REPLY:
	memcpy((char *) &rep_err_code, pkt_err_code(rpkt), 4);
	if (swap_bytes)
	    rep_err_code = krb4_swab32(rep_err_code);
	return(rep_err_code);

    default:
	return(INTK_PROT);
    }

    /* Extract the ciphertext */
    cip->length = pkt_clen(rpkt);       /* let clen do the swap */

    memcpy((char *) (cip->dat), (char *) pkt_cipher(rpkt), cip->length);

#ifndef NOENCRYPTION
    /* Attempt to decrypt it */

    key_sched(cr.session,key_s);
    DEB (("About to do decryption ..."));
    pcbc_encrypt((C_Block *)cip->dat,(C_Block *)cip->dat,
                 (long) cip->length,key_s,(C_Block *)cr.session,0);
#endif /* !NOENCRYPTION */
    /* Get rid of all traces of key */
    memset((char *) cr.session, 0, sizeof(cr.session));
    memset((char *) key_s, 0, sizeof(key_s));

    ptr = (char *) cip->dat;

    memcpy((char *)ses, ptr, 8);
    ptr += 8;

    (void) strcpy(s_name,ptr);
    ptr += strlen(s_name) + 1;

    (void) strcpy(s_instance,ptr);
    ptr += strlen(s_instance) + 1;

    (void) strcpy(rlm,ptr);
    ptr += strlen(rlm) + 1;

    lifetime = (unsigned long) ptr[0];
    kvno = (unsigned long) ptr[1];
    tkt->length = (int) ptr[2];
    ptr += 3;
    memcpy((char *)(tkt->dat), ptr, tkt->length);
    ptr += tkt->length;

    if (strcmp(s_name, service) || strcmp(s_instance, sinstance) ||
        strcmp(rlm, realm))	/* not what we asked for */
	return(INTK_ERR);	/* we need a better code here XXX */

    /* check KDC time stamp */
    memcpy((char *)&kdc_time, ptr, 4); /* Time (coarse) */
    if (swap_bytes) kdc_time = krb4_swab32(kdc_time);

    ptr += 4;

    t_local = TIME_GMT_UNIXSEC;
    t_diff = t_local - kdc_time;
    if (t_diff < 0) t_diff = -t_diff;	/* Absolute value of difference */
    if (t_diff > CLOCK_SKEW) {
        return(RD_AP_TIME);		/* XXX should probably be better
					   code */
    }

    if (kerror = krb_save_credentials(s_name,s_instance,rlm,ses,lifetime,
				  kvno,tkt,t_local))
	return(kerror);

    return(AD_OK);
}
