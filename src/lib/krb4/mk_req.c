/*
 * lib/krb4/mk_req.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2000, 2002 by the Massachusetts
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
#include "prot.h"
#include "des.h"
#include <string.h>
#include "krb4int.h"

extern int krb_ap_req_debug;
static int lifetime = 255;		/* Default based on the TGT */

static int krb_mk_req_creds_prealm(KTEXT, CREDENTIALS *, KRB4_32, char *);

/*
 * krb_mk_req takes a text structure in which an authenticator is to
 * be built, the name of a service, an instance, a realm,
 * and a checksum.  It then retrieves a ticket for
 * the desired service and creates an authenticator in the text
 * structure passed as the first argument.  krb_mk_req returns
 * KSUCCESS on success and a Kerberos error code on failure.
 *
 * The peer procedure on the other end is krb_rd_req.  When making
 * any changes to this routine it is important to make corresponding
 * changes to krb_rd_req.
 *
 * The authenticator consists of the following:
 *
 * authent->dat
 *
 * unsigned char	KRB_PROT_VERSION	protocol version no.
 * unsigned char	AUTH_MSG_APPL_REQUEST	message type
 * (least significant
 * bit of above)	HOST_BYTE_ORDER		local byte ordering
 * unsigned char	kvno from ticket	server's key version
 * string		realm			server's realm
 * unsigned char	tl			ticket length
 * unsigned char	idl			request id length
 * text			ticket->dat		ticket for server
 * text			req_id->dat		request id
 *
 * The ticket information is retrieved from the ticket cache or
 * fetched from Kerberos.  The request id (called the "authenticator"
#ifdef NOENCRYPTION
 * in the papers on Kerberos) contains the following:
#else
 * in the papers on Kerberos) contains information encrypted in the session
 * key for the client and ticket-granting service:  {req_id}Kc,tgs
 * Before encryption, it contains the following:
#endif
 *
 * req_id->dat
 *
 * string		cr.pname		{name, instance, and
 * string		cr.pinst		realm of principal
 * string		myrealm			making this request}
 * 4 bytes		checksum		checksum argument given
 * unsigned char	time_usecs		time (microseconds)
 * 4 bytes		time_secs		time (seconds)
 *
 * req_id->length = 3 strings + 3 terminating nulls + 5 bytes for time,
 *                  all rounded up to multiple of 8.
 */

static int
krb_mk_req_creds_prealm(authent, creds, checksum, myrealm)
    register	KTEXT authent;	/* Place to build the authenticator */
    CREDENTIALS	*creds;
    KRB4_32	checksum;	/* Checksum of data (optional) */
    char	*myrealm;	/* Client's realm */
{
    KTEXT_ST req_st; /* Temp storage for req id */
    KTEXT req_id = &req_st;
    unsigned char *p, *q, *reqid_lenp;
    int tl;			/* Tkt len */
    int idl;			/* Reqid len */
    register KTEXT ticket;	/* Pointer to tkt_st */
    Key_schedule  key_s;
    size_t realmlen, pnamelen, pinstlen, myrealmlen;
    unsigned KRB4_32 time_secs;
    unsigned KRB4_32 time_usecs;

    /* Don't risk exposing stack garbage to correspondent, even if
       encrypted from other prying eyes.  */
    memset(&req_st, 0x69, sizeof(req_st));

    ticket = &creds->ticket_st;
    /* Get the ticket and move it into the authenticator */
    if (krb_ap_req_debug)
        DEB (("Realm: %s\n", creds->realm));

    realmlen = strlen(creds->realm) + 1;
    if (sizeof(authent->dat) < (1 + 1 + 1
				+ realmlen
				+ 1 + 1 + ticket->length)
	|| ticket->length < 0 || ticket->length > 255) {
	authent->length = 0;
	return KFAILURE;
    }

    if (krb_ap_req_debug)
        DEB (("%s %s %s %s %s\n", creds->service, creds->instance,
	      creds->realm, creds->pname, creds->pinst));

    p = authent->dat;

    /* The fixed parts of the authenticator */
    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_APPL_REQUEST;
    *p++ = creds->kvno;

    memcpy(p, creds->realm, realmlen);
    p += realmlen;

    tl = ticket->length;
    *p++ = tl;
    /* Save ptr to where req_id->length goes. */
    reqid_lenp = p;
    p++;
    memcpy(p, ticket->dat, (size_t)tl);
    p += tl;

    if (krb_ap_req_debug)
        DEB (("Ticket->length = %d\n",ticket->length));
    if (krb_ap_req_debug)
        DEB (("Issue date: %d\n",creds->issue_date));

    pnamelen = strlen(creds->pname) + 1;
    pinstlen = strlen(creds->pinst) + 1;
    myrealmlen = strlen(myrealm) + 1;
    if (sizeof(req_id->dat) / 8 < (pnamelen + pinstlen + myrealmlen
				   + 4 + 1 + 4 + 7) / 8) {
	return KFAILURE;
    }

    q = req_id->dat;

    /* Build request id */
    /* Auth name */
    memcpy(q, creds->pname, pnamelen);
    q += pnamelen;
    /* Principal's instance */
    memcpy(q, creds->pinst, pinstlen);
    q += pinstlen;    
    /* Authentication domain */
    memcpy(q, myrealm, myrealmlen);
    q += myrealmlen;
    /* Checksum */
    KRB4_PUT32BE(q, checksum);

    /* Fill in the times on the request id */
    time_secs = TIME_GMT_UNIXSEC_US (&time_usecs);
    *q++ = time_usecs;		/* time_usecs % 255 */
    /* Time (coarse) */
    KRB4_PUT32BE(q, time_secs);

    /* Fill to a multiple of 8 bytes for DES */
    req_id->length = ((q - req_id->dat + 7) / 8) * 8;

#ifndef NOENCRYPTION
    /* Encrypt the request ID using the session key */
    key_sched(creds->session, key_s);
    pcbc_encrypt((C_Block *)req_id->dat, (C_Block *)req_id->dat,
                 (long)req_id->length, key_s, &creds->session, 1);
    /* clean up */
    memset(key_s, 0, sizeof(key_s));
#endif /* NOENCRYPTION */

    /* Copy it into the authenticator */
    idl = req_id->length;
    if (idl > 255)
	return KFAILURE;
    *reqid_lenp = idl;
    memcpy(p, req_id->dat, (size_t)idl);
    p += idl;

    authent->length = p - authent->dat;

    /* clean up */
    memset(req_id, 0, sizeof(*req_id));

    if (krb_ap_req_debug)
        DEB (("Authent->length = %d\n",authent->length));
    if (krb_ap_req_debug)
        DEB (("idl = %d, tl = %d\n", idl, tl));

    return KSUCCESS;
}

int KRB5_CALLCONV
krb_mk_req(authent, service, instance, realm, checksum)
    register	KTEXT authent;	/* Place to build the authenticator */
    char	*service;	/* Name of the service */
    char	*instance;	/* Service instance */
    char	*realm;	/* Authentication domain of service */
    KRB4_32	checksum;	/* Checksum of data (optional) */
{
    char krb_realm[REALM_SZ];	/* Our local realm, if not specified */
    char myrealm[REALM_SZ];	/* Realm of initial TGT. */
    int retval;
    CREDENTIALS creds;

    /* get current realm if not passed in */
    if (realm == NULL) {
	retval = krb_get_lrealm(krb_realm, 1);
	if (retval != KSUCCESS)
	    return retval;
	realm = krb_realm;
    }
    /*
     * Determine realm of these tickets.  We will send this to the
     * KDC from which we are requesting tickets so it knows what to
     * with our session key.
     */
    retval = krb_get_tf_realm(TKT_FILE, myrealm);
    if (retval != KSUCCESS)
	retval = krb_get_lrealm(myrealm, 1);
    if (retval != KSUCCESS)
	return retval;

    retval = krb_get_cred(service, instance, realm, &creds);
    if (retval == RET_NOTKT) {
	retval = get_ad_tkt(service, instance, realm, lifetime);
        if (retval)
            return retval;
	retval = krb_get_cred(service, instance, realm, &creds);
        if (retval)
	    return retval;
    }
    if (retval != KSUCCESS)
	return retval;

    retval = krb_mk_req_creds_prealm(authent, &creds, checksum, myrealm);
    memset(&creds.session, 0, sizeof(creds.session));
    return retval;
}

int KRB5_CALLCONV
krb_mk_req_creds(authent, creds, checksum)
    register	KTEXT authent;	/* Place to build the authenticator */
    CREDENTIALS	*creds;
    KRB4_32	checksum;	/* Checksum of data (optional) */
{
    return krb_mk_req_creds_prealm(authent, creds, checksum, creds->realm);
}

/* 
 * krb_set_lifetime sets the default lifetime for additional tickets
 * obtained via krb_mk_req().
 * 
 * It returns the previous value of the default lifetime.
 */

int KRB5_CALLCONV
krb_set_lifetime(newval)
int newval;
{
    int olife = lifetime;

    lifetime = newval;
    return olife;
}
