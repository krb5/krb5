/*
 * lib/krb4/rd_req.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2000, 2001, 2002 by the
 * Massachusetts Institute of Technology.  All Rights Reserved.
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

#include "des.h"
#include "krb.h"
#include "prot.h"
#include <string.h>
#include <krb5.h>
#include <krb54proto.h>

extern int krb_ap_req_debug;

static int
krb_rd_req_with_key(KTEXT, char *, char *, KRB_UINT32, AUTH_DAT *,
		    Key_schedule, krb5_keyblock *);

/* declared in krb.h */
int krb_ignore_ip_address = 0;

/*
 * Keep the following information around for subsequent calls
 * to this routine by the same server using the same key.
 */

static Key_schedule serv_key;	/* Key sched to decrypt ticket */
static C_Block ky;              /* Initialization vector */
static int st_kvno;		/* version number for this key */
static char st_rlm[REALM_SZ];	/* server's realm */
static char st_nam[ANAME_SZ];	/* service name */
static char st_inst[INST_SZ];	/* server's instance */
static int krb5_key;		/* whether krb5 key is used for decrypt */

/*
 * This file contains two functions.  krb_set_key() takes a DES
 * key or password string and returns a DES key (either the original
 * key, or the password converted into a DES key) and a key schedule
 * for it.
 *
 * krb_rd_req() reads an authentication request and returns information
 * about the identity of the requestor, or an indication that the
 * identity information was not authentic.
 */

/*
 * krb_set_key() takes as its first argument either a DES key or a
 * password string.  The "cvt" argument indicates how the first
 * argument "key" is to be interpreted: if "cvt" is null, "key" is
 * taken to be a DES key; if "cvt" is non-null, "key" is taken to
 * be a password string, and is converted into a DES key using
 * string_to_key().  In either case, the resulting key is returned
 * in the external static variable "ky".  A key schedule is
 * generated for "ky" and returned in the external static variable
 * "serv_key".
 *
 * This routine returns the return value of des_key_sched.
 *
 * krb_set_key() needs to be in the same .o file as krb_rd_req() so that
 * the key set by krb_set_key() is available in private storage for
 * krb_rd_req().
 */

static krb5_keyblock srv_k5key;

int
krb_set_key(key, cvt)
    char *key;
    int cvt;
{
    if (krb5_key)
	/* XXX assumes that context arg is ignored */
	krb5_free_keyblock_contents(NULL, &srv_k5key);
    krb5_key = 0;
#ifdef NOENCRYPTION
    memset(ky, 0, sizeof(ky));
    return KSUCCESS;
#else /* Encrypt */
    if (cvt)
        string_to_key(key, ky);
    else
        memcpy((char *)ky, key, 8);
    return des_key_sched(ky,serv_key);
#endif /* NOENCRYPTION */
}

int
krb_set_key_krb5(ctx, key)
    krb5_context ctx;
    krb5_keyblock *key;
{
    if (krb5_key)
	krb5_free_keyblock_contents(ctx, &srv_k5key);
    krb5_key = 1;
    return krb5_copy_keyblock_contents(ctx, key, &srv_k5key);
}

void
krb_clear_key_krb5(ctx)
    krb5_context ctx;
{
    if (krb5_key)
	krb5_free_keyblock_contents(ctx, &srv_k5key);
    krb5_key = 0;
}

/*
 * krb_rd_req() takes an AUTH_MSG_APPL_REQUEST or
 * AUTH_MSG_APPL_REQUEST_MUTUAL message created by krb_mk_req(),
 * checks its integrity and returns a judgement as to the requestor's
 * identity.
 *
 * The "authent" argument is a pointer to the received message.
 * The "service" and "instance" arguments name the receiving server,
 * and are used to get the service's ticket to decrypt the ticket
 * in the message, and to compare against the server name inside the
 * ticket.  "from_addr" is the network address of the host from which
 * the message was received; this is checked against the network
 * address in the ticket.  If "from_addr" is zero, the check is not
 * performed.  "ad" is an AUTH_DAT structure which is
 * filled in with information about the sender's identity according
 * to the authenticator and ticket sent in the message.  Finally,
 * "fn" contains the name of the file containing the server's key.
 * (If "fn" is NULL, the server's key is assumed to have been set
 * by krb_set_key().  If "fn" is the null string ("") the default
 * file KEYFILE, defined in "krb.h", is used.)
 *
 * krb_rd_req() returns RD_AP_OK if the authentication information
 * was genuine, or one of the following error codes (defined in
 * "krb.h"):
 *
 *	RD_AP_VERSION		- wrong protocol version number
 *	RD_AP_MSG_TYPE		- wrong message type
 *	RD_AP_UNDEC		- couldn't decipher the message
 *	RD_AP_INCON		- inconsistencies found
 *	RD_AP_BADD		- wrong network address
 *	RD_AP_TIME		- client time (in authenticator)
 *				  too far off server time
 *	RD_AP_NYV		- Kerberos time (in ticket) too
 *				  far off server time
 *	RD_AP_EXP		- ticket expired
 *
 * For the message format, see krb_mk_req().
 *
 * Mutual authentication is not implemented.
 */

static int
krb_rd_req_with_key(authent, service, instance, from_addr, ad, ks, k5key)
    register KTEXT authent;	/* The received message */
    char *service;		/* Service name */
    char *instance;		/* Service instance */
    unsigned KRB4_32 from_addr; /* Net address of originating host */
    AUTH_DAT *ad;		/* Structure to be filled in */
    Key_schedule ks;
    krb5_keyblock *k5key;
{
    KTEXT_ST ticket;		/* Temp storage for ticket */
    KTEXT tkt = &ticket;
    KTEXT_ST req_id_st;		/* Temp storage for authenticator */
    register KTEXT req_id = &req_id_st;

    char realm[REALM_SZ];	/* Realm of issuing kerberos */
    Key_schedule seskey_sched; /* Key sched for session key */
    char sname[SNAME_SZ];	/* Service name from ticket */
    char iname[INST_SZ];	/* Instance name from ticket */
    char r_aname[ANAME_SZ];	/* Client name from authenticator */
    char r_inst[INST_SZ];	/* Client instance from authenticator */
    char r_realm[REALM_SZ];	/* Client realm from authenticator */
    unsigned int r_time_ms;     /* Fine time from authenticator */
    unsigned KRB4_32 r_time_sec;   /* Coarse time from authenticator */
    register unsigned char *ptr; /* For stepping through */
    unsigned KRB4_32 t_local;	/* Local time on our side of the protocol */
    KRB4_32 delta_t;      	/* Time in authenticator minus local time */
#ifdef KRB_CRYPT_DEBUG
    KRB4_32 tkt_age;		/* Age of ticket */
#endif
    int le;			/* is little endian? */
    int mutual;			/* Mutual authentication requested? */
    int t;			/* msg type */
    unsigned char s_kvno;	/* Version number of the server's key
				   Kerberos used to encrypt ticket */
    int ret;
    int len;

    tkt->mbz = req_id->mbz = 0;

    if (authent->length < 1 + 1 + 1)
	return RD_AP_MODIFIED;

    ptr = authent->dat;
#define AUTHENT_REMAIN (authent->length - (ptr - authent->dat))

    /* get msg version, type and byte order, and server key version */

    /* check version */
    if (KRB_PROT_VERSION != *ptr++)
        return RD_AP_VERSION;

    /* byte order */
    t = *ptr++;
    le = t & 1;

    /* check msg type */
    mutual = 0;
    switch (t & ~1) {
    case AUTH_MSG_APPL_REQUEST:
        break;
    case AUTH_MSG_APPL_REQUEST_MUTUAL:
        mutual++;
        break;
    default:
        return RD_AP_MSG_TYPE;
    }

#ifdef lint
    /* XXX mutual is set but not used; why??? */
    /* this is a crock to get lint to shut up */
    if (mutual)
        mutual = 0;
#endif /* lint */
    s_kvno = *ptr++;		/* get server key version */
    len = krb4int_strnlen((char *)ptr, AUTHENT_REMAIN) + 1;
    if (len <= 0 || len > sizeof(realm)) {
	return RD_AP_MODIFIED;  /* must have been modified, the client wouldn't
	                           try to trick us with wacky data */
    }
    /* And the realm of the issuing KDC */
    (void)memcpy(realm, ptr, (size_t)len);
    ptr += len;			/* skip the realm "hint" */

    /* Get ticket length */
    tkt->length = *ptr++;
    /* Get authenticator length while we're at it. */
    req_id->length = *ptr++;
    if (AUTHENT_REMAIN < tkt->length + req_id->length)
	return RD_AP_MODIFIED;
    /* Copy ticket */
    memcpy(tkt->dat, ptr, (size_t)tkt->length);
    ptr += tkt->length;

#ifdef KRB_CRYPT_DEBUG
    if (krb_ap_req_debug)
        log("ticket->length: %d",tkt->length);
    if (krb_ap_req_debug)
	log("authent->length: %d", authent->length);
#endif

#ifndef NOENCRYPTION
    /* Decrypt and take apart ticket */
#endif

    if (k5key == NULL) {
	if (decomp_ticket(tkt,&ad->k_flags,ad->pname,ad->pinst,ad->prealm,
			  &(ad->address),ad->session, &(ad->life),
			  &(ad->time_sec),sname,iname,ky,ks)) {
#ifdef KRB_CRYPT_DEBUG
	    log("Can't decode ticket");
#endif
	    return(RD_AP_UNDEC);
	}
    } else {
	if (decomp_tkt_krb5(tkt, &ad->k_flags, ad->pname, ad->pinst,
			    ad->prealm, &ad->address, ad->session,
			    &ad->life, &ad->time_sec, sname, iname,
			    k5key)) {
	    return RD_AP_UNDEC;
	}
    }

#ifdef KRB_CRYPT_DEBUG
    if (krb_ap_req_debug) {
        log("Ticket Contents.");
        log(" Aname:   %s%s%s@%s",ad->pname,
	    ((int)*(ad->pinst) ? "." : ""), ad->pinst,
            ((int)*(ad->prealm) ? ad->prealm : "Athena"));
        log(" Service: %s%s%s",sname,((int)*iname ? "." : ""),iname);
	log("    sname=%s, sinst=%s", sname, iname);
    }
#endif

    /* Extract the authenticator */
    memcpy(req_id->dat, ptr, (size_t)req_id->length);

#ifndef NOENCRYPTION
    /* And decrypt it with the session key from the ticket */
#ifdef KRB_CRYPT_DEBUG
    if (krb_ap_req_debug) log("About to decrypt authenticator");
#endif

    key_sched(ad->session, seskey_sched);
    pcbc_encrypt((C_Block *)req_id->dat, (C_Block *)req_id->dat,
                 (long)req_id->length,
		 seskey_sched, &ad->session, DES_DECRYPT);
    memset(seskey_sched, 0, sizeof(seskey_sched));

#ifdef KRB_CRYPT_DEBUG
    if (krb_ap_req_debug) log("Done.");
#endif
#endif /* NOENCRYPTION */

    ptr = req_id->dat;
#define REQID_REMAIN (req_id->length - (ptr - req_id->dat))

    ret = RD_AP_MODIFIED;

    len = krb4int_strnlen((char *)ptr, REQID_REMAIN) + 1;
    if (len <= 0 || len > ANAME_SZ)
	goto cleanup;
    memcpy(r_aname, ptr, (size_t)len); /* Authentication name */
    ptr += len;
    len = krb4int_strnlen((char *)ptr, REQID_REMAIN) + 1;
    if (len <= 0 || len > INST_SZ)
	goto cleanup;
    memcpy(r_inst, ptr, (size_t)len); /* Authentication instance */
    ptr += len;
    len = krb4int_strnlen((char *)ptr, REQID_REMAIN) + 1;
    if (len <= 0 || len > REALM_SZ)
	goto cleanup;
    memcpy(r_realm, ptr, (size_t)len); /* Authentication name */
    ptr += len;

    if (REQID_REMAIN < 4 + 1 + 4)
	goto cleanup;
    KRB4_GET32(ad->checksum, ptr, le);
    r_time_ms = *ptr++;		/* Time (fine) */
#ifdef lint
    /* XXX r_time_ms is set but not used.  why??? */
    /* this is a crock to get lint to shut up */
    if (r_time_ms)
        r_time_ms = 0;
#endif /* lint */
    /* Time (coarse) */
    KRB4_GET32(r_time_sec, ptr, le);

    /* Check for authenticity of the request */
#ifdef KRB_CRYPT_DEBUG
    if (krb_ap_req_debug)
        log("Pname:   %s %s",ad->pname,r_aname);
#endif

    ret = RD_AP_INCON;
    if (strcmp(ad->pname,r_aname) != 0)
	goto cleanup;
    if (strcmp(ad->pinst,r_inst) != 0)
	goto cleanup;

#ifdef KRB_CRYPT_DEBUG
    if (krb_ap_req_debug)
        log("Realm:   %s %s",ad->prealm,r_realm);
#endif

    if (strcmp(ad->prealm,r_realm) != 0)
	goto cleanup;

    /* check the time integrity of the msg */
    ret = RD_AP_TIME;
    t_local = TIME_GMT_UNIXSEC;
    delta_t = t_local - r_time_sec;
    if (delta_t < 0) delta_t = -delta_t;  /* Absolute value of difference */
    if (delta_t > CLOCK_SKEW) {
#ifdef KRB_CRYPT_DEBUG
        if (krb_ap_req_debug)
            log("Time out of range: %d - %d = %d",
                time_secs, r_time_sec, delta_t);
#endif
	goto cleanup;
    }

    /* Now check for expiration of ticket */

    ret = RD_AP_NYV;
#ifdef KRB_CRYPT_DEBUG
    tkt_age = t_local - ad->time_sec;
    if (krb_ap_req_debug)
        log("Time: %d Issue Date: %d Diff: %d Life %x",
            time_secs, ad->time_sec, tkt_age, ad->life);
#endif
    if (t_local < ad->time_sec) {
        if ((ad->time_sec - t_local) > CLOCK_SKEW)
	    goto cleanup;
    } else if (krb_life_to_time((KRB4_32)ad->time_sec, ad->life)
	     < t_local + CLOCK_SKEW) {
	ret = RD_AP_EXP;
	goto cleanup;
    }

#ifdef KRB_CRYPT_DEBUG
    if (krb_ap_req_debug)
        log("Address: %d %d",ad->address,from_addr);
#endif

    if (!krb_ignore_ip_address
	&& from_addr && (ad->address != from_addr)) {
	ret = RD_AP_BADD;
	goto cleanup;
    }

    /* All seems OK */
    ad->reply.length = 0;
    ret = 0;

cleanup:
    if (ret) {
	/* Stomp on session key if there is an error. */
	memset(ad->session, 0, sizeof(ad->session));
	return ret;
    }

    return RD_AP_OK;
}

int KRB5_CALLCONV
krb_rd_req_int(authent, service, instance, from_addr, ad, key)
    KTEXT authent;		/* The received message */
    char *service;		/* Service name */
    char *instance;		/* Service instance */
    KRB_UINT32 from_addr;	/* Net address of originating host */
    AUTH_DAT *ad;		/* Structure to be filled in */
    C_Block key;		/* Key to decrypt ticket with */
{
    Key_schedule ks;
    int ret;

    do {
	ret = des_key_sched(key, ks);
	if (ret) break;
	ret = krb_rd_req_with_key(authent, service, instance,
				  from_addr, ad, ks, NULL);
    } while (0);
    memset(ks, 0, sizeof(ks));
    return ret;
}

int KRB5_CALLCONV
krb_rd_req(authent, service, instance, from_addr, ad, fn)
    register KTEXT authent;	/* The received message */
    char *service;		/* Service name */
    char *instance;		/* Service instance */
    unsigned KRB4_32 from_addr; /* Net address of originating host */
    AUTH_DAT *ad;		/* Structure to be filled in */
    char *fn;		/* Filename to get keys from */
{
    unsigned char *ptr;
    unsigned char s_kvno;
    char realm[REALM_SZ];
    unsigned char skey[KKEY_SZ];
#ifdef KRB4_USE_KEYTAB
    krb5_keyblock keyblock;
#endif
    int len;
    int status;

#define AUTHENT_REMAIN (authent->length - (ptr - authent->dat))
    if (authent->length < 3)
	return RD_AP_MODIFIED;
    ptr = authent->dat + 2;
    s_kvno = *ptr++;		/* get server key version */
    len = krb4int_strnlen((char *)ptr, AUTHENT_REMAIN) + 1;
    if (len <= 0 || len > sizeof(realm))
	return RD_AP_MODIFIED;
    (void)memcpy(realm, ptr, (size_t)len);
#undef AUTHENT_REMAIN
    /*
     * If "fn" is NULL, key info should already be set; don't
     * bother with ticket file.  Otherwise, check to see if we
     * already have key info for the given server and key version
     * (saved in the static st_* variables).  If not, go get it
     * from the ticket file.  If "fn" is the null string, use the
     * default ticket file.
     */
    if (fn && (strcmp(st_nam,service) || strcmp(st_inst,instance)
	       || strcmp(st_rlm,realm) || (st_kvno != s_kvno))) {
        if (*fn == 0)
	    fn = KEYFILE;
        st_kvno = s_kvno;
        if (read_service_key(service,instance,realm, (int)s_kvno,
			     fn, (char *)skey) == 0) {
	    if ((status = krb_set_key((char *)skey,0)))
		return(status);
#ifdef KRB4_USE_KEYTAB
	} else if (krb54_get_service_keyblock(service, instance,
					      realm, (int)s_kvno,
					      fn, &keyblock) == 0) {
	    krb_set_key_krb5(krb5__krb4_context, &keyblock);
	    krb5_free_keyblock_contents(krb5__krb4_context, &keyblock);
#endif
	} else
	    return RD_AP_UNDEC;

	len = krb4int_strnlen(realm, sizeof(st_rlm)) + 1;
	if (len <= 0)
	    return KFAILURE;
	memcpy(st_rlm, realm, (size_t)len);
	len = krb4int_strnlen(service, sizeof(st_nam)) + 1;
	if (len <= 0)
	    return KFAILURE;
	memcpy(st_nam, service, (size_t)len);
	len = krb4int_strnlen(instance, sizeof(st_inst)) + 1;
	if (len <= 0)
	    return KFAILURE;
	memcpy(st_inst, instance, (size_t)len);
    }
    return krb_rd_req_with_key(authent, service, instance,
			       from_addr, ad,
			       krb5_key ? NULL : serv_key,
			       krb5_key ? &srv_k5key : NULL);
}
