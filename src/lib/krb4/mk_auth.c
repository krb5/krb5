/*
 * lib/krb4/mk_auth.c
 *
 * Copyright 1987, 1988, 2000, 2001 by the Massachusetts Institute of
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
 * Derived from sendauth.c by John Gilmore, 10 October 1994.
 */

#include <stdio.h>
#include "krb.h"
#include "prot.h"
#include <errno.h>
#include <string.h>

#define	KRB_SENDAUTH_VERS "AUTHV0.1" /* MUST be KRB_SENDAUTH_VLEN chars */
/*
 * If the protocol changes, you will need to change the version string
 * and make appropriate changes in recvauth.c and sendauth.c.
 */

/*
 * This file contains two routines: krb_mk_auth() and krb_check_auth().
 *
 * krb_mk_auth() packages a ticket for transmission to an application
 * server.
 *
 * krb_krb_check_auth() validates a mutual-authentication response from
 * the application server.
 * 
 * These routines are portable versions that implement a protocol
 * compatible with the original Unix "sendauth".
 */

/*
 * The first argument to krb_mk_auth() contains a bitfield of
 * options (the options are defined in "krb.h"):
 *
 * KOPT_DONT_CANON	Don't canonicalize instance as a hostname.
 *			(If this option is not chosen, krb_get_phost()
 *			is called to canonicalize it.)
 *
 * KOPT_DONT_MK_REQ 	Don't request server ticket from Kerberos.
 *			A ticket must be supplied in the "ticket"
 *			argument.
 *			(If this option is not chosen, and there
 *			is no ticket for the given server in the
 *			ticket cache, one will be fetched using
 *			krb_mk_req() and returned in "ticket".)
 *
 * KOPT_DO_MUTUAL	Do mutual authentication, requiring that the
 * 			receiving server return the checksum+1 encrypted
 *			in the session key.  The mutual authentication
 *			is done using krb_mk_priv() on the other side
 *			(see "recvauth.c") and krb_rd_priv() on this
 *			side.
 *
 * The "ticket" argument is used to store the new ticket
 * from the krb_mk_req() call. If the KOPT_DONT_MK_REQ options is
 * chosen, the ticket must be supplied in the "ticket" argument.
 * The "service", "inst", and "realm" arguments identify the ticket.
 * If "realm" is null, the local realm is used.
 *
 * The following argument is only needed if the KOPT_DO_MUTUAL option
 * is chosen:
 *
 *   The "checksum" argument is a number that the server will add 1 to
 *   to authenticate itself back to the client.
 *
 * The application protocol version number (of up to KRB_SENDAUTH_VLEN
 * characters) is passed in "version".
 *
 * The ticket is packaged into a message in the buffer pointed to by
 * the argument "buf".
 *
 * If all goes well, KSUCCESS is returned, otherwise some error code.
 *
 * The format of the message packaged to send to the application server is:
 *
 * Size			Variable		Field
 * ----			--------		-----
 *
 * KRB_SENDAUTH_VLEN	KRB_SENDAUTH_VER	sendauth protocol
 * bytes					version number
 *
 * KRB_SENDAUTH_VLEN	version			application protocol
 * bytes					version number
 *
 * 4 bytes		ticket->length		length of ticket
 *
 * ticket->length	ticket->dat		ticket itself
 */

/*
 * Build a "sendauth" packet compatible with Unix sendauth/recvauth.
 */
int KRB5_CALLCONV
krb_mk_auth(options, ticket, service, inst, realm, checksum, version, buf)
     long options;		/* bit-pattern of options */
     KTEXT ticket;		/* where to put ticket (return); or
				   supplied in case of KOPT_DONT_MK_REQ */
     char *service;		/* service name */
     char *inst;		/* instance (OUTPUT canonicalized) */
     char *realm;		/* realm */
     unsigned KRB4_32 checksum; /* checksum to include in request */
     char *version;		/* version string */
     KTEXT buf;			/* Output buffer to fill  */
{
    int rem;
    char krb_realm[REALM_SZ];
    char *phost;
    int phostlen;
    unsigned char *p;

    rem = KSUCCESS;

    /* get current realm if not passed in */
    if (!realm) {
	rem = krb_get_lrealm(krb_realm,1);
	if (rem != KSUCCESS)
	    return rem;
	realm = krb_realm;
    }

    if (!(options & KOPT_DONT_CANON)) {
	phost = krb_get_phost(inst);
	phostlen = krb4int_strnlen(phost, INST_SZ) + 1;
	if (phostlen <= 0 || phostlen > INST_SZ)
	    return KFAILURE;
	memcpy(inst, phost, (size_t)phostlen);
    }

    /* get the ticket if desired */
    if (!(options & KOPT_DONT_MK_REQ)) {
	rem = krb_mk_req(ticket, service, inst, realm, (KRB4_32)checksum);
	if (rem != KSUCCESS)
	    return rem;
    }

#ifdef ATHENA_COMPAT
    /* this is only for compatibility with old servers */
    if (options & KOPT_DO_OLDSTYLE) {
	(void) sprintf(buf->dat,"%d ",ticket->length);
	(void) write(fd, buf, strlen(buf));
	(void) write(fd, (char *) ticket->dat, ticket->length);
	return(rem);
    }
#endif /* ATHENA_COMPAT */

    /* Check buffer size */
    if (sizeof(buf->dat) < (KRB_SENDAUTH_VLEN + KRB_SENDAUTH_VLEN
			    + 4 + ticket->length)
	|| ticket->length < 0)
	return KFAILURE;

    /* zero the buffer */
    memset(buf->dat, 0, sizeof(buf->dat));
    p = buf->dat;

    /* insert version strings */
    strncpy((char *)p, KRB_SENDAUTH_VERS, KRB_SENDAUTH_VLEN);
    p += KRB_SENDAUTH_VLEN;
    strncpy((char *)p, version, KRB_SENDAUTH_VLEN);
    p += KRB_SENDAUTH_VLEN;

    /* put ticket length into buffer */
    KRB4_PUT32BE(p, ticket->length);

    /* put ticket into buffer */
    memcpy(p, ticket->dat, (size_t)ticket->length);
    p += ticket->length;

    buf->length = p - buf->dat;
    return KSUCCESS;
}

/*
 * For mutual authentication using mk_auth, check the server's response
 * to validate that we're really talking to the server which holds the
 * key that we obtained from the Kerberos key server.
 *
 * The "buf" argument is the response we received from the app server.
 * The "checksum" argument is a number that the server has added 1 to
 * to authenticate itself back to the client (us); the "msg_data" argument
 * returns the returned mutual-authentication message from the server
 * (i.e., the checksum+1); "session" holds the
 * session key of the server, extracted from the ticket file, for use
 * in decrypting the mutual authentication message from the server;
 * and "schedule" returns the key schedule for that decryption.  The
 * the local and server addresses are given in "laddr" and "faddr".
 */
int KRB5_CALLCONV
krb_check_auth (buf, checksum, msg_data, session, schedule, laddr, faddr)
     KTEXT buf;			/* The response we read from app server */
     unsigned KRB4_32 checksum; /* checksum we included in request */
     MSG_DAT *msg_data;	/* mutual auth MSG_DAT (return) */
     C_Block session;		/* credentials (input) */
     Key_schedule schedule;	/* key schedule (return) */
     struct sockaddr_in *laddr;	/* local address */
     struct sockaddr_in *faddr;	/* address of foreign host on fd */
{
    int cc;
    unsigned KRB4_32 cksum;
    unsigned char *p;

    /* decrypt it */
#ifndef NOENCRYPTION
    key_sched(session, schedule);
#endif /* !NOENCRYPTION */
    if (buf->length < 0)
	return KFAILURE;
    cc = krb_rd_priv(buf->dat, (unsigned KRB4_32)buf->length, schedule,
		     (C_Block *)session, faddr, laddr, msg_data);
    if (cc)
	return cc;

    /*
     * Fetch the (incremented) checksum that we supplied in the
     * request.
     */
    if (msg_data->app_length < 4)
	return KFAILURE;
    p = msg_data->app_data;
    KRB4_GET32BE(cksum, p);

    /* if it doesn't match, fail -- reply wasn't from our real server.  */
    if (cksum != checksum + 1)
	return KFAILURE;	/* XXX */
    return KSUCCESS;
}
