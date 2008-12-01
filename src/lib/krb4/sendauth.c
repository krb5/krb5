/*
 * sendauth.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 */

#include "mit-copyright.h"

#include "krb.h"
#include "krb4int.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "port-sockets.h"

#define	KRB_SENDAUTH_VERS "AUTHV0.1" /* MUST be KRB_SENDAUTH_VLEN chars */
/*
 * If the protocol changes, you will need to change the version string
 * and make appropriate changes in krb_recvauth.c
 */

/*
 * This file contains two routines: krb_sendauth() and krb_sendsrv().
 *
 * krb_sendauth() transmits a ticket over a file descriptor for a
 * desired service, instance, and realm, doing mutual authentication
 * with the server if desired.
 *
 * Most of the real work of krb_sendauth() has been moved into mk_auth.c
 * for portability; sendauth takes a Unix file descriptor as argument,
 * which doesn't work on other operating systems.
 *
 * krb_sendsvc() sends a service name to a remote knetd server, and is
 * only for Athena compatability.
 */

/*
 * The first argument to krb_sendauth() contains a bitfield of
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
 * The "fd" argument is a file descriptor to write to the remote
 * server on.  The "ticket" argument is used to store the new ticket
 * from the krb_mk_req() call. If the KOPT_DONT_MK_REQ options is
 * chosen, the ticket must be supplied in the "ticket" argument.
 * The "service", "inst", and "realm" arguments identify the ticket.
 * If "realm" is null, the local realm is used.
 *
 * The following arguments are only needed if the KOPT_DO_MUTUAL option
 * is chosen:
 *
 *   The "checksum" argument is a number that the server will add 1 to
 *   to authenticate itself back to the client; the "msg_data" argument
 *   holds the returned mutual-authentication message from the server
 *   (i.e., the checksum+1); the "cred" structure is used to hold the
 *   session key of the server, extracted from the ticket file, for use
 *   in decrypting the mutual authentication message from the server;
 *   and "schedule" holds the key schedule for that decryption.  The
 *   the local and server addresses are given in "laddr" and "faddr".
 *
 * The application protocol version number (of up to KRB_SENDAUTH_VLEN
 * characters) is passed in "version".
 *
 * If all goes well, KSUCCESS is returned, otherwise some error code.
 *
 * The format of the message sent to the server is:
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
 * XXX: Note that krb_rd_priv() is coded in such a way that
 * "msg_data->app_data" will be pointing into "packet", which
 * will disappear when krb_sendauth() returns.
 * 
 * See FIXME KLUDGE code in appl/bsd/kcmd.c.
 */
KRB4_32 __krb_sendauth_hidden_tkt_len=0;
#define raw_tkt_len __krb_sendauth_hidden_tkt_len


/* 
 * Read a server's sendauth response out of a file descriptor.
 * Returns a Kerberos error code.
 *
 * Note sneaky code using raw_tkt_len to stash away a bit of info
 * for use by appl/bsd/kcmd.c.  Now that krb_net_rd_sendauth is
 * a separate function, kcmd should call it directly to get this
 * sneaky info.  
 */
int
krb_net_rd_sendauth (fd, reply, raw_len)
     int fd;			/* file descriptor to write onto */
     KTEXT reply;		/* Where we put the reply message */
     KRB4_32 *raw_len;		/* Where to read the length field info */
{
    KRB4_32 tkt_len;
    int got;

    reply->length = 0;		/* Nothing read from net yet */
    reply->mbz = 0;

    /* get the length of the reply */
  reread:
    got = krb_net_read(fd, (char *)raw_len, sizeof(KRB4_32));
    if (got != sizeof(KRB4_32))
	return KFAILURE;

    /* Here's an amazing hack.  If we are contacting an rlogin server,
       and it is running on a Sun4, and it was compiled with the wrong
       shared libary version, it will print an ld.so warning message
       when it starts up.  We just ignore any such message and keep
       going.  This doesn't affect security: we just require the
       ticket to follow the warning message.  */
    if (!memcmp("ld.s", raw_len, 4)) {
    	char c;

	while (krb_net_read(fd, &c, 1) == 1 && c != '\n')
	    ;
	goto reread;
    }

    tkt_len = ntohl(*raw_len);

    /* if the length is negative, the server failed to recognize us. */
    if ((tkt_len < 0) || (tkt_len > sizeof(reply->dat)))
	return KFAILURE;	 /* XXX */
    /* read the reply... */
    got = krb_net_read(fd, (char *)reply->dat, (int) tkt_len);
    if (got != (int) tkt_len)
	return KFAILURE;

    reply->length = tkt_len;
    reply->mbz = 0;
    return KSUCCESS;
}


/*
 * krb_sendauth
 * 
 * The original routine, provided on Unix.
 * Obtains a service ticket using the ticket-granting ticket,
 * uses it to stuff an authorization request down a Unix socket to the
 * end-user application server, sucks a response out of the socket, 
 * and decodes it to verify mutual authentication.
 */
int KRB5_CALLCONV
krb_sendauth(options, fd, ticket, service, inst, realm, checksum,
	     msg_data, cred, schedule, laddr, faddr, version)
     long options;		/* bit-pattern of options */
     int fd;			/* file descriptor to write onto */
     KTEXT ticket;		/* where to put ticket (return); or
				   supplied in case of KOPT_DONT_MK_REQ */
     char *service;         /* service name */
     char *inst;            /* service instance */
     char *realm;           /* service realm */
     unsigned KRB4_32 checksum; /* checksum to include in request */
     MSG_DAT *msg_data;		/* mutual auth MSG_DAT (return) */
     CREDENTIALS *cred;		/* credentials (return) */
     Key_schedule schedule;	/* key schedule (return) */
     struct sockaddr_in *laddr;	/* local address */
     struct sockaddr_in *faddr;	/* address of foreign host on fd */
     char *version;		/* version string */
{
    int rem, cc;
    char srv_inst[INST_SZ];
    char krb_realm[REALM_SZ];
    KTEXT_ST packet[1];		/* Re-use same one for msg and reply */

    /* get current realm if not passed in */
    if (!realm) {
	rem = krb_get_lrealm(krb_realm,1);
	if (rem != KSUCCESS)
	    return(rem);
	realm = krb_realm;
    }

    /* copy instance into local storage, so mk_auth can canonicalize */
    (void) strncpy(srv_inst, inst, INST_SZ-1);
    srv_inst[INST_SZ-1] = 0;
    rem = krb_mk_auth (options, ticket, service, srv_inst, realm, checksum,
   			   version, packet);
    if (rem != KSUCCESS)
	return rem;

#ifdef ATHENA_COMPAT
    /* this is only for compatibility with old servers */
    if (options & KOPT_DO_OLDSTYLE) {
	(void) sprintf(buf,"%d ",ticket->length);
	(void) write(fd, buf, strlen(buf));
	(void) write(fd, (char *) ticket->dat, ticket->length);
	return(rem);
    }
#endif /* ATHENA_COMPAT */

    /* write the request to the server */
    if ((cc = krb_net_write(fd, packet->dat, packet->length)) != packet->length)
	return(cc);

    /* mutual authentication, if desired */
    if (options & KOPT_DO_MUTUAL) {
	/* get credentials so we have service session
	   key for decryption below */
	cc = krb_get_cred(service, srv_inst, realm, cred);
	if (cc)
	    return(cc);

	/* Get the reply out of the socket.  */
	cc = krb_net_rd_sendauth (fd, packet, &raw_tkt_len);
	if (cc != KSUCCESS)
	    return cc;

	/* Check the reply to verify that server is really who we expect.  */
	cc = krb_check_auth (packet, checksum,
		msg_data, cred->session, schedule, laddr, faddr);
	if (cc != KSUCCESS)
	    return cc;
    }
    return(KSUCCESS);
}


#ifdef ATHENA_COMPAT
/*
 * krb_sendsvc
 */

int
krb_sendsvc(fd, service)
     int fd;
     char *service;
{
    /* write the service name length and then the service name to
       the fd */
    KRB4_32 serv_length;
    int cc;

    serv_length = htonl((unsigned long)strlen(service));
    if ((cc = krb_net_write(fd, (char *) &serv_length,
	sizeof(serv_length)))
	!= sizeof(serv_length))
	return(cc);
    if ((cc = krb_net_write(fd, service, strlen(service)))
	!= strlen(service))
	return(cc);
    return(KSUCCESS);
}
#endif /* ATHENA_COMPAT */
