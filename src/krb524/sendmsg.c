/*
 * Copyright 1990,1991,1997 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * Send a packet to a service and await a reply, using an exponential
 * backoff retry algorithm.  This is based on krb5_sendto_kdc.
 */

/* Grab socket stuff.  This might want to go away later. */
#define NEED_SOCKETS
#define NEED_LOWLEVEL_IO
#include "k5-int.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>

#ifdef _AIX
#include <sys/select.h>
#endif

#include <krb.h>
#include "krb524.h"

/* Cheat and grab this internal function from lib/krb5/os. */
krb5_error_code krb5_locate_kdc
    PROTOTYPE((krb5_context, const krb5_data *,
	       struct sockaddr **, int *));

/*
 * krb524_sendto_kdc:
 *
 * A slightly modified version of krb5_sendto_kdc.
 *
 * send the formatted request 'message' to a KDC for realm 'realm' and
 * return the response (if any) in 'reply'.
 *
 * If the message is sent and a response is received, 0 is returned,
 * otherwise an error code is returned.
 *
 * The storage for 'reply' is allocated and should be freed by the caller
 * when finished.
 */

extern int krb5_max_dgram_size;
extern int krb5_max_skdc_timeout;
extern int krb5_skdc_timeout_shift;
extern int krb5_skdc_timeout_1;

krb5_error_code
krb524_sendto_kdc (context, message, realm, reply)
    krb5_context context;
    const krb5_data * message;
    const krb5_data * realm;
    krb5_data * reply;
{
    register int timeout, host, i;
    struct sockaddr *addr;
    int naddr;
    struct servent *serv;
    int sent, nready;
    krb5_error_code retval;
    SOCKET *socklist;
    fd_set readable;
    struct timeval waitlen;
    int cc;

    /*
     * find KDC location(s) for realm
     */

    if (retval = krb5_locate_kdc (context, realm, &addr, &naddr))
	return retval;
    if (naddr == 0)
	return KRB5_REALM_UNKNOWN;

    socklist = (SOCKET *)malloc(naddr * sizeof(SOCKET));
    if (socklist == NULL) {
	free(addr);
	return ENOMEM;
    }
    for (i = 0; i < naddr; i++)
	socklist[i] = INVALID_SOCKET;

    /*
     * Bash the ports numbers.
     */
    serv = getservbyname(KRB524_SERVICE, "udp");
    for (i = 0; i < naddr; i++)
	if (serv)
	    ((struct sockaddr_in *)&addr[i])->sin_port = serv->s_port;
	else
	    ((struct sockaddr_in *)&addr[i])->sin_port = htons(KRB524_PORT);

    if (!(reply->data = malloc(krb5_max_dgram_size))) {
	free(addr);
	free(socklist);
	return ENOMEM;
    }
    reply->length = krb5_max_dgram_size;

#if 0
    /*
     * Not needed for Windows, since it's done by the DLL
     * initialization. XXX What about for the Macintosh?
     *
     * See below for commented out SOCKET_CLEANUP()
     */
    if (SOCKET_INITIALIZE()) {  /* PC needs this for some tcp/ip stacks */
	free(addr);
	free(socklist);
	free(reply->data);
        return SOCKET_ERRNO;
    }
#endif

    /*
     * do exponential backoff.
     */

    for (timeout = krb5_skdc_timeout_1; timeout < krb5_max_skdc_timeout;
	 timeout <<= krb5_skdc_timeout_shift) {
	sent = 0;
	for (host = 0; host < naddr; host++) {
	    /* send to the host, wait timeout seconds for a response,
	       then move on. */
	    /* cache some sockets for each host */
	    if (socklist[host] == INVALID_SOCKET) {
		/* XXX 4.2/4.3BSD has PF_xxx = AF_xxx, so the socket
		   creation here will work properly... */
		/*
		 * From socket(2):
		 *
		 * The protocol specifies a particular protocol to be
		 * used with the socket.  Normally only a single
		 * protocol exists to support a particular socket type
		 * within a given protocol family.
		 */
		socklist[host] = socket(addr[host].sa_family, SOCK_DGRAM, 0);
		if (socklist[host] == INVALID_SOCKET)
		    continue;		/* try other hosts */
		/* have a socket to send/recv from */
		/* On BSD systems, a connected UDP socket will get connection
		   refused and net unreachable errors while an unconnected
		   socket will time out, so use connect, send, recv instead of
		   sendto, recvfrom.  The connect here may return an error if
		   the destination host is known to be unreachable. */
		if (connect(socklist[host],
			    &addr[host], sizeof(addr[host])) == SOCKET_ERROR)
		  continue;
	    }
	    if (send(socklist[host],
		       message->data, message->length, 0) != message->length)
	      continue;
	retry:
	    waitlen.tv_usec = 0;
	    waitlen.tv_sec = timeout;
	    FD_ZERO(&readable);
	    FD_SET(socklist[host], &readable);
	    if (nready = select(SOCKET_NFDS(socklist[host]),
				&readable,
				0,
				0,
				&waitlen)) {
		if (nready == SOCKET_ERROR) {
		    if (SOCKET_ERRNO == SOCKET_EINTR)
			goto retry;
		    retval = SOCKET_ERRNO;
		    goto out;
		}
		if ((cc = recv(socklist[host],
			       reply->data, reply->length, 0)) == SOCKET_ERROR)
		  {
		    /* man page says error could be:
		       EBADF: won't happen
		       ENOTSOCK: it's a socket.
		       EWOULDBLOCK: not marked non-blocking, and we selected.
		       EINTR: could happen
		       EFAULT: we allocated the reply packet.

		       In addition, net related errors like ECONNREFUSED
		       are possble (but undocumented).  Assume anything
		       other than EINTR is a permanent error for the
		       server (i.e. don't set sent = 1).
		       */

		    if (SOCKET_ERRNO == SOCKET_EINTR)
		      sent = 1;
		    continue;
		  }

		/* We might consider here verifying that the reply
		   came from one of the KDC's listed for that address type,
		   but that check can be fouled by some implementations of
		   some network types which might show a loopback return
		   address, for example, if the KDC is on the same host
		   as the client. */

		reply->length = cc;
		retval = 0;
		goto out;
	    } else if (nready == 0) {
		/* timeout */
	        sent = 1;
	    }
	    /* not ready, go on to next server */
	}
	if (!sent) {
	    /* never were able to send to any servers; give up */
	    retval = KRB5_KDC_UNREACH;
	    break;
	}
    }
    retval = KRB5_KDC_UNREACH;
 out:
    for (i = 0; i < naddr; i++)
	if (socklist[i] != INVALID_SOCKET)
	    (void) closesocket (socklist[i]);
#if 0
    SOCKET_CLEANUP();                           /* Done with sockets for now */
#endif
    free(addr);
    free(socklist);
    if (retval) {
	free(reply->data);
	reply->data = 0;
	reply->length = 0;
    }
    return retval;
}
