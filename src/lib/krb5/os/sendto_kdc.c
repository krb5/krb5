/*
 * lib/krb5/os/sendto_kdc.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * 
 *
 * Send packet to KDC for realm; wait for response, retransmitting
 * as necessary.
 */

#define NEED_SOCKETS
#define NEED_LOWLEVEL_IO
#include "fake-addrinfo.h"
#include "k5-int.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#include "os-proto.h"

#ifdef _AIX
#include <sys/select.h>
#endif

/*
 * send the formatted request 'message' to a KDC for realm 'realm' and
 * return the response (if any) in 'reply'.
 *
 * If the message is sent and a response is received, 0 is returned,
 * otherwise an error code is returned.
 *
 * The storage for 'reply' is allocated and should be freed by the caller
 * when finished.
 */

krb5_error_code
krb5_sendto_kdc (context, message, realm, reply, use_master)
    krb5_context context;
    const krb5_data * message;
    const krb5_data * realm;
    krb5_data * reply;
    int use_master;
{
    krb5_error_code retval;
    struct addrlist addrs;

    /*
     * find KDC location(s) for realm
     */

    if ((retval = krb5_locate_kdc(context, realm, &addrs, use_master, SOCK_DGRAM)))
	return retval;
    if (addrs.naddrs == 0)
	return (use_master ? KRB5_KDC_UNREACH : KRB5_REALM_UNKNOWN);
    retval = krb5int_sendto_udp (context, message, &addrs, reply);
    krb5int_free_addrlist (&addrs);
    return retval;
}

krb5_error_code
krb5int_sendto_udp (krb5_context context, const krb5_data *message,
		    const struct addrlist *addrs, krb5_data *reply)
{
    int timeout, host, i;
    int sent, nready;
    krb5_error_code retval;
    SOCKET *socklist;
    fd_set readable;
    struct timeval waitlen;
    int cc;

    socklist = (SOCKET *)malloc(addrs->naddrs * sizeof(SOCKET));
    if (socklist == NULL) {
	return ENOMEM;
    }
    for (i = 0; i < addrs->naddrs; i++)
	socklist[i] = INVALID_SOCKET;

    if (!(reply->data = malloc(krb5_max_dgram_size))) {
	krb5_xfree(socklist);
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
	krb5_xfree(socklist);
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
	for (host = 0; host < addrs->naddrs; host++) {
	    if (addrs->addrs[host]->ai_socktype != SOCK_DGRAM)
		continue;
	    /* Send to the host, wait timeout seconds for a response,
	       then move on. */
	    /* Cache some sockets for each host.  */
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
#ifdef DEBUG
		fprintf (stderr, "getting dgram socket in family %d...",
			 addrs->addrs[host]->ai_family);
#endif
		socklist[host] = socket(addrs->addrs[host]->ai_family,
					SOCK_DGRAM, 0);
		if (socklist[host] == INVALID_SOCKET) {
#ifdef DEBUG
		    perror ("socket");
		    fprintf (stderr, "af was %d\n", addrs->addrs[host]->ai_family);
#endif
		    continue;		/* try other hosts */
		}
#ifdef DEBUG
		{
		    char addrbuf[NI_MAXHOST], portbuf[NI_MAXSERV];
		    if (0 != getnameinfo (addrs->addrs[host]->ai_addr,
					  addrs->addrs[host]->ai_addrlen,
					  addrbuf, sizeof (addrbuf),
					  portbuf, sizeof (portbuf),
					  NI_NUMERICHOST | NI_NUMERICSERV))
			strcpy (addrbuf, "??"), strcpy (portbuf, "??");
		    fprintf (stderr, " fd %d; connecting to %s port %s...",
			     socklist[host], addrbuf, portbuf);
		}
#endif
		/* have a socket to send/recv from */
		/* On BSD systems, a connected UDP socket will get connection
		   refused and net unreachable errors while an unconnected
		   socket will time out, so use connect, send, recv instead of
		   sendto, recvfrom.  The connect here may return an error if
		   the destination host is known to be unreachable. */
		if (connect(socklist[host], addrs->addrs[host]->ai_addr,
			    addrs->addrs[host]->ai_addrlen) == SOCKET_ERROR) {
#ifdef DEBUG
		    perror ("connect");
#endif
		    continue;
		}
	    }
#ifdef DEBUG
	    fprintf (stderr, "sending...");
#endif
	    if (send(socklist[host],
		       message->data, message->length, 0) 
		!= message->length) {
#ifdef DEBUG
		perror ("sendto");
#endif
		continue;
	    }
#ifdef DEBUG
	    fprintf (stderr, "\n");
#endif
	retry:
	    waitlen.tv_usec = 0;
	    waitlen.tv_sec = timeout;
	    FD_ZERO(&readable);
	    FD_SET(socklist[host], &readable);
	    if ((nready = select(SOCKET_NFDS(socklist[host]),
				 &readable,
				 0,
				 0,
				 &waitlen))) {
		if (nready == SOCKET_ERROR) {
		    if (SOCKET_ERRNO == SOCKET_EINTR)
			goto retry;
		    retval = SOCKET_ERRNO;
		    goto out;
		}
		if ((cc = recv(socklist[host],
			       reply->data, reply->length, 
			       0)) == SOCKET_ERROR)
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
    for (i = 0; i < addrs->naddrs; i++)
	if (socklist[i] != INVALID_SOCKET)
	    (void) closesocket (socklist[i]);
#if 0
    SOCKET_CLEANUP();                           /* Done with sockets for now */
#endif
    krb5_xfree(socklist);
    if (retval) {
	free(reply->data);
	reply->data = 0;
	reply->length = 0;
    }
    return retval;
}
