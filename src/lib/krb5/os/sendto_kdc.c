/*
 * $Source$
 * $Author$
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Send packet to KDC for realm; wait for response, retransmitting
 * as necessary.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_sendto_kdc_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <krb5/los-proto.h>
#include "os-proto.h"

#ifdef _AIX
#include <sys/select.h>
#endif

#ifndef AF_MAX
/* good enough -- only missing on old linux so far anyhow. */
#define AF_MAX 10
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
 *
 */


extern int krb5_max_dgram_size;
extern int krb5_max_skdc_timeout;
extern int krb5_skdc_timeout_shift;
extern int krb5_skdc_timeout_1;

krb5_error_code
krb5_sendto_kdc (DECLARG(const krb5_data *, message),
		 DECLARG(const krb5_data *, realm),
		 DECLARG(krb5_data *, reply))
OLDDECLARG(const krb5_data *, message)
OLDDECLARG(const krb5_data *, realm)
OLDDECLARG(krb5_data *, reply)
{
    register int timeout, host, i;
    struct sockaddr *addr;
    int naddr;
    int sent, nready;
    krb5_error_code retval;
    int socklist[AF_MAX];		/* one for each, if necessary! */
    fd_set readable;
    struct timeval waitlen;
    int cc;

    /*
     * find KDC location(s) for realm
     */

    if (retval = krb5_locate_kdc (realm, &addr, &naddr))
	return retval;
    if (naddr == 0)
	return KRB5_REALM_UNKNOWN;
    
    for (i = 0; i < AF_MAX; i++)
	socklist[i] = -1;

    if (!(reply->data = malloc(krb5_max_dgram_size))) {
	krb5_xfree(addr);
	return ENOMEM;
    }
    reply->length = krb5_max_dgram_size;

    /*
     * do exponential backoff.
     */

    for (timeout = krb5_skdc_timeout_1; timeout < krb5_max_skdc_timeout;
	 timeout <<= krb5_skdc_timeout_shift) {
	sent = 0;
	for (host = 0; host < naddr; host++) {
	    /* send to the host, wait timeout seconds for a response,
	       then move on. */
	    /* cache some sockets for various address families in the
	       list */
	    if (socklist[addr[host].sa_family] == -1) {
		/* XXX 4.2/4.3BSD has PF_xxx = AF_xxx, so the socket
		   creation here will work properly... */
		socklist[addr[host].sa_family] = socket(addr[host].sa_family,
							SOCK_DGRAM,
							0); /* XXX always zero? */
		if (socklist[addr[host].sa_family] == -1)
		    continue;		/* try other hosts */
	    }
	    /* have a socket to send/recv from */
	    /* On BSD systems, a connected UDP socket will get connection
	       refused and net unreachable errors while an unconnected
	       socket will time out, so use connect, send, recv instead of
	       sendto, recvfrom.  The connect here may return an error if
	       the destination host is known to be unreachable. */
	    if (connect(socklist[addr[host].sa_family],
			&addr[host], sizeof(addr[host])) == -1)
	      continue;
	    if (send(socklist[addr[host].sa_family],
		       message->data, message->length, 0) != message->length)
	      continue;
	retry:
	    waitlen.tv_usec = 0;
	    waitlen.tv_sec = timeout;
	    FD_ZERO(&readable);
	    FD_SET(socklist[addr[host].sa_family], &readable);
	    if (nready = select(1 + socklist[addr[host].sa_family],
				&readable,
				0,
				0,
				&waitlen)) {
		if (nready == -1) {
		    if (errno == EINTR)
			goto retry;
		    retval = errno;
		    goto out;
		}
		if ((cc = recv(socklist[addr[host].sa_family],
			       reply->data, reply->length, 0)) == -1)
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

		    if (errno == EINTR)
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
    for (i = 0; i < AF_MAX; i++)
	if (socklist[i] != -1)
	    (void) close(socklist[i]);
    krb5_xfree(addr);
    if (retval) {
	free(reply->data);
	reply->data = 0;
	reply->length = 0;
    }
    return retval;
}
