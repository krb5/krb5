/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Send packet to KDC for realm; wait for response, retransmitting
 * as necessary.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_sendto_kdc_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <krb5/libos-proto.h>
#include "os-proto.h"

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
    struct sockaddr fromaddr;
    int fromlen, cc;

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
	free((char *)addr);
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
	    if (sendto(socklist[addr[host].sa_family],
		       message->data,
		       message->length,
		       0,
		       &addr[host],
		       sizeof(addr[host])) != message->length)
		continue;
	    else
		sent = 1;
	    waitlen.tv_usec = 0;
	    waitlen.tv_sec = timeout;
	    FD_ZERO(&readable);
	    FD_SET(socklist[addr[host].sa_family], &readable);
	    if (nready = select(1<<socklist[addr[host].sa_family],
				&readable,
				0,
				0,
				&waitlen)) {
		if (nready == -1) {
		    if (errno == EINTR)
			continue;
		    retval = errno;
		    goto out;
		}
		if ((cc = recvfrom(socklist[addr[host].sa_family],
				   reply->data,
				   reply->length,
				   0,
				   &fromaddr,
				   &fromlen)) == -1)
		    continue;		/* XXX */
		if (bcmp((char *)&fromaddr, (char *)&addr[host],
			 fromlen)) {
		    /* not from this one, perhaps from an earlier
		       request? */
		    for (i = host-1; i >= 0; i--) {
			if (!bcmp((char *)&fromaddr, (char *)&addr[host],
				  fromlen))
			    break;
		    }
		    if (i < 0)		/* not from someone we asked */
			continue;	/* XXX */
		}
		/* reply came from where we sent a request,
		   so clean up and return. */
		reply->length = cc;
		retval = 0;
		goto out;
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
    free((char *)addr);
    if (retval) {
	free(reply->data);
	reply->data = 0;
	reply->length = 0;
    }
    return retval;
}
