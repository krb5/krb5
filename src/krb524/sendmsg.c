/*
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
 * Send a packet to a service and await a reply, using an exponential
 * backoff retry algorithm.  This is based on krb5_sendto_kdc.
 */

#include "krb5.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#ifdef _AIX
#include <sys/select.h>
#endif

#include <krb.h>
#include "krb524.h"

/*
 * Send the formatted request 'message' to the host/port specified in
 * addr and return the response (if any) in 'reply'.
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

int krb524_send_message
	KRB5_PROTOTYPE((const struct sockaddr * addr, const krb5_data * message,
		   krb5_data * reply));


int krb524_send_message (addr, message, reply)
     const struct sockaddr * addr;
     const krb5_data * message;
     krb5_data * reply;
{
    register int timeout;
    int nready, received;
    krb5_error_code retval;
    fd_set readable;
    struct timeval waitlen;
    int s, cc;
    
    if ((reply->data = malloc(krb5_max_dgram_size)) == NULL)
	return ENOMEM;
    reply->length = krb5_max_dgram_size;

    /* XXX 4.2/4.3BSD has PF_xxx = AF_xxx, so the */
    /* socket creation here will work properly... */
    s = socket(addr->sa_family, SOCK_DGRAM, 0);
    if (s == -1) {
	 retval = errno;
	 goto out;
    }
    
    /*
     * On BSD systems, a connected UDP socket will get connection
     * refused and net unreachable errors while an unconnected socket
     * will time out, so use connect, send, recv instead of sendto,
     * recvfrom.  The connect here may return an error if the
     * destination host is known to be unreachable.
     */
    if (connect(s, (struct sockaddr *) addr, sizeof(struct sockaddr)) == -1) {
	 retval = errno;
	 goto out;
    }
	 
    /*
     * Send the message, and wait for a reply, using an exponential
     * backoff.  Use the kdc timeout values, just for consistency.
     */

    received = 0;
    for (timeout = krb5_skdc_timeout_1;
	 timeout < krb5_max_skdc_timeout;
	 timeout <<= krb5_skdc_timeout_shift) {
	 
	 if (send(s, message->data, message->length, 0) != message->length) {
	      retval = errno;
	      goto out;
	 }
	 
	 waitlen.tv_usec = 0;
	 waitlen.tv_sec = timeout;
	 FD_ZERO(&readable);
	 FD_SET(s, &readable);
	 nready = select(1 + s, &readable, 0, 0, &waitlen);
	 if (nready < 0) {
	      retval = errno;
	      goto out;
	 } else if (nready == 1) {
	      if ((cc = recv(s, reply->data, reply->length, 0)) == -1) { 
		   retval = errno;
		   goto out;
	      }

	      /*
	       * We might consider here verifying that the reply came
	       * from the host specified, but that check can be fouled
	       * by some implementations of some network types which
	       * might show a loopback return address, for example, if
	       * the server is on the same host as the client.
	       *
	       * Besides, reply addresses can be spoofed, and we don't
	       * want to provide a false sense of security.
	       */
	      reply->length = cc;
	      retval = 0;
	      goto out;
	 }
	 /* else timeout, try again */
    }

    /* If the loop exits normally, the max timeout expired without */
    /* a reply having arrived.  */
    retval = KRB524_NOTRESP;

out:
    (void) close(s);
    if (retval) {
	 free(reply->data);
	 reply->data = 0;
	 reply->length = 0;
    }
    return retval;
}
