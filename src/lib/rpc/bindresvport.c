/* lib/rpc/bindresvport.c */
/*
 * Copyright (c) 2010, Oracle America, Inc.
 * Copyright (c) 2014, Andreas Schneider <asn@samba.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the "Oracle America, Inc." nor the names of
 *       its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gssrpc/rpc.h>
#include <errno.h>

int
bindresvport_sa(int sd, struct sockaddr *sa)
{
	struct sockaddr_storage myaddr;
	socklen_t salen;
	static short port;
	int af;
	short i;
	int rc;

#define STARTPORT 600
#define ENDPORT   (IPPORT_RESERVED - 1)
#define NPORTS    (ENDPORT - STARTPORT + 1)

	if (port == 0) {
		port = (getpid() % NPORTS) + STARTPORT;
	}

	if (sa == NULL) {
		salen = sizeof(myaddr);
		sa = (struct sockaddr *)&myaddr;

		rc = getsockname(sd, (struct sockaddr *)&myaddr, &salen);
		if (rc < 0) {
			return -1;
		}

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} else {
		af = sa->sa_family;
	}

	for (i = 0; i < NPORTS; i++, port++) {
		switch(af) {
		case AF_INET: {
			struct sockaddr_in *sinp = (struct sockaddr_in *)sa;

			salen = sizeof(struct sockaddr_in);
			sinp->sin_port = htons(port);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sin6p = (struct sockaddr_in6 *)sa;

			salen = sizeof(struct sockaddr_in6);
			sin6p->sin6_port = htons(port);
			break;
		}
		default:
			errno = EAFNOSUPPORT;
			return -1;
		}
		sa->sa_family = af;

		if (port > ENDPORT) {
			port = STARTPORT;
		}

		rc = bind(sd, (struct sockaddr *)sa, salen);
		if (rc == 0 || errno != EADDRINUSE) {
			break;
		}
	}

	return rc;
}

/*
 * Bind a socket to a privileged IP port
 */
int
bindresvport(int sd, struct sockaddr_in *sockin)
{
	return bindresvport_sa(sd, (struct sockaddr *)sockin);
}
