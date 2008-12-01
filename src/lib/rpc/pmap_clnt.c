/* @(#)pmap_clnt.c	2.2 88/08/01 4.0 RPCSRC */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
#if !defined(lint) && defined(SCCSIDS)
static char sccsid[] = "@(#)pmap_clnt.c 1.37 87/08/11 Copyr 1984 Sun Micro";
#endif

/*
 * pmap_clnt.c
 * Client interface to pmap rpc service.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#include <unistd.h>
#include <gssrpc/rpc.h>
#include <gssrpc/pmap_prot.h>
#include <gssrpc/pmap_clnt.h>

#if TARGET_OS_MAC
#include <sys/un.h>
#include <string.h>
#include <syslog.h>
#endif

static struct timeval timeout = { 5, 0 };
static struct timeval tottimeout = { 60, 0 };

void clnt_perror();

/*
 * Set a mapping between program,version and port.
 * Calls the pmap service remotely to do the mapping.
 */
bool_t
pmap_set(
	rpcprog_t program,
	rpcvers_t version,
	rpcprot_t protocol,
	u_int port)
{
	struct sockaddr_in myaddress;
	int sock = -1;
	register CLIENT *client;
	struct pmap parms;
	bool_t rslt;

	get_myaddress(&myaddress);
	client = clntudp_bufcreate(&myaddress, PMAPPROG, PMAPVERS,
	    timeout, &sock, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
	if (client == (CLIENT *)NULL)
		return (FALSE);
	parms.pm_prog = program;
	parms.pm_vers = version;
	parms.pm_prot = protocol;
	parms.pm_port = port;
#if TARGET_OS_MAC
	{
	    /*
	     * Poke launchd, then wait for portmap to start up.
	     *
	     * My impression is that the protocol involves getting
	     * something back from the server.  So wait, briefly, to
	     * see if it's going to send us something.  Then continue
	     * on, regardless.  I don't actually check what the data
	     * is, because I have no idea what sort of validation, if
	     * any, is needed.
	     *
	     * However, for whatever reason, the socket seems to be
	     * mode 700 owner root on my system, so if you don't
	     * change its ownership or mode, and if the program isn't
	     * running as root, you still lose.
	     */
#define TICKLER_SOCKET "/var/run/portmap.socket"
	    int tickle;
	    struct sockaddr_un a = {
		.sun_family = AF_UNIX,
		.sun_path = TICKLER_SOCKET,
		.sun_len = (sizeof(TICKLER_SOCKET)
			    + offsetof(struct sockaddr_un, sun_path)),
	    };

	    if (sizeof(TICKLER_SOCKET) <= sizeof(a.sun_path)) {
		tickle = socket(AF_UNIX, SOCK_STREAM, 0);
		if (tickle >= 0) {
		    if (connect(tickle, (struct sockaddr *)&a, a.sun_len) == 0
			&& tickle < FD_SETSIZE) {
			fd_set readfds;
			struct timeval tv;

			FD_ZERO(&readfds);
			/* XXX Range check.  */
			FD_SET(tickle, &readfds);
			tv.tv_sec = 5;
			tv.tv_usec = 0;
			(void) select(tickle+1, &readfds, 0, 0, &tv);
		    }
		    close(tickle);
		}
	    }
	}
#endif
	if (CLNT_CALL(client, PMAPPROC_SET, xdr_pmap, &parms, xdr_bool, &rslt,
	    tottimeout) != RPC_SUCCESS) {
		clnt_perror(client, "Cannot register service");
		return (FALSE);
	}
	CLNT_DESTROY(client);
	(void)close(sock);
	return (rslt);
}

/*
 * Remove the mapping between program,version and port.
 * Calls the pmap service remotely to do the un-mapping.
 */
bool_t
pmap_unset(
	rpcprog_t program,
	rpcvers_t version)
{
	struct sockaddr_in myaddress;
	int socket = -1;
	register CLIENT *client;
	struct pmap parms;
	bool_t rslt;

	get_myaddress(&myaddress);
	client = clntudp_bufcreate(&myaddress, PMAPPROG, PMAPVERS,
	    timeout, &socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
	if (client == (CLIENT *)NULL)
		return (FALSE);
	parms.pm_prog = program;
	parms.pm_vers = version;
	parms.pm_port = parms.pm_prot = 0;
	CLNT_CALL(client, PMAPPROC_UNSET, xdr_pmap, &parms, xdr_bool, &rslt,
	    tottimeout);
	CLNT_DESTROY(client);
	(void)close(socket);
	return (rslt);
}
