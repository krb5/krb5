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
 * Sample Kerberos v5 server.
 *
 * sample_server:
 * A sample Kerberos server, which reads an AP_REQ from a TCP socket,
 * decodes it, and writes back the results (in ASCII) to the client.
 *
 * Usage:
 * sample_server servername
 *
 * file descriptor 0 (zero) should be a socket connected to the requesting
 * client (this will be correct if this server is started by inetd).
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_sserver_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>

#include <ctype.h>
#include <com_err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>

#include "../sample.h"

extern krb5_deltat krb5_clockskew;

#define DEBUG

void
main(argc, argv)
int argc;
char *argv[];
{
    struct sockaddr_in peername;
    krb5_address peeraddr;
    int namelen = sizeof(peername);
    int sock = 0;			/* incoming connection fd */
    krb5_data recv_data;
    short xmitlen;
    krb5_error_code retval;
    krb5_principal server, client;
    char repbuf[BUFSIZ];
    char *cname;

    krb5_init_ets();
    /* open a log connection */

    openlog("sserver", 0, LOG_DAEMON);

    if (retval = krb5_sname_to_principal(NULL, SAMPLE_SERVICE, KRB5_NT_SRV_HST,
					 &server)) {
	syslog(LOG_ERR, "while generating service name (%s): %s",
	       SAMPLE_SERVICE, error_message(retval));
	exit(1);
    }
    
    /*
     * If user specified a port, then listen on that port; otherwise,
     * assume we've been started out of inetd.
     */
    if (argc > 2) {
	int acc;
	struct sockaddr_in sin;

	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	    syslog(LOG_ERR, "socket: %m");
	    exit(3);
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = 0;
	sin.sin_port = htons(atoi(argv[1]));
	if (bind(sock, &sin, sizeof(sin))) {
	    syslog(LOG_ERR, "bind: %m");
	    exit(3);
	}
	if (listen(sock, 1) == -1) {
	    syslog(LOG_ERR, "listen: %m");
	    exit(3);
	}
	if ((acc = accept(sock, (struct sockaddr *)&peername, &namelen)) == -1) {
	    syslog(LOG_ERR, "accept: %m");
	    exit(3);
	}
	dup2(acc, 0);
	close(sock);
	sock = 0;
    } else {
	/*
	 * To verify authenticity, we need to know the address of the
	 * client.
	 */
	if (getpeername(0, (struct sockaddr *)&peername, &namelen) < 0) {
	    syslog(LOG_ERR, "getpeername: %m");
	    exit(1);
	}
    }

    peeraddr.addrtype = peername.sin_family;
    peeraddr.length = sizeof(peername.sin_addr);
    peeraddr.contents = (krb5_octet *)&peername.sin_addr;

    if (retval = krb5_recvauth((krb5_pointer)&sock,
			       SAMPLE_VERSION, server, &peeraddr,
			       0, 0, 0,	/* no fetchfrom, keyproc or arg */
			       0,	/* default rc type */
			       0,	/* no flags */
			       0,	/* don't need seq number */
			       &client,
			       0, 0	/* don't care about ticket or
					   authenticator */
			       )) {
	syslog(LOG_ERR, "recvauth failed--%s", error_message(retval));
	exit(1);
    }

    if (retval = krb5_unparse_name(client, &cname)) {
	syslog(LOG_ERR, "unparse failed: %s", error_message(retval));
	cname = "<unparse error>";
    }

    sprintf(repbuf, "You are %s\n", cname);
    if (!retval)
	free(cname);
    xmitlen = htons(strlen(repbuf));
    recv_data.length = strlen(repbuf);
    recv_data.data = repbuf;
    if ((retval = krb5_net_write(0, (char *)&xmitlen,
				 sizeof(xmitlen))) < 0) {
	syslog(LOG_ERR, "%m: while writing len to client");
	exit(1);
    }
    if ((retval = krb5_net_write(0, (char *)recv_data.data,
				 recv_data.length)) < 0) {
	syslog(LOG_ERR, "%m: while writing data to client");
	exit(1);
    }
    exit(0);
}
