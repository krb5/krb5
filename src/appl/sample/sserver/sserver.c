/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
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

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>

#include <ctype.h>
#include <com_err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>

#include "sample.h"

extern krb5_deltat krb5_clockskew;

void
main(argc, argv)
int argc;
char *argv[];
{
    struct sockaddr_in peername;
    krb5_address peeraddr;
    int namelen = sizeof(peername);
    krb5_data recv_data;
    short xmitlen;
    krb5_error_code retval;
    krb5_tkt_authent authd;
    krb5_principal server;
    char repbuf[BUFSIZ];
    char *cname;

    krb5_init_ets();
    /* open a log connection */

    openlog("sserver", 0, LOG_DAEMON);

    if (argc < 2) {
	syslog(LOG_ERR, "needs server argument");
	exit(1);
    }
    if (retval = krb5_parse_name(argv[1], &server)) {
	syslog(LOG_ERR, "parse server name %s: %s", argv[1],
	       error_message(retval));
	exit(1);
    }

#ifdef DEBUG
{
    int sock, acc;
    struct sockaddr_in sin;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	syslog(LOG_ERR, "socket: %m");
	exit(3);
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(5555);
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
}
#else
    /*
     * To verify authenticity, we need to know the address of the
     * client.
     */
    if (getpeername(0, (struct sockaddr *)&peername, &namelen) < 0) {
	syslog(LOG_ERR, "getpeername: %m");
	exit(1);
    }
#endif
    peeraddr.addrtype = peername.sin_family;
    peeraddr.length = sizeof(peername.sin_addr);
    if (!(peeraddr.contents = (krb5_octet *)malloc(peeraddr.length))) {
	syslog(LOG_ERR, "no memory allocating addr");
	exit(1);
    }
    memcpy((char *)peeraddr.contents, (char *)&peername.sin_addr,
	  peeraddr.length);

    if ((retval = krb5_net_read(0, (char *)&xmitlen, sizeof(xmitlen))) <= 0) {
	if (retval == 0)
	    errno = ECONNRESET;		/* XXX */
	syslog(LOG_ERR, "read size: %m");
	exit(1);
    }
    recv_data.length = ntohs(xmitlen);
    if (!(recv_data.data = (char *) malloc(recv_data.length))) {
	syslog(LOG_ERR, "no memory allocating packet");
	exit(1);
    }
    if ((retval = krb5_net_read(0, (char *)recv_data.data,
				recv_data.length)) <= 0) {
	if (retval == 0)
	    errno = ECONNRESET;		/* XXX */
	syslog(LOG_ERR, "read contents: %m");
	exit(1);
    }
    if (retval = krb5_rd_req_simple(&recv_data, server, &peeraddr, &authd)) {
	syslog(LOG_ERR, "rd_req failed: %s", error_message(retval));
	sprintf(repbuf, "RD_REQ failed: %s\n", error_message(retval));
	goto sendreply;
    }
    xfree(recv_data.data);

    if (retval = krb5_unparse_name(authd.ticket->enc_part2->client, &cname)) {
	syslog(LOG_ERR, "unparse failed: %s", error_message(retval));
	cname = "<unparse error>";
    }
    sprintf(repbuf, "You are %s\n", cname);
    if (!retval)
	free(cname);
 sendreply:
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
