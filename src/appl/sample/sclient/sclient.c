/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Sample Kerberos v5 client.
 *
 * Usage: sample_client hostname
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_sclient_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>

#include <stdio.h>
#include <ctype.h>
#include <com_err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>

#include "sample.h"

void
main(argc, argv)
int argc;
char *argv[];
{
    struct servent *sp;
    struct hostent *hp;
    struct sockaddr_in sin, lsin;
    char *remote_host;
    register char *cp;
    int sock, namelen;
    krb5_data send_data;
    krb5_checksum send_cksum;
    krb5_error_code retval;
    krb5_ccache ccdef;
    krb5_principal server;
    char **hrealms;
    short xmitlen;
    char sbuf[512];

    if (argc != 2) {
	fprintf(stderr, "usage: %s <hostname>\n",argv[0]);
	exit(1);
    }
    
    krb5_init_ets();

    (void) signal(SIGPIPE, SIG_IGN);
    if (!valid_cksumtype(CKSUMTYPE_CRC32)) {
	com_err(argv[0], KRB5_PROG_SUMTYPE_NOSUPP, "while using CRC-32");
	exit(1);
    }

    /* clear out the structure first */
    (void) memset((char *)&sin, 0, sizeof(sin));

    /* find the port number for knetd */
    sp = getservbyname(SAMPLE_SERVICE, "tcp");
    if (!sp) {
	fprintf(stderr,
		"unknown service %s/tcp; check /etc/services\n",
		SAMPLE_SERVICE);
	exit(1);
    }
    /* copy the port number */
    sin.sin_port = sp->s_port;
    sin.sin_family = AF_INET;

    /* look up the server host */
    hp = gethostbyname(argv[1]);
    if (!hp) {
	fprintf(stderr, "unknown host %s\n",argv[1]);
	exit(1);
    }

    if (retval = krb5_get_host_realm(hp->h_name, &hrealms)) {
	com_err(argv[0], retval, "while determining realm(s) of %s",
		hp->h_name);
	exit(1);
    }
    if (strlen(hp->h_name)+strlen(SAMPLE_SERVICE)+strlen(hrealms[0])+3 >
	sizeof(sbuf)) {
	fprintf(stderr, "hostname too long!\n");
	exit(1);
    }

    /* copy the hostname into non-volatile storage */
    remote_host = malloc(strlen(hp->h_name) + 1);
    (void) strcpy(remote_host, hp->h_name);

    /* lower-case to get name for "instance" part of service name */
    for (cp = remote_host; *cp; cp++)
	if (isupper(*cp))
	    *cp = tolower(*cp);

    memset(sbuf, 0, sizeof(sbuf));
    strcpy(sbuf, SAMPLE_SERVICE);
    strcat(sbuf, "/");
    strcat(sbuf, remote_host);
    strcat(sbuf, "@");
    strcat(sbuf, hrealms[0]);
    (void) krb5_free_host_realm(hrealms);
    if (retval = krb5_parse_name(sbuf, &server)) {
	com_err(argv[0], retval, "while parsing service name %s", sbuf);
	exit(1);
    }

    /* set up the address of the foreign socket for connect() */
    sin.sin_family = hp->h_addrtype;
    (void) memcpy((char *)&sin.sin_addr,
		  (char *)hp->h_addr,
		  sizeof(hp->h_addr));

    /* open a TCP socket */
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
	perror("socket");
	exit(1);
    }

    /* connect to the server */
    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
	perror("connect");
	close(sock);
	exit(1);
    }

    /* find out who I am, now that we are connected and therefore bound */
    namelen = sizeof(lsin);
    if (getsockname(sock, (struct sockaddr *) &lsin, &namelen) < 0) {
	perror("getsockname");
	close(sock);
	exit(1);
    }

    /* compute checksum, using CRC-32 */
    if (!(send_cksum.contents = (krb5_octet *)
	  malloc(krb5_cksumarray[CKSUMTYPE_CRC32]->checksum_length))) {
	com_err(argv[0], ENOMEM, "while allocating checksum");
	exit(1);
    }
    /* choose some random stuff to compute checksum from */
    if (retval = (*krb5_cksumarray[CKSUMTYPE_CRC32]->
		  sum_func)(remote_host,
			    strlen(remote_host),
			    0,
			    0,		/* if length is 0, crc-32 doesn't
					   use the seed */
			    &send_cksum)) {
	com_err(argv[0], retval, "while computing checksum");
	exit(1);
    }

    if (retval = krb5_cc_default(&ccdef)) {
	com_err(argv[0], retval, "while getting default ccache");
	exit(1);
    }

    if (retval = krb5_mk_req(server, 0, &send_cksum, ccdef, &send_data)) {
	com_err(argv[0], retval, "while preparing AP_REQ");
	exit(1);
    }
    xmitlen = htons(send_data.length);

    if ((retval = krb5_net_write(sock, (char *)&xmitlen,
				 sizeof(xmitlen))) < 0) {
	com_err(argv[0], errno, "while writing len to server");
	exit(1);
    }
    if ((retval = krb5_net_write(sock, (char *)send_data.data,
				 send_data.length)) < 0) {
	com_err(argv[0], errno, "while writing data to server");
	exit(1);
    }
    xfree(send_data.data);
    if ((retval = krb5_net_read(sock, (char *)&xmitlen,
				sizeof(xmitlen))) <= 0) {
	if (retval == 0)
	    errno = ECONNRESET;		/* XXX */
	com_err(argv[0], errno, "while reading data from server");
	exit(1);
    }
    send_data.length = ntohs(xmitlen);
    if (!(send_data.data = (char *)malloc(send_data.length + 1))) {
	com_err(argv[0], ENOMEM, "while allocating buffer to read from server");
	exit(1);
    }
    if ((retval = krb5_net_read(sock, (char *)send_data.data,
				send_data.length)) <= 0) {
	if (retval == 0)
	    errno = ECONNRESET;		/* XXX */
	com_err(argv[0], errno, "while reading data from server");
	exit(1);
    }
    send_data.data[send_data.length] = '\0';
    printf("reply len %d, contents:\n%s\n",send_data.length,send_data.data);
    exit(0);
}
