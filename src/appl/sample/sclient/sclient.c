/*
 * appl/sample/sclient/sclient.c
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
 * Sample Kerberos v5 client.
 *
 * Usage: sample_client hostname
 */

#include "krb5.h"
#include "com_err.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc();
#endif

#include "../sample.h"

void
main(argc, argv)
int argc;
char *argv[];
{
    struct servent *sp;
    struct hostent *hp;
    struct sockaddr_in sin, lsin;
    int sock, namelen;
    krb5_context context;
    krb5_data recv_data;
    krb5_data cksum_data;
    krb5_error_code retval;
    krb5_ccache ccdef;
    krb5_principal client, server;
    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;
    krb5_auth_context auth_context = 0;
    short xmitlen;
    char *service = 0;

    if (argc != 2 && argc != 3 && argc != 4) {
	fprintf(stderr, "usage: %s <hostname> [port] [service]\n",argv[0]);
	exit(1);
    }

    krb5_init_context(& context);
    krb5_init_ets(context);

    (void) signal(SIGPIPE, SIG_IGN);
    if (!valid_cksumtype(CKSUMTYPE_CRC32)) {
	com_err(argv[0], KRB5_PROG_SUMTYPE_NOSUPP, "while using CRC-32");
	exit(1);
    }

    /* clear out the structure first */
    (void) memset((char *)&sin, 0, sizeof(sin));

    if (argc > 2) {
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(argv[2]));
    } else {
	/* find the port number for knetd */
	sp = getservbyname(SAMPLE_PORT, "tcp");
	if (!sp) {
	    fprintf(stderr,
		    "unknown service %s/tcp; check /etc/services\n",
		    SAMPLE_PORT);
	    exit(1);
	}
	/* copy the port number */
	sin.sin_port = sp->s_port;
	sin.sin_family = AF_INET;
    }
    if (argc > 3) {
	service = argv[3];
    }

    /* look up the server host */
    hp = gethostbyname(argv[1]);
    if (!hp) {
	fprintf(stderr, "unknown host %s\n",argv[1]);
	exit(1);
    }

    if (retval = krb5_sname_to_principal(context, argv[1], service,
					 KRB5_NT_SRV_HST, &server)) {
	com_err(argv[0], retval, "while creating server name for %s/%s",
		argv[1], service);
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

    cksum_data.data = argv[1];
    cksum_data.length = strlen(argv[1]);

    if (retval = krb5_cc_default(context, &ccdef)) {
	com_err(argv[0], retval, "while getting default ccache");
	exit(1);
    }

    if (retval = krb5_cc_get_principal(context, ccdef, &client)) {
	com_err(argv[0], retval, "while getting client principal name");
	exit(1);
    }
    retval = krb5_sendauth(context, &auth_context, (krb5_pointer) &sock,
			   SAMPLE_VERSION, client, server,
			   AP_OPTS_MUTUAL_REQUIRED,
			   &cksum_data,
			   0,		/* no creds, use ccache instead */
			   ccdef, &err_ret, &rep_ret, NULL);

    krb5_free_principal(context, server);	/* finished using it */

    if (retval && retval != KRB5_SENDAUTH_REJECTED) {
	com_err(argv[0], retval, "while using sendauth");
	exit(1);
    }
    if (retval == KRB5_SENDAUTH_REJECTED) {
	/* got an error */
	printf("sendauth rejected, error reply is:\n\t\"%*s\"\n",
	       err_ret->text.length, err_ret->text.data);
    } else if (rep_ret) {
	/* got a reply */
	printf("sendauth succeeded, reply is:\n");
	if ((retval = krb5_net_read(context, sock, (char *)&xmitlen,
				    sizeof(xmitlen))) <= 0) {
	    if (retval == 0)
		errno = ECONNABORTED;
	    com_err(argv[0], errno, "while reading data from server");
	    exit(1);
	}
	recv_data.length = ntohs(xmitlen);
	if (!(recv_data.data = (char *)malloc(recv_data.length + 1))) {
	    com_err(argv[0], ENOMEM,
		    "while allocating buffer to read from server");
	    exit(1);
	}
	if ((retval = krb5_net_read(context, sock, (char *)recv_data.data,
				    recv_data.length)) <= 0) {
	    if (retval == 0)
		errno = ECONNABORTED;
	    com_err(argv[0], errno, "while reading data from server");
	    exit(1);
	}
	recv_data.data[recv_data.length] = '\0';
	printf("reply len %d, contents:\n%s\n",
	       recv_data.length,recv_data.data);
    } else {
	com_err(argv[0], 0, "no error or reply from sendauth!");
	exit(1);
    }
    exit(0);
}
