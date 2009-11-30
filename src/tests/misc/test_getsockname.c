/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * test_getsockname.c
 *
 * This routine demonstrates a bug in the socket emulation library of
 * Solaris and other monstrosities that uses STREAMS.  On other
 * machines with a real networking layer, it prints the local
 * interface address that is used to send a message to a specific
 * host.  On Solaris, it prints out 0.0.0.0.
 */

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include "autoconf.h"

int
main(argc, argv)
    int argc;
    char *argv[];
{
    int sock;
    GETSOCKNAME_ARG3_TYPE i;
    struct hostent *host;
    struct sockaddr_in s_sock;          /* server address */
    struct sockaddr_in c_sock;          /* client address */

    char *hostname;

    if (argc == 2) {
        hostname = argv[1];
    } else {
        fprintf(stderr, "Usage: %s hostname\n", argv[0]);
        exit(1);
    }

    /* Look up server host */
    if ((host = gethostbyname(hostname)) == (struct hostent *) 0) {
        fprintf(stderr, "%s: unknown host\n", hostname);
        exit(1);
    }

    /* Set server's address */
    (void) memset(&s_sock, 0, sizeof(s_sock));

    memcpy(&s_sock.sin_addr, host->h_addr, sizeof(s_sock.sin_addr));
#ifdef DEBUG
    printf("s_sock.sin_addr is %s\n", inet_ntoa(s_sock.sin_addr));
#endif
    s_sock.sin_family = AF_INET;
    s_sock.sin_port = htons(5555);

    /* Open a socket */
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset(&c_sock, 0, sizeof(c_sock));
    c_sock.sin_family = AF_INET;

    /* Bind it to set the address; kernel will fill in port # */
    if (bind(sock, (struct sockaddr *)&c_sock, sizeof(c_sock)) < 0) {
        perror("bind");
        exit(1);
    }

    /* "connect" the datagram socket; this is necessary to get a local address
       properly bound for getsockname() below. */
    if (connect(sock, (struct sockaddr *)&s_sock, sizeof(s_sock)) == -1) {
        perror("connect");
        exit(1);
    }

    /* Get my address */
    memset(&c_sock, 0, sizeof(c_sock));
    i = sizeof(c_sock);
    if (getsockname(sock, (struct sockaddr *)&c_sock, &i) < 0) {
        perror("getsockname");
        exit(1);
    }

    printf("My interface address is: %s\n", inet_ntoa(c_sock.sin_addr));

    exit(0);
}
