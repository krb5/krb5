/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/resolve/resolve.c */
/*
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * A simple program to test the functionality of the resolver library.
 * It simply will try to get the IP address of the host, and then look
 * up the name from the address. If the resulting name does not contain the
 * domain name, then the resolve library is broken.
 *
 * Warning: It is possible to fool this program into thinking everything is
 * alright by a clever use of /etc/hosts - but this is better than nothing.
 *
 * Usage:
 *   resolve [hostname]
 *
 *   When invoked with no arguments, gethostname is used for the local host.
 *
 */

/* This program tests the resolve library and sees if it is broken... */

#include "k5-platform.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

int
main(int argc, char **argv)
{
    struct addrinfo *ai = NULL, hint;
    char myname[MAXHOSTNAMELEN + 1], namebuf[NI_MAXHOST], abuf[256];
    const char *addrstr;
    int err, quiet = 0;

    argc--; argv++;
    while (argc) {
        if ((strcmp(*argv, "--quiet") == 0) ||
            (strcmp(*argv, "-q") == 0)) {
            quiet++;
        } else
            break;
        argc--; argv++;
    }

    if (argc >= 1) {
        strlcpy(myname, *argv, sizeof(myname));
    } else {
        if(gethostname(myname, MAXHOSTNAMELEN)) {
            perror("gethostname failure");
            exit(1);
        }
    }

    myname[MAXHOSTNAMELEN] = '\0';  /* for safety */

    /* Look up the address... */
    if (!quiet)
        printf("Hostname:  %s\n", myname);

    memset(&hint, 0, sizeof(hint));
    hint.ai_flags = AI_CANONNAME;
    err = getaddrinfo(myname, 0, &hint, &ai);
    if (err) {
        fprintf(stderr,
                "Could not look up address for hostname '%s' - fatal\n",
                myname);
        exit(2);
    }

    if (!quiet) {
        addrstr = inet_ntop(ai->ai_family, ai->ai_addr, abuf, sizeof(abuf));
        if (addrstr != NULL)
            printf("Host address: %s\n", addrstr);
    }

    err = getnameinfo(ai->ai_addr, ai->ai_addrlen, namebuf, sizeof(namebuf),
                      NULL, 0, NI_NAMEREQD);
    if (err && !quiet)
        fprintf(stderr, "Error looking up IP address\n");

    printf("%s%s\n", quiet ? "" : "FQDN: ", err ? ai->ai_canonname : namebuf);

    if (!quiet)
        printf("Resolve library appears to have passed the test\n");

    freeaddrinfo(ai);
    return 0;
}
