/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * clients/kdestroy/kdestroy.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 *
 *
 * Destroy the contents of your credential cache.
 */

#include "autoconf.h"
#include <krb5.h>
#include <com_err.h>
#include <string.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef __STDC__
#define BELL_CHAR '\a'
#else
#define BELL_CHAR '\007'
#endif

extern int optind;
extern char *optarg;

#ifndef _WIN32
#define GET_PROGNAME(x) (strrchr((x), '/') ? strrchr((x), '/')+1 : (x))
#else
#define GET_PROGNAME(x) max(max(strrchr((x), '/'), strrchr((x), '\\')) + 1,(x))
#endif

char *progname;


static void usage()
{
#define KRB_AVAIL_STRING(x) ((x)?"available":"not available")

    fprintf(stderr, "Usage: %s [-q] [-c cache_name]\n", progname);
    fprintf(stderr, "\t-q quiet mode\n");
    fprintf(stderr, "\t-c specify name of credentials cache\n");
    exit(2);
}

int
main(argc, argv)
    int argc;
    char **argv;
{
    krb5_context kcontext;
    krb5_error_code retval;
    int c;
    krb5_ccache cache = NULL;
    char *cache_name = NULL;
    int code = 0;
    int errflg = 0;
    int quiet = 0;

    progname = GET_PROGNAME(argv[0]);

    while ((c = getopt(argc, argv, "54qc:")) != -1) {
        switch (c) {
        case 'q':
            quiet = 1;
            break;
        case 'c':
            if (cache_name) {
                fprintf(stderr, "Only one -c option allowed\n");
                errflg++;
            } else {
                cache_name = optarg;
            }
            break;
        case '4':
            fprintf(stderr, "Kerberos 4 is no longer supported\n");
            exit(3);
            break;
        case '5':
            break;
        case '?':
        default:
            errflg++;
            break;
        }
    }

    if (optind != argc)
        errflg++;

    if (errflg) {
        usage();
    }

    retval = krb5_init_context(&kcontext);
    if (retval) {
        com_err(progname, retval, "while initializing krb5");
        exit(1);
    }

    if (cache_name) {
        code = krb5_cc_resolve (kcontext, cache_name, &cache);
        if (code != 0) {
            com_err (progname, code, "while resolving %s", cache_name);
            exit(1);
        }
    } else {
        code = krb5_cc_default(kcontext, &cache);
        if (code) {
            com_err(progname, code, "while getting default ccache");
            exit(1);
        }
    }

    code = krb5_cc_destroy (kcontext, cache);
    if (code != 0) {
        com_err (progname, code, "while destroying cache");
        if (code != KRB5_FCC_NOFILE) {
            if (quiet)
                fprintf(stderr, "Ticket cache NOT destroyed!\n");
            else {
                fprintf(stderr, "Ticket cache %cNOT%c destroyed!\n",
                        BELL_CHAR, BELL_CHAR);
            }
            errflg = 1;
        }
    }
    return errflg;
}
