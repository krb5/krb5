/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * admin/destroy/kdb5_destroy.c
 *
 * Copyright 1990, 2008 by the Massachusetts Institute of Technology.
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
 * kdb_dest(roy): destroy the named database.
 *
 * This version knows about DBM format databases.
 */

#include "k5-int.h"
#include <stdio.h>
#include "com_err.h"
#include <kadm5/admin.h>
#include <kdb.h>
#include "kdb5_util.h"

extern int exit_status;
extern krb5_boolean dbactive;
extern kadm5_config_params global_params;

char *yes = "yes\n";                    /* \n to compare against result of
                                           fgets */

void
kdb5_destroy(argc, argv)
    int argc;
    char *argv[];
{
    extern char *optarg;
    extern int optind;
    int optchar;
    char *dbname;
    char buf[5];
    krb5_error_code retval1;
    krb5_context context;
    int force = 0;

    retval1 = kadm5_init_krb5_context(&context);
    if( retval1 )
    {
        com_err(progname, retval1, "while initializing krb5_context");
        exit(1);
    }

    if ((retval1 = krb5_set_default_realm(context,
                                          util_context->default_realm))) {
        com_err(progname, retval1, "while setting default realm name");
        exit(1);
    }

    dbname = global_params.dbname;

    optind = 1;
    while ((optchar = getopt(argc, argv, "f")) != -1) {
        switch(optchar) {
        case 'f':
            force++;
            break;
        case '?':
        default:
            usage();
            return;
            /*NOTREACHED*/
        }
    }
    if (!force) {
        printf("Deleting KDC database stored in '%s', are you sure?\n", dbname);
        printf("(type 'yes' to confirm)? ");
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            exit_status++; return;
        }
        if (strcmp(buf, yes)) {
            exit_status++; return;
        }
        printf("OK, deleting database '%s'...\n", dbname);
    }

    retval1 = krb5_db_destroy(context, db5util_db_args);
    if (retval1) {
        com_err(progname, retval1, "deleting database '%s'",dbname);
        exit_status++; return;
    }

    if (global_params.iprop_enabled) {
        (void) unlink(global_params.iprop_logfile);
    }

    dbactive = FALSE;
    printf("** Database '%s' destroyed.\n", dbname);
    return;
}
