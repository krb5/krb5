/*
 * admin/destroy/kdb5_destroy.c
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
 * kdb_dest(roy): destroy the named database.
 *
 * This version knows about DBM format databases.
 */

#include "k5-int.h"
#include <stdio.h>
#include "com_err.h"
#include <kadm5/admin.h>
#include <kadm5/adb.h>
#include "kdb5_util.h"

extern int exit_status;
extern krb5_boolean dbactive;
extern kadm5_config_params global_params;

char *yes = "yes\n";			/* \n to compare against result of
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
    krb5_error_code retval, retval1, retval2;
    krb5_context context;
    int force = 0;

    krb5_init_context(&context);

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

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

    retval = krb5_db_set_name(context, dbname);
    if (retval) {
	com_err(argv[0], retval, "'%s'",dbname);
	exit_status++; return;
    }
    retval1 = krb5_db_destroy(context, dbname);
    retval2 = osa_adb_destroy_policy_db(&global_params);
    if (retval1) {
	com_err(argv[0], retval1, "deleting database '%s'",dbname);
	exit_status++; return;
    }
    if (retval2) {
	 com_err(argv[0], retval2, "destroying policy database");
	 exit_status++; return;
    }

    dbactive = FALSE;
    printf("** Database '%s' destroyed.\n", dbname);
    return;
}
