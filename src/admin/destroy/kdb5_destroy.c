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
 * permission.  M.I.T. makes no representations about the suitability of
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

extern int errno;

char *yes = "yes\n";			/* \n to compare against result of
					   fgets */

static void
usage(who, status)
    char *who;
    int status;
{
    fprintf(stderr, "usage: %s [-d dbpathname]\n", who);
    exit(status);
}

void
main(argc, argv)
    int argc;
    char *argv[];
{
    extern char *optarg;	
    int optchar;
    char *dbname = DEFAULT_KDB_FILE;
    char buf[5];
    char dbfilename[MAXPATHLEN];
    krb5_error_code retval;
    krb5_context context;
    int force = 0;

    krb5_init_context(&context);
    krb5_init_ets(context);

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    while ((optchar = getopt(argc, argv, "d:f")) != EOF) {
	switch(optchar) {
	case 'd':			/* set db name */
	    dbname = optarg;
	    break;
	case 'f':
	    force++;
	    break;
	case '?':
	default:
	    usage(argv[0], 1);
	    /*NOTREACHED*/
	}
    }
    if (!force) {
	printf("Deleting KDC database stored in '%s', are you sure?\n", dbname);
	printf("(type 'yes' to confirm)? ");
	if (fgets(buf, sizeof(buf), stdin) == NULL)
	    exit(1);
	if (strcmp(buf, yes))
	    exit(1);
	printf("OK, deleting database '%s'...\n", dbname);
    }

    if (retval = krb5_db_set_name(context, dbname)) {
	com_err(argv[0], retval, "'%s'",dbname);
	exit(1);
    }
    if (retval = kdb5_db_destroy(context, dbname)) {
	com_err(argv[0], retval, "deleting database '%s'",dbname);
	exit(1);
    }

    printf("** Database '%s' destroyed.\n", dbname);
    exit(0);
}
