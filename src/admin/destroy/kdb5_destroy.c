/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_dest_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <stdio.h>

#include <com_err.h>
#include <krb5/ext-proto.h>
#include <krb5/sysincl.h>		/* for MAXPATHLEN */

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
    char *dbname = 0;
    char buf[5];
    char dbfilename[MAXPATHLEN];
    krb5_error_code retval;

    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    while ((optchar = getopt(argc, argv, "d:")) != EOF) {
	switch(optchar) {
	case 'd':			/* set db name */
	    dbname = optarg;
	    break;
	case '?':
	default:
	    usage(argv[0], 1);
	    /*NOTREACHED*/
	}
    }
    if (!dbname)
	dbname = DEFAULT_DBM_FILE;	/* XXX? */

    printf("Deleting KDC database stored in '%s', are you sure?\n", dbname);
    printf("(type 'yes' to confirm)? ");
    if ((fgets(buf, sizeof(buf), stdin) != NULL) && /* typed something */
	!strcmp(buf,yes)) {		/* it matches yes */
	printf("OK, deleting database '%s'...\n", dbname);
	(void) strcpy(dbfilename, dbname);
	(void) strcat(dbfilename, ".dir");
	if (unlink(dbfilename) == -1) {
	    retval = errno;
	    com_err(argv[0], retval, "deleting database file '%s'",dbfilename);
	    if (retval == ENOENT)
		    fprintf(stderr,
			    "Database appears to not exist--inspect files manually!\n");
		else
		    fprintf(stderr,
			    "Database may be partially deleted--inspect files manually!\n");

	    exit(1);
	}
	(void) strcpy(dbfilename, dbname);
	(void) strcat(dbfilename, ".pag");
	if (unlink(dbfilename) == -1) {
	    retval = errno;
	    com_err(argv[0], retval, "deleting database file '%s'",dbfilename);
	    fprintf(stderr,
		    "Database may be partially deleted--inspect files manually!\n");
	    exit(1);
	}
	(void) strcpy(dbfilename, dbname);
	(void) strcat(dbfilename, ".ok");
	if (unlink(dbfilename) == -1) {
	    retval = errno;
	    com_err(argv[0], retval, "deleting database file '%s'",dbfilename);
	    fprintf(stderr,
		    "Database partially deleted--inspect files manually!\n");
	    exit(1);
	}
	printf("** Database '%s' destroyed.\n", dbname);
	exit(0);
    }
    exit(1);
}
