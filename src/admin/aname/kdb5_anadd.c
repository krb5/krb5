/*
 * admin/aname/kdb5_anadd.c
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
 * Program to add/delete entries to/from the aname translation database.
 */

#include "k5-int.h"
#include <sys/file.h>
#include "com_err.h"
#include <stdio.h>
#include <errno.h>

extern int errno;

void
usage(name, code)
char *name;
int code;
{
    fprintf(stderr, "usage: %s {-d|-a} [-n dbname] pname [ lname ]\n\
\t-d requires pname, -a requires pname and lname\n", name);
    exit(code);
}

void
main(argc, argv)
int argc;
char *argv[];
{
    DBM *db;
    datum key, contents;
    int optchar;
    extern char *optarg;
    extern int optind;
    int del = 0, add = 0;
    char *lname, *pname;
    extern char *krb5_lname_file;
    char *andbname = krb5_lname_file;

    while ((optchar = getopt(argc, argv, "dan:")) != EOF) {
	switch(optchar) {
	case 'd':			/* del */
	    del++;
	    if (add) {
		fprintf(stderr, "only one of -a, -d\n");
		usage(argv[0], 1);
	    }
	    break;
	case 'a':			/* add */
	    add++;
	    if (del) {
		fprintf(stderr, "only one of -a, -d\n");
		usage(argv[0], 1);
	    }
	    break;
	case 'n':
	    andbname = optarg;
	    break;
	case '?':
	default:
	    usage(argv[0], 1);
	    /*NOTREACHED*/
	}
    }
    if (!del && !add) {
	printf("assuming you want to add\n");
	add = 1;
    }
    if (argc - optind < 1) {
	fprintf(stderr, "must supply pname\n");
	usage(argv[0], 1);
    }
    if (add && (argc - optind < 2)) {
	    fprintf(stderr, "must supply pname and lname\n");
	    usage(argv[0], 1);
    }
    pname = argv[optind];
    lname = argv[optind+1];

    if (!(db = dbm_open(andbname, O_RDWR|O_CREAT, 0644))) {
	com_err(argv[0], errno, "while opening/creating %s",
		andbname);
	exit(1);
    }
    key.dptr = pname;
    key.dsize = strlen(pname)+1;	/* include the null */

    if (del) {
	if (dbm_delete(db, key)) {
	    com_err(argv[0], 0, "No such entry while deleting %s from %s",
		    pname, andbname);
	    dbm_close(db);
	    exit(1);
	}
    } else if (add) {
	contents.dptr = lname;
	contents.dsize = strlen(lname)+1;
	if (dbm_store(db, key, contents, DBM_REPLACE)) {
	    com_err(argv[0], errno, "while inserting/replacing %s in %s",
		    pname, andbname);
	    dbm_close(db);
	    exit(1);
	}
    }
    dbm_close(db);
    exit(0);
}
