/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Program to add/delete entries to/from the aname translation database.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_anadd_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/dbm.h>
#include <sys/file.h>
#include <com_err.h>
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
    int delete = 0, add = 0;
    char *lname, *pname;
    extern char *krb5_lname_file;
    char *andbname = krb5_lname_file;

    while ((optchar = getopt(argc, argv, "dan:")) != EOF) {
	switch(optchar) {
	case 'd':			/* delete */
	    delete++;
	    if (add) {
		fprintf(stderr, "only one of -a, -d\n");
		usage(argv[0], 1);
	    }
	    break;
	case 'a':			/* add */
	    add++;
	    if (delete) {
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
    if (!delete && !add) {
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

    if (delete) {
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
