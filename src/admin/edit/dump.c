/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Dump a KDC database
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_edit_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/libos-proto.h>
#include <krb5/asn1.h>
#include <krb5/config.h>
#include <krb5/sysincl.h>		/* for MAXPATHLEN */
#include <krb5/ext-proto.h>
#include <krb5/func-proto.h>

#include <com_err.h>
#include <ss/ss.h>
#include <stdio.h>


#define REALM_SEP	'@'
#define REALM_SEP_STR	"@"

struct mblock {
    krb5_deltat max_life;
    krb5_deltat max_rlife;
    krb5_timestamp expiration;
    krb5_flags flags;
    krb5_kvno mkvno;
};

struct dump_record {
	char	*comerr_name;
	FILE	*f;
};

krb5_error_code
dump_iterator(ptr, entry)
krb5_pointer ptr;
krb5_db_entry *entry;
{
    krb5_error_code retval;
    struct dump_record *arg = (struct dump_record *) entry;
    char *name;

    if (retval = krb5_unparse_name(entry->principal, &name)) {
	com_err(arg->comerr_name, retval, "while unparsing principal");
	return retval;
    }
    printf("entry: %s\n", name);
    free(name);
    return 0;
}
/*ARGSUSED*/

void dump_db(argc, argv)
	int	argc;
	char	**argv;
{
	FILE	*f;
	struct dump_record	arg;
	
	if (argc != 2) {
		com_err(argv[0], 0, "Usage: %s filename", argv[0]);
		return;
	}
	if (!(f = fopen(argv[1], "w"))) {
		com_err(argv[0], errno,
			"While opening file %s for writing", argv[1]);
		return;
	}
	arg.comerr_name = argv[0];
	arg.f = f;
	(void) krb5_db_iterate(dump_iterator, &arg);
}


void update_ok_file (file_name)
     char *file_name;
{
    /* handle slave locking/failure stuff */
    char *file_ok;
    int fd;
    static char ok[]=".dump_ok";

    if ((file_ok = (char *)malloc(strlen(file_name) + strlen(ok) + 1))
	== NULL) {
	fprintf(stderr, "kdb_util: out of memory.\n");
	(void) fflush (stderr);
	perror ("malloc");
	exit (1);
    }
    strcpy(file_ok, file_name);
    strcat(file_ok, ok);
    if ((fd = open(file_ok, O_WRONLY|O_CREAT|O_TRUNC, 0400)) < 0) {
	fprintf(stderr, "Error creating 'ok' file, '%s'", file_ok);
	perror("");
	(void) fflush (stderr);
	exit (1);
    }
    free(file_ok);
    close(fd);
    return;
}
