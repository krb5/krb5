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

krb5_encrypt_block master_encblock;
extern char *current_dbname;
extern krb5_boolean dbactive;

void update_ok_file();

krb5_error_code
dump_iterator(ptr, entry)
krb5_pointer ptr;
krb5_db_entry *entry;
{
    krb5_error_code retval;
    struct dump_record *arg = (struct dump_record *) ptr;
    char *name=NULL, *mod_name=NULL;
    int	i;

    if (retval = krb5_unparse_name(entry->principal, &name)) {
	com_err(arg->comerr_name, retval, "while unparsing principal");
	return retval;
    }
    if (retval = krb5_unparse_name(entry->mod_name, &mod_name)) {
	free(name);
	com_err(arg->comerr_name, retval, "while unparsing principal");
	return retval;
    }
    fprintf(arg->f, "%d\t%d\t%s\t%d\t%d\t", strlen(name), strlen(mod_name),
	    name, entry->key.keytype, entry->key.length);
    for (i=0; i<entry->key.length; i++) {
	    fprintf(arg->f, "%02x", *(entry->key.contents+i));
    }
    fprintf(arg->f, "\t%u\t%u\t%u\t%u\t%u\t%s\t%u\t%u\n", entry->kvno,
	   entry->max_life, entry->max_renewable_life, entry->mkvno,
	   entry->expiration, mod_name, entry->mod_date, entry->attributes);
    free(name);
    free(mod_name);
    return 0;
}
/*ARGSUSED*/

void dump_db(argc, argv)
	int	argc;
	char	**argv;
{
	FILE	*f;
	struct dump_record	arg;
	
	if (argc > 2) {
		com_err(argv[0], 0, "Usage: %s filename", argv[0]);
		return;
	}
	if (argc == 2) {
		if (!(f = fopen(argv[1], "w"))) {
			com_err(argv[0], errno,
				"While opening file %s for writing", argv[1]);
			return;
		}
	} else {
		f = stdout;
	}
	arg.comerr_name = argv[0];
	arg.f = f;
	(void) krb5_db_iterate(dump_iterator, (krb5_pointer) &arg);
	if (argc == 2)
		fclose(f);
	if (argv[1])
		update_ok_file(argv[1]);
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
	fprintf(stderr, "%s: out of memory.\n", progname);
	(void) fflush (stderr);
	perror ("malloc");
	exit (1);
    }
    strcpy(file_ok, file_name);
    strcat(file_ok, ok);
    if ((fd = open(file_ok, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
	fprintf(stderr, "Error creating 'ok' file, '%s'", file_ok);
	perror("");
	(void) fflush (stderr);
	exit (1);
    }
    free(file_ok);
    close(fd);
    return;
}

void load_db(argc, argv)
	int	argc;
	char	**argv;
{
	FILE	*f;
	krb5_db_entry entry;
	krb5_error_code retval;
	int	name_len, mod_name_len,i,one;
	char	*name, *mod_name;
	char	*new_dbname;
	
	if (argc != 3) {
		com_err(argv[0], 0, "Usage: %s filename dbname", argv[0]);
		return;
	}
	if (!(new_dbname = malloc(strlen(argv[2])+2))) {
		com_err(argv[0], 0, "No room to allocate new database name!");
		return;
	}
	strcpy(new_dbname, argv[2]);
	strcat(new_dbname, "~");
	if (retval = krb5_db_create(new_dbname)) {
		com_err(argv[0], retval, "while creating database '%s'",
			new_dbname);
		return;
	}
	if (dbactive) {
		if ((retval = krb5_db_fini()) &&
		    retval != KRB5_KDB_DBNOTINITED) {
			com_err(argv[0], retval,
				"while closing previous database");
			return;
		}
	}
	if (retval = krb5_db_set_name(new_dbname)) {
		com_err(argv[0], retval,
			"while setting active database to '%s'", new_dbname
			);
		exit(1);
	}
	if (retval = krb5_db_init()) {
		com_err(argv[0], retval,
			"while initializing database %s",
			new_dbname
			);
		exit(1);
		}
	if (!(f = fopen(argv[1], "r"))) {
		com_err(argv[0], errno,
			"While opening file %s for writing", argv[1]);
		return;
	}
	for (;;) {
		memset((char *)&entry, 0, sizeof(entry));
		if (fscanf(f,"%d\t%d\t", &name_len, &mod_name_len) == EOF)
			break;
		if (!(name = malloc(name_len+1))) {
			com_err(argv[0], errno,
				"While allocating speace for name");
			break;
		}
		if (!(mod_name = malloc(mod_name_len+1))) {
			free(name);
			com_err(argv[0], errno,
				"While allocating speace for name");
			break;
		}
		fscanf(f, "%s\t%d\t%d\t", name, &entry.key.keytype,
		       &entry.key.length);
		if (!(entry.key.contents = (krb5_octet *) malloc(entry.key.length+1))) {
			free(name);
			free(mod_name);
			com_err(argv[0], errno,
				"While allocating speace for name");
			break;
		}
		for (i=0; i<entry.key.length; i++) {
			fscanf(f,"%02x", entry.key.contents+i);
		}
		fscanf(f, "\t%u\t%u\t%u\t%u\t%u\t%s\t%u\t%u\n",
			&entry.kvno, &entry.max_life,
			&entry.max_renewable_life, &entry.mkvno,
			&entry.expiration, mod_name, &entry.mod_date,
			&entry.attributes);
		if (retval=krb5_parse_name(name, &entry.principal)) {
			com_err(argv[0], retval, "while trying to parse %s",
				name);
			goto cleanup;
		}
		if (retval=krb5_parse_name(mod_name, &entry.mod_name)) {
			com_err(argv[0], retval,
				"while trying to parse %s for %s",
				mod_name, name);
			goto cleanup;
		}
		one=1;
		if (retval = krb5_db_put_principal(&entry, &one)) {
			com_err(argv[0], retval,
				"while trying to store principal %s",
				name);
			goto cleanup;
		}
	cleanup:
		free(name);
		free(mod_name);
		free((char *)entry.key.contents);
	}
	if (retval = krb5_db_fini()) {
		com_err(argv[0], retval,
			"while closing database '%s'", new_dbname);
		exit(1);
	}
	if (retval = krb5_db_rename(new_dbname, argv[2])) {
		com_err(argv[0], retval,
			"while renaming database from %s to %s",
			new_dbname, argv[2]);
		exit(1);
	}
	if (dbactive) {
		if (retval = krb5_db_set_name(current_dbname)) {
			com_err(argv[0], retval,
				"while resetting active database to '%s'",
				current_dbname);
			exit(1);
		}
		if (retval = krb5_db_init()) {
			com_err(argv[0], retval,
				"while initializing active database %s",
				current_dbname);
			exit(1);
		}
	}
}
