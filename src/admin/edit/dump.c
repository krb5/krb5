/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Dump a KDC database
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_edit_c[] =
"$Id$";
#endif	/* !lint & !saber */

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/los-proto.h>
#include <krb5/asn1.h>
#include <krb5/config.h>
#include <krb5/sysincl.h>		/* for MAXPATHLEN */
#include <krb5/ext-proto.h>
#include <krb5/func-proto.h>

#include <com_err.h>
#include <ss/ss.h>
#include <stdio.h>

extern char *progname;
extern char *Err_no_database;

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

static char ld_vers[] = "kdb5_edit load_dump version 1.0\n";

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
    fprintf(arg->f, "\t%u\t%u\t%u\t%u\t%u\t%s\t%u\t%u\t%u\t%u\t", entry->kvno,
	    entry->max_life, entry->max_renewable_life, entry->mkvno,
	    entry->expiration, mod_name, entry->mod_date, entry->attributes,
	    entry->salt_type, entry->salt_length);
    for (i=0; i<entry->salt_length; i++) {
	    fprintf(arg->f, "%02x", *(entry->salt+i));
    }
    fprintf(arg->f, ";\n");
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
	if (!dbactive) {
		com_err(argv[0], 0, Err_no_database);
		return;
	}
	if (argc == 2) {
		/*
		 * Make sure that we don't open and truncate on the fopen,
		 * since that may hose an on-going kprop process.
		 * 
		 * We could also control this by opening for read and
		 * write, doing an flock with LOCK_EX, and then
		 * truncating the file once we have gotten the lock,
		 * but that would involve more OS dependancies than I
		 * want to get into.
		 */
		unlink(argv[1]);
		if (!(f = fopen(argv[1], "w"))) {
			com_err(argv[0], errno,
				"While opening file %s for writing", argv[1]);
			return;
		}
	} else {
		f = stdout;
	}
	fputs(ld_vers, f);
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
		com_err(progname, ENOMEM,
			"while allocating filename for update_ok_file");
		return;
	}
	strcpy(file_ok, file_name);
	strcat(file_ok, ok);
	if ((fd = open(file_ok, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
		com_err(progname, errno, "while creating 'ok' file, '%s'",
			file_ok);
		free(file_ok);
		return;
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
	int	ch;
	int	load_error = 0;
	int	lineno = 0;
	int	stype, slength;
	int	align;
	char	buf[64];	/* Must be longer than ld_vers */
	
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
	fgets(buf, sizeof(buf), f);
	if (strcmp(buf, ld_vers)) {
		com_err(argv[0], 0, "Bad dump file version");
		load_error++;
		goto error_out;
	}
	for (;;) {
		int nitems;

		lineno++;
		memset((char *)&entry, 0, sizeof(entry));
		nitems = fscanf(f,"%d\t%d\t", &name_len, &mod_name_len);
		if (nitems == EOF)
			break;
		if (nitems != 2) {
			fprintf(stderr, "Couldn't parse line #%d\n", lineno);
			load_error++;
			break;
		}
		if (!(name = malloc(name_len+1))) {
			com_err(argv[0], errno,
				"While allocating space for name");
			load_error++;
			break;
		}
		if (!(mod_name = malloc(mod_name_len+1))) {
			free(name);
			com_err(argv[0], errno,
				"While allocating space for name");
			load_error++;
			break;
		}
		if (fscanf(f, "%s\t%d\t%d\t", name, &entry.key.keytype,
			   &entry.key.length) != 3) {
			fprintf(stderr, "Couldn't parse line #%d\n", lineno);
			load_error++;
			break;
		}
		if (!(entry.key.contents = (krb5_octet *) malloc(entry.key.length+1))) {
			free(name);
			free(mod_name);
			com_err(argv[0], errno,
				"While allocating space for name");
			load_error++;
			break;
		}
		for (i=0; i<entry.key.length; i++) {
			if (fscanf(f,"%02x", &align) != 1) {
				fprintf(stderr, "Couldn't parse line #%d\n",
					lineno);
				load_error++;
				break;
			}
			entry.key.contents[i] = align;
		}
		if (fscanf(f, "\t%u\t%u\t%u\t%u\t%u\t%s\t%u\t%u\t%u\t%u\t",
			   &entry.kvno, &entry.max_life,
			   &entry.max_renewable_life, &entry.mkvno,
			   &entry.expiration, mod_name, &entry.mod_date,
			   &entry.attributes, &stype,
			   &slength) != 10) {
			fprintf(stderr, "Couldn't parse line #%d\n",
				lineno);
			load_error++;
			break;
		}
		entry.salt_type = stype;
		entry.salt_length = slength;
		if (slength) {
			if (!(entry.salt = (krb5_octet *) malloc(slength+1))) {
				free(name);
				free(mod_name);
				xfree(entry.key.contents);
				com_err(argv[0], errno,
					"While allocating space for the salt");
				load_error++;
				break;
			}
		} else
			entry.salt = 0;
		for (i=0; i <entry.salt_length; i++) {
			if (fscanf(f, "%02x", &align) != 1) {
				fprintf(stderr, "Couldn't parse line #%d\n",
					lineno);
				load_error++;
				break;
			}
			entry.salt[i] = align;
		}
		if (((ch = fgetc(f)) != ';') || ((ch = fgetc(f)) != '\n')) {
			fprintf(stderr, "Ignoring trash at end of entry: ");
			while (ch != '\n') {
				putc(ch, stderr);
				ch = fgetc(f);
			}
			putc(ch, stderr);
		}
		if (retval=krb5_parse_name(name, &entry.principal)) {
			com_err(argv[0], retval,
				"while trying to parse %s in line %d",
				name, lineno);
			load_error++;
			goto cleanup;
		}
		if (retval=krb5_parse_name(mod_name, &entry.mod_name)) {
			com_err(argv[0], retval,
				"while trying to parse %s in line %d",
				mod_name, lineno);
			load_error++;
			goto cleanup;
		}
		one=1;
		if (retval = krb5_db_put_principal(&entry, &one)) {
			com_err(argv[0], retval,
				"while trying to store principal %s",
				name);
			load_error++;
			goto cleanup;
		}
	cleanup:
		free(name);
		free(mod_name);
		xfree(entry.key.contents);
	}
error_out:
	if (retval = krb5_db_fini()) {
		com_err(argv[0], retval,
			"while closing database '%s'", new_dbname);
		exit(1);
	}
	if (load_error) {
		printf("Error while loading database, aborting load.\n");
		if (retval = kdb5_db_destroy(new_dbname)) {
			com_err(argv[0], retval,
				"while destroying temporary database '%s'",
				new_dbname);
			exit(1);
		}
		/*
		 * XXX Kludge alert, but we want to exit with a
		 * non-zero status, and it's hard to do that in the ss
		 * framework, since the the do_xxx procedures return
		 * void.  Grump.
		 */
		exit(1);
	} else {
		if (retval = krb5_db_rename(new_dbname, argv[2])) {
			com_err(argv[0], retval,
				"while renaming database from %s to %s",
				new_dbname, argv[2]);
			exit(1);
		}
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
