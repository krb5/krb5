/*
 * admin/edit/dump.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Dump a KDC database
 */

#include "k5-int.h"
#include "com_err.h"
#include "kdb5_edit.h"
#include <stdio.h>

struct dump_record {
	char	*comerr_name;
	FILE	*f;
};

static char ld_vers[] = "kdb5_edit load_dump version 3.0\n";

krb5_encrypt_block master_encblock;
extern char *current_dbname;
extern krb5_boolean dbactive;
extern int exit_status;
extern krb5_context edit_context;

void update_ok_file();

krb5_error_code
dump_iterator(ptr, entry)
    krb5_pointer 	  ptr;
    krb5_db_entry 	* entry;
{
    struct dump_record  * arg = (struct dump_record *) ptr;
    krb5_error_code 	  retval;
    datum		  content;

    if (retval = krb5_encode_princ_contents(edit_context, &content, entry)) {
	com_err(arg->comerr_name, retval, "while encoding an entry");
	exit_status++;
	return retval;
    }
    fprintf(arg->f, "%d\t", content.dsize);
    fwrite(content.dptr, content.dsize, 1, arg->f);
    fprintf(arg->f, ";\n");
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
		exit_status++;
		return;
	}
	if (!dbactive) {
		com_err(argv[0], 0, Err_no_database);
		exit_status++;
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
			exit_status++;
			return;
		}
	} else {
		f = stdout;
	}
	fputs(ld_vers, f);
	arg.comerr_name = argv[0];
	arg.f = f;
	(void)krb5_db_iterate(edit_context, dump_iterator, (krb5_pointer) &arg);
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
		exit_status++;
		return;
	}
	strcpy(file_ok, file_name);
	strcat(file_ok, ok);
	if ((fd = open(file_ok, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
		com_err(progname, errno, "while creating 'ok' file, '%s'",
			file_ok);
		exit_status++;
		free(file_ok);
		return;
	}
	if (write(fd, "", 1) != 1) {
	    com_err(progname, errno, "while writing to 'ok' file, '%s'",
		    file_ok);
	     exit_status++;
	     free(file_ok);
	     return;
	}

	free(file_ok);
	close(fd);
	return;
}


/*
 * Reads a name (actually, any string) of the specified length,
 * containing any characters, and the character following the string.
 * Returns a negative number if the specified number of characters
 * can't be read or if the character following them isn't a tab.
 *
 * If successful, adds a null to the end of the string and returns the
 * number of newlines read into it (usually 0).
 *
 * There must be enough space in the passed-in buffer for len
 * characters followed by a null.
 */
int read_name(f, buf, len)
	FILE	*f;
	char	*buf;
	int	len;
{
	char *ptr;
	int c;
	int newlines = 0;

	for (ptr = buf;
	     (ptr - buf < len) && ((c = fgetc(f)) >= 0);
	     ptr++) {
		*ptr = c;
		if (c == '\n')
		     newlines++;
	}

	if (ptr - buf < len)
	     return -1;

	if ((c = fgetc(f)) < 0)
	     return -1;

	if (c != '\t')
	     return -1;

	*ptr = '\0';

	return newlines;
}
	
	
void load_db(argc, argv)
	int	argc;
	char	**argv;
{
    krb5_error_code 	  retval;
    krb5_db_entry 	  entry;
    datum	  	  contents;
    FILE		* f;
    char		* new_dbname;
    char		  buf[64];	/* Must be longer than ld_vers */
    int			  lineno;
    int			  one;

	int	i;
	int	name_ret;
	int	ch;
	int	load_error = 0;
	int	stype;
	int	tmp1, tmp2, tmp3;
	
	if (argc != 3) {
		com_err(argv[0], 0, "Usage: %s filename dbname", argv[0]);
		exit_status++;
		return;
	}
	if (!(new_dbname = malloc(strlen(argv[2])+2))) {
		com_err(argv[0], 0, "No room to allocate new database name!");
		exit_status++;
		return;
	}
	strcpy(new_dbname, argv[2]);
	strcat(new_dbname, "~");
	if (retval = krb5_db_create(edit_context, new_dbname)) {
		com_err(argv[0], retval, "while creating database '%s'",
			new_dbname);
		exit_status++;
		return;
	}
	if (dbactive) {
		if ((retval = krb5_db_fini(edit_context)) &&
		    retval != KRB5_KDB_DBNOTINITED) {
			com_err(argv[0], retval,
				"while closing previous database");
			exit_status++;
			return;
		}
	}
	if (retval = krb5_db_set_name(edit_context, new_dbname)) {
		com_err(argv[0], retval,
			"while setting active database to '%s'", new_dbname
			);
		exit(1);
	}
	if (retval = krb5_db_init(edit_context)) {
		com_err(argv[0], retval,
			"while initializing database %s",
			new_dbname
			);
		exit(1);
		}
	if (!(f = fopen(argv[1], "r"))) {
		com_err(argv[0], errno,
			"While opening file %s for reading", argv[1]);
		exit_status++;
		return;
	}
	fgets(buf, sizeof(buf), f);
	if (strcmp(buf, ld_vers)) {
		com_err(argv[0], 0, "Bad dump file version");
		load_error++;
	}
	for (lineno = 1; load_error == 0; lineno++) {
	    datum contents;
	    int nitems;

	    memset((char *)&entry, 0, sizeof(entry));
	    if ((nitems = fscanf(f, "%d\t", &contents.dsize)) != 1) {
		if (nitems != EOF) {
	            fprintf(stderr, "Couldn't parse line #%d\n", lineno);
	            load_error++;
		    continue;
		}
		break;
	    }
	    if (!(contents.dptr = malloc(contents.dsize))) {
	        com_err(argv[0], errno, "While allocating space");
	        load_error++;
	        continue;
	    }
	    if (fread(contents.dptr, contents.dsize, 1, f) == EOF) {
	        fprintf(stderr, "Couldn't read line #%d\n", lineno);
	        free(contents.dptr);
	        load_error++;
	        continue;
	    }
	    if (((ch = fgetc(f)) != ';') || ((ch = fgetc(f)) != '\n')) {
	        fprintf(stderr, "Ignoring trash at end of entry: ");
	        while ((ch != '\n') && (ch != EOF)) {
		    putc(ch, stderr);
		    ch = fgetc(f);
	        }
	        putc(ch, stderr);
	        load_error++;
	        continue;
	    }
	    if (retval = krb5_decode_princ_contents(edit_context, &contents, &entry)) {
	    	com_err(argv[0], retval,"while trying to parse line %d",lineno);
	    	free (contents.dptr);
	    	load_error++;
	    	continue;
	    }
	    one=1;
	    if (retval = krb5_db_put_principal(edit_context, &entry, &one)) {
	    	com_err(argv[0], retval, "while trying to write db entry");
	   	krb5_dbe_free_contents(edit_context, &entry);
	    	free (contents.dptr);
		continue;
	    }
	}
	if (retval = krb5_db_fini(edit_context)) {
		com_err(argv[0], retval,
			"while closing database '%s'", new_dbname);
		exit(1);
	}
	if (load_error) {
		printf("Error while loading database, aborting load.\n");
		exit_status += load_error;
		if (retval = kdb5_db_destroy(edit_context, new_dbname)) {
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
		if (retval = krb5_db_rename(edit_context, new_dbname, argv[2])) {
			com_err(argv[0], retval,
				"while renaming database from %s to %s",
				new_dbname, argv[2]);
			exit(1);
		}
	}
	if (dbactive) {
		if (retval = krb5_db_set_name(edit_context, current_dbname)) {
			com_err(argv[0], retval,
				"while resetting active database to '%s'",
				current_dbname);
			exit(1);
		}
		if (retval = krb5_db_init(edit_context)) {
			com_err(argv[0], retval,
				"while initializing active database %s",
				current_dbname);
			exit(1);
		}
	}
}
