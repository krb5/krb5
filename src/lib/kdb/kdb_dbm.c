/*
 * lib/kdb/kdb_dbm.c
 *
 * Copyright 1988,1989,1990,1991 by the Massachusetts Institute of Technology. 
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
 */

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "k5-int.h"
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <utime.h>

#define OLD_COMPAT_VERSION_1

#ifdef OLD_COMPAT_VERSION_1
#include "kdb_compat.h"
#endif

#define KRB5_DBM_MAX_RETRY 5

/* exclusive or shared lock flags */
#define	KRB5_DBM_SHARED		0
#define	KRB5_DBM_EXCLUSIVE	1

/*
 * Per-database context.  One of these is attached to a Kerberos context.
 */
typedef struct __krb5_db_context {
    krb5_boolean	db_inited;	/* Context initialized		*/
    char *		db_name;	/* Name of database		*/
    DBM *		db_dbm_ctx;	/* DBM context for database	*/
    char *		db_lf_name;	/* Name of lock file		*/
    FILE *		db_lf_file;	/* File descriptor of lock file	*/
    int			db_locks_held;	/* Number of times locked	*/
    int			db_lock_mode;	/* Last lock mode, e.g. greatest*/
    krb5_boolean	db_nb_locks;	/* [Non]Blocking lock modes	*/
} db_context_t;

#ifdef DEBUG
extern int debug;
extern long krb5_dbm_db_debug;
extern char *progname;
#endif

static char default_db_name[] = DEFAULT_KDB_FILE;

static krb5_boolean non_blocking = FALSE;

static char *gen_dbsuffix 
	PROTOTYPE((char *, char * ));
static krb5_error_code krb5_dbm_db_start_update 
	PROTOTYPE((krb5_context,
		   char *,
		   time_t * ));
static krb5_error_code krb5_dbm_db_end_update 
	PROTOTYPE((krb5_context,
		   char *,
		   time_t ));
static krb5_error_code krb5_dbm_db_start_read 
	PROTOTYPE((krb5_context,
		   time_t * ));
static krb5_error_code krb5_dbm_db_end_read 
	PROTOTYPE((krb5_context,
		   time_t  ));
static krb5_error_code encode_princ_dbmkey 
	PROTOTYPE((krb5_context,
		   datum *,
		   krb5_principal ));
static void free_encode_princ_dbmkey 
	PROTOTYPE((krb5_context,
		   datum * ));
static krb5_error_code encode_princ_contents
	PROTOTYPE((krb5_context,
		   datum *,
	           krb5_db_entry * ));
static void free_encode_princ_contents 
	PROTOTYPE((datum * ));
static krb5_error_code decode_princ_contents
    	PROTOTYPE((krb5_context,
		   datum *,
	           krb5_db_entry * ));
static void free_decode_princ_contents 
	PROTOTYPE((krb5_context,
		   krb5_db_entry * ));

#if 0
/* not used */
static krb5_error_code decode_princ_dbmkey 
	PROTOTYPE((datum *,
		   krb5_principal * ));
static void free_decode_princ_dbmkey 
	PROTOTYPE((krb5_principal ));
#endif


#ifdef	BERK_DB_DBM
/*
 * This module contains all of the code which directly interfaces to
 * the underlying representation of the Kerberos database; this
 * implementation uses a Berkeley hashed database file to store the
 * relations, plus a third file as a semaphore to allow the database
 * to be replaced out from underneath the KDC server.
 */
extern DBM	*db_dbm_open PROTOTYPE((char *, int, int));
extern void     db_dbm_close PROTOTYPE((DBM *));
extern datum    db_dbm_fetch PROTOTYPE((DBM *, datum));
extern datum    db_dbm_firstkey PROTOTYPE((DBM *));
extern datum    db_dbm_nextkey PROTOTYPE((DBM *));
extern int      db_dbm_delete PROTOTYPE((DBM *, datum));
extern int      db_dbm_store PROTOTYPE((DBM *, datum, datum, int));
extern int	db_dbm_error PROTOTYPE((DBM *));
extern int	db_dbm_clearerr PROTOTYPE((DBM *));
extern int	db_dbm_dirfno PROTOTYPE((DBM *));

#define	KDBM_OPEN(db, fl, mo)	db_dbm_open(db, fl, mo)
#define	KDBM_CLOSE(db)		db_dbm_close(db)
#define	KDBM_FETCH(db, key)	db_dbm_fetch(db, key)
#define	KDBM_FIRSTKEY(db)	db_dbm_firstkey(db)
#define	KDBM_NEXTKEY(db)	db_dbm_nextkey(db)
#define	KDBM_DELETE(db, key)	db_dbm_delete(db, key)
#define	KDBM_STORE(db,key,c,f)	db_dbm_store(db, key, c, f)
#define	KDBM_ERROR(db)		db_dbm_error(db)
#define	KDBM_CLEARERR(db)	db_dbm_clearerr(db)
#define	KDBM_DIRFNO(db)		db_dbm_dirfno(db)
#else	/* BERK_DB_DBM */
/*
 * This module contains all of the code which directly interfaces to
 * the underlying representation of the Kerberos database; this
 * implementation uses a DBM or NDBM indexed "file" (actually
 * implemented as two separate files) to store the relations, plus a
 * third file as a semaphore to allow the database to be replaced out
 * from underneath the KDC server.
 */
#define	KDBM_OPEN(db, fl, mo)	dbm_open(db, fl, mo)
#define	KDBM_CLOSE(db)		dbm_close(db)
#define	KDBM_FETCH(db, key)	dbm_fetch(db, key)
#define	KDBM_FIRSTKEY(db)	dbm_firstkey(db)
#define	KDBM_NEXTKEY(db)	dbm_nextkey(db)
#define	KDBM_DELETE(db, key)	dbm_delete(db, key)
#define	KDBM_STORE(db,key,c,f)	dbm_store(db, key, c, f)
#define	KDBM_ERROR(db)		dbm_error(db)
#define	KDBM_CLEARERR(db)	dbm_clearerr(db)
#define	KDBM_DIRFNO(db)		dbm_dirfno(db)
#endif	/* BERK_DB_DBM */

/*
 * Locking:
 * 
 * There are two distinct locking protocols used.  One is designed to
 * lock against processes (the admin_server, for one) which make
 * incremental changes to the database; the other is designed to lock
 * against utilities (kdb5_edit, kpropd, kdb5_convert) which replace the
 * entire database in one fell swoop.
 *
 * The first locking protocol is implemented using flock() in the 
 * krb_dbl_lock() and krb_dbl_unlock routines.
 *
 * The second locking protocol is necessary because DBM "files" are
 * actually implemented as two separate files, and it is impossible to
 * atomically rename two files simultaneously.  It assumes that the
 * database is replaced only very infrequently in comparison to the time
 * needed to do a database read operation.
 *
 * A third file is used as a "version" semaphore; the modification
 * time of this file is the "version number" of the database.
 * At the start of a read operation, the reader checks the version
 * number; at the end of the read operation, it checks again.  If the
 * version number changed, or if the semaphore was nonexistant at
 * either time, the reader sleeps for a second to let things
 * stabilize, and then tries again; if it does not succeed after
 * KRB5_DBM_MAX_RETRY attempts, it gives up.
 * 
 * On update, the semaphore file is deleted (if it exists) before any
 * update takes place; at the end of the update, it is replaced, with
 * a version number strictly greater than the version number which
 * existed at the start of the update.
 * 
 * If the system crashes in the middle of an update, the semaphore
 * file is not automatically created on reboot; this is a feature, not
 * a bug, since the database may be inconsistant.  Note that the
 * absence of a semaphore file does not prevent another _update_ from
 * taking place later.  Database replacements take place automatically
 * only on slave servers; a crash in the middle of an update will be
 * fixed by the next slave propagation.  A crash in the middle of an
 * update on the master would be somewhat more serious, but this would
 * likely be noticed by an administrator, who could fix the problem and
 * retry the operation.
 */

#define free_dbsuffix(name) free(name)

/*
 * Routines to deal with context.
 */
#define	k5dbm_inited(c)	(c && c->db_context &&	\
			 ((db_context_t *) c->db_context)->db_inited)
/*
 * Restore the default context.
 */
static void
k5dbm_clear_context(dbctx)
    db_context_t	*dbctx;
{
    /*
     * Free any dynamically allocated memory.  File descriptors and locks
     * are the caller's problem.
     */
    if (dbctx->db_lf_name)
	free(dbctx->db_lf_name);
    if (dbctx->db_name && (dbctx->db_name != default_db_name))
	free(dbctx->db_name);
    /*
     * Clear the structure and reset the defaults.
     */
    memset((char *) dbctx, 0, sizeof(db_context_t));
    dbctx->db_name = default_db_name;
    dbctx->db_nb_locks = FALSE;
}

static krb5_error_code
k5dbm_init_context(context)
    krb5_context	context;
{
    db_context_t *	db_ctx;

    if (!context->db_context) {
	db_ctx = (db_context_t *) malloc(sizeof(db_context_t));
	if (!db_ctx)
	    return(ENOMEM);
	context->db_context = (void *) db_ctx;
	memset((char *) db_ctx, 0, sizeof(db_context_t));
	k5dbm_clear_context((db_context_t *) context->db_context);
    }
    return(0);
}

/*
 * Utility routine: generate name of database file.
 */

static char *
gen_dbsuffix(db_name, sfx)
char *db_name;
char *sfx;
{
    char *dbsuffix;
    
    if (sfx == NULL)
	sfx = ".ok";

    dbsuffix = malloc (strlen(db_name) + strlen(sfx) + 1);
    if (!dbsuffix)
	return(0);
    (void) strcpy(dbsuffix, db_name);
    (void) strcat(dbsuffix, sfx);
    return dbsuffix;
}

/*
 * initialization for data base routines.
 */

krb5_error_code
krb5_dbm_db_init(context)
    krb5_context context;
{
    char *filename = 0;
    db_context_t	*db_ctx;
    krb5_error_code	kret;

    if (k5dbm_inited(context))
	return 0;

    /*
     * Check for presence of our context, if not present, allocate one.
     */
    if (kret = k5dbm_init_context(context))
	return(kret);
    db_ctx = context->db_context;

    filename = gen_dbsuffix (db_ctx->db_name, ".ok");
    if (!filename)
	return ENOMEM;
    /*
     * should be open read/write so that write locking can work with
     * POSIX systems
     */
    db_ctx->db_lf_file = fopen(filename, "r+");
    if ((db_ctx->db_lf_file = fopen(filename, "r+")) == NULL) {
	if (errno == EACCES) {
	    if ((db_ctx->db_lf_file = fopen(filename, "r")) == 0)
		goto err_out;
	} else
	    goto err_out;
    }
    db_ctx->db_inited++;
    db_ctx->db_lf_name = filename;
    errno = 0;
    return 0;
    
err_out:
    free(filename);
    k5dbm_clear_context((db_context_t *) context->db_context);
    return (errno);
}

/*
 * gracefully shut down database--must be called by ANY program that does
 * a krb5_dbm_db_init 
 */
krb5_error_code
krb5_dbm_db_fini(context)
    krb5_context context;
{
    krb5_error_code retval;
    db_context_t	*db_ctx;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (db_context_t *) context->db_context;
    if (db_ctx->db_dbm_ctx) {
	/* dbm_close returns void, but it is possible for there to be an
	   error in close().  Possible changes to this routine: check errno
	   on return from dbm_close(), call fsync on the database file
	   descriptors.  */
	KDBM_CLOSE(db_ctx->db_dbm_ctx);
	db_ctx->db_dbm_ctx = (DBM *) NULL;
    }

    if (fclose(db_ctx->db_lf_file) == EOF)
	retval = errno;
    else
	retval = 0;
    k5dbm_clear_context(db_ctx);
    free(context->db_context);
    context->db_context = (void *) NULL;
    return retval;
}

/*
 * Open the database for update.
 */
krb5_error_code
krb5_dbm_db_open_database(context)
    krb5_context context;
{
  db_context_t *db_ctx;

  if (!k5dbm_inited(context))
    return KRB5_KDB_DBNOTINITED;

  db_ctx = (db_context_t *) context->db_context;
  if (!(db_ctx->db_dbm_ctx = (DBM *)KDBM_OPEN(db_ctx->db_name, O_RDWR, 0600)))
    return errno;

  /* It is safe to ignore errors here because all function which write
     to the database try again to lock.  */
  (void) krb5_dbm_db_lock(context, KRB5_DBM_EXCLUSIVE);

  return 0;
}

krb5_error_code
krb5_dbm_db_close_database(context)
    krb5_context context;
{
  db_context_t *db_ctx;

  if (!k5dbm_inited(context))
    return KRB5_KDB_DBNOTINITED;

  db_ctx = (db_context_t *) context->db_context;
  KDBM_CLOSE(db_ctx->db_dbm_ctx);
  db_ctx->db_dbm_ctx = (DBM *) NULL;
  (void) krb5_dbm_db_unlock(context);
  return 0;
}

/*
 * Set the "name" of the current database to some alternate value.
 *
 * Passing a null pointer as "name" will set back to the default.
 * If the alternate database doesn't exist, nothing is changed.
 */

krb5_error_code
krb5_dbm_db_set_name(context, name)
    krb5_context context;
    char *name;
{
    DBM *db;
    db_context_t *db_ctx;
    krb5_error_code kret;

    if (k5dbm_inited(context))
	return KRB5_KDB_DBINITED;
    /*
     * Check for presence of our context, if not present, allocate one.
     */
    if (kret = k5dbm_init_context(context))
	return(kret);
    db_ctx = context->db_context;
    if (name == NULL)
	name = default_db_name;
    db = KDBM_OPEN(name, O_RDONLY, 0);
    if (db == NULL)
	return errno;
    KDBM_CLOSE(db);
    db_ctx->db_name = strdup(name);
    return 0;
}

/*
 * Return the last modification time of the database.
 */

krb5_error_code
krb5_dbm_db_get_age(context, db_name, age)
    krb5_context context;
    char *db_name;
    time_t *age;
{
    struct stat st;
    char *okname;
    char *ctxname;
    
    ctxname = default_db_name;
    if (context && context->db_context &&
	((db_context_t *) context->db_context)->db_name)
	ctxname = ((db_context_t *) context->db_context)->db_name;
    okname = gen_dbsuffix(db_name ? db_name : ctxname, ".ok");

    if (!okname)
	return ENOMEM;
    if (stat (okname, &st) < 0)
	*age = -1;
    else
	*age = st.st_mtime;

    free_dbsuffix (okname);
    return 0;
}

/* start_update() and end_update() are used to bracket a database replacement
   operation
 */

/*
 * Remove the semaphore file; indicates that database is currently
 * under renovation.
 *
 * This is only for use when moving the database out from underneath
 * the server (for example, during slave updates).
 */

static krb5_error_code
krb5_dbm_db_start_update(context, db_name, age)
    krb5_context context;
    char *db_name;
    time_t *age;
{
    char *okname;
    krb5_error_code retval;

    okname = gen_dbsuffix(db_name, ".ok");
    if (!okname)
	return ENOMEM;

    retval = krb5_dbm_db_get_age(context, db_name, age);
    if (!retval && unlink(okname) < 0) {
	if (errno != ENOENT)
	    retval = errno;
    }
    free_dbsuffix (okname);
    return retval;
}

static krb5_error_code
krb5_dbm_db_end_update(context, db_name, age)
    krb5_context context;
    char *db_name;
    time_t age;
{
    int fd;
    krb5_error_code retval = 0;
    char *new_okname;
    char *okname;

    /* strategy:
       create a new "ok" file, set its modify time to "age",
       and move it on top of the old "ok" file.
     */
    new_okname = gen_dbsuffix(db_name, ".ok#");
    if (!new_okname)
	return ENOMEM;
    okname = gen_dbsuffix(db_name, ".ok");
    if (!okname) {
	free_dbsuffix(new_okname);
	return ENOMEM;
    }    

    fd = open (new_okname, O_CREAT|O_RDWR|O_TRUNC, 0600);
    if (fd < 0)
	retval = errno;
    else {
	struct stat st;
	struct utimbuf times;
	/* only set the time if the new file is "newer" than
	   "age" */
	if ((fstat (fd, &st) == 0) && (st.st_mtime <= age)) {
	    times.actime = st.st_atime;
	    times.modtime = age;
	    /* set the mod timetimes.. */
	    utime(new_okname, &times);
#ifndef NOFSYNC
	    fsync(fd);
#endif
	}
	close(fd);
	if (rename (new_okname, okname) < 0)
	    retval = errno;
    }

    free_dbsuffix (new_okname);
    free_dbsuffix (okname);

    return retval;
}

/* Database readers call start_read(), do the reading, and then call
   end_read() with the value from start_read().

   If the value of krb5_dbm_db_get_age(context, NULL, age) changes while 
   this is going on, then the reader has encountered a modified database 
   and should retry.
*/

static krb5_error_code
krb5_dbm_db_start_read(context, age)
    krb5_context context;
    time_t *age;
{
    return (krb5_dbm_db_get_age(context, NULL, age));
}

static krb5_error_code
krb5_dbm_db_end_read(context, age)
    krb5_context context;
    time_t age;
{
    time_t age2;
    krb5_error_code retval;

    if (retval = krb5_dbm_db_get_age(context, NULL, &age2))
	return retval;
    if (age2 != age || age == -1) {
	return KRB5_KDB_DB_CHANGED;
    }
    return 0;
}


static krb5_error_code
encode_princ_dbmkey(context, key, principal)
    krb5_context context;
    datum  *key;
    krb5_principal principal;
{
    char *princ_name;
    krb5_error_code retval;

    if (retval = krb5_unparse_name(context, principal, &princ_name))
	return(retval);
    key->dptr = princ_name;
    key->dsize = strlen(princ_name)+1;	/* need to store the NULL for
					   decoding */
    return 0;
}

static void
free_encode_princ_dbmkey(context, key)
    krb5_context context;
    datum  *key;
{
    (void) free(key->dptr);
    key->dptr = 0;
    key->dsize = 0;
    return;
}

#if 0
/* these aren't used, but if they ever should be... */
static krb5_error_code
decode_princ_dbmkey(context, key, principal)
    datum  *key;
    krb5_principal *principal;
{
    return(krb5_parse_name(context, key->dptr, principal));
}

static void
free_decode_princ_dbmkey(context, principal)
    krb5_context context;
    krb5_principal principal;
{
    krb5_free_principal(context, principal);
    return;
}
#endif

static krb5_error_code
encode_princ_contents(context, contents, entry)
    krb5_context context;
    register datum  *contents;
    krb5_db_entry *entry;
{
    krb5_db_entry copy_princ;
    char *unparse_princ, *unparse_mod_princ;
    register char *nextloc;
    int princ_size, mod_size;

    krb5_error_code retval;

    /* since there is some baggage pointing off of the entry
       structure, we'll encode it by writing the structure, with nulled
       pointers, followed by the unparsed principal name, then the key, and
       then the unparsed mod_princ name, and then the salt (if any).
       */
    copy_princ = *entry;
    copy_princ.principal = 0;
    copy_princ.mod_name = 0;
    copy_princ.salt = 0;
    copy_princ.alt_salt = 0;
    if (!entry->salt)
	copy_princ.salt_length = 0; /* Safety measures.... */
    if (!entry->alt_salt)
	copy_princ.alt_salt_length = 0;

    if (retval = krb5_unparse_name(context, entry->principal, &unparse_princ))
	return(retval);
    if (retval = krb5_unparse_name(context, entry->mod_name, &unparse_mod_princ)) {
	free(unparse_princ);
	return(retval);
    }
    princ_size = strlen(unparse_princ)+1;
    mod_size = strlen(unparse_mod_princ)+1;
    contents->dsize = (2 + sizeof(copy_princ) + princ_size
		       + sizeof(entry->principal->type) + mod_size
		       + sizeof(copy_princ.key.length) 
		       + copy_princ.key.length + copy_princ.salt_length
		       + sizeof(copy_princ.alt_key.length)
		       + copy_princ.alt_key.length
		       + copy_princ.alt_salt_length);
    contents->dptr = malloc(contents->dsize);
    if (!contents->dptr) {
	free(unparse_princ);
	free(unparse_mod_princ);
	contents->dsize = 0;
	contents->dptr = 0;
	return(ENOMEM);
    }
    nextloc = contents->dptr;
    *nextloc++ = 2;		/* Version number 2.0 */
    *nextloc++ = 0;
    (void) memcpy(nextloc, (char *)&copy_princ, sizeof(copy_princ));
    nextloc += sizeof(copy_princ);

    (void) memcpy(nextloc, unparse_princ, princ_size);
    nextloc += princ_size;
    (void) memcpy(nextloc, (char *)&entry->principal->type,
		  sizeof(entry->principal->type));
    nextloc +=  sizeof(entry->principal->type);
    (void) memcpy(nextloc, unparse_mod_princ, mod_size);
    nextloc += mod_size;
    if (copy_princ.key.length) {
	(void) memcpy(nextloc, (char *)entry->key.contents, entry->key.length);
	nextloc += entry->key.length;
    }
    if (copy_princ.salt_length) {
	(void) memcpy(nextloc, (char *)entry->salt, entry->salt_length);
	nextloc += entry->salt_length;
    }
    if (copy_princ.alt_key.length) {
	(void) memcpy(nextloc, (char *)entry->alt_key.contents,
		      entry->alt_key.length);
	nextloc += entry->alt_key.length;
    }
    if (copy_princ.alt_salt_length) {
	(void) memcpy(nextloc, (char *)entry->alt_salt,
		      entry->alt_salt_length);
	nextloc += entry->alt_salt_length;
    }
    free(unparse_princ);
    free(unparse_mod_princ);
    return 0;
}

static void
free_encode_princ_contents(contents)
    datum *contents;
{
    free(contents->dptr);
    contents->dsize = 0;
    contents->dptr = 0;
    return;
}

static krb5_error_code
decode_princ_contents(context, contents, entry)
    krb5_context context;
    datum  *contents;
    krb5_db_entry *entry;
{
    register char *nextloc;
    krb5_principal princ, mod_princ;
    krb5_error_code retval;
    int	sizeleft;
    int major_version = 0, minor_version = 0;

    /*
     * undo the effects of encode_princ_contents.
     */
    sizeleft = contents->dsize;
    nextloc = contents->dptr;
    if (sizeleft <= 0)
	return KRB5_KDB_TRUNCATED_RECORD;

    /*
     * First, check the version number.  If the major version number is
     * greater than zero, then the version number is explicitly
     * allocated; otherwise, it is part of the zeroed principal pointer.
     */
    major_version = *nextloc;
    if (major_version) {
	nextloc++; sizeleft--;
	minor_version = *nextloc;
	nextloc++; sizeleft--;
    }
#ifdef OLD_COMPAT_VERSION_1
    if (major_version == 0 || major_version == 1) {
	old_krb5_db_entry old_entry;

	/*
	 * Copy in structure to old-style structure, and then copy it
	 * to the new structure.
	 */
	sizeleft -= sizeof(old_entry);
	if (sizeleft < 0) 
	    return KRB5_KDB_TRUNCATED_RECORD;

	memcpy((char *) &old_entry, nextloc, sizeof(old_entry));
	nextloc += sizeof(old_entry);	/* Skip past structure */
	
	entry->key.keytype = old_entry.key.keytype;
	entry->key.length = old_entry.key.length;

	entry->kvno = old_entry.kvno;
	entry->max_life = old_entry.max_life;
	entry->max_renewable_life = old_entry.max_renewable_life;
	entry->mkvno = old_entry.mkvno;
	
	entry->expiration = old_entry.expiration;
	entry->pw_expiration = old_entry.pw_expiration;
	entry->last_pwd_change = old_entry.last_pwd_change;
	entry->last_success = old_entry.last_success;
    
	entry->last_failed = old_entry.last_failed;
	entry->fail_auth_count = old_entry.fail_auth_count;
    
	entry->mod_date = old_entry.mod_date;
	entry->attributes = old_entry.attributes;
	entry->salt_type = old_entry.salt_type;
	entry->salt_length = old_entry.salt_length;
	
	entry->alt_key.keytype = old_entry.alt_key.keytype;
	entry->alt_key.length = old_entry.alt_key.length;
	entry->alt_salt_type = old_entry.alt_salt_type;
	entry->alt_salt_length = old_entry.alt_salt_length;

	goto resume_processing;
    }
#endif
    if (major_version != 2)
	return KRB5_KDB_BAD_VERSION;
    
    sizeleft -= sizeof(*entry);
    if (sizeleft < 0) 
	return KRB5_KDB_TRUNCATED_RECORD;

    memcpy((char *) entry, nextloc, sizeof(*entry));
    nextloc += sizeof(*entry);	/* Skip past structure */

#ifdef OLD_COMPAT_VERSION_1
resume_processing:
#endif
    
    /*
     * These values should be zero if they are not in use, but just in
     * case, we clear them to make sure nothing bad happens if we need
     * to call free_decode_princ_contents().  (What me, paranoid?)
     */
    entry->principal = 0;
    entry->mod_name = 0;
    entry->salt = 0;
    entry->alt_salt = 0;
    entry->key.contents = 0;
    entry->alt_key.contents = 0;

    /*
     * Get the principal name for the entry (stored as a string which
     * gets unparsed.)
     */
    sizeleft -= strlen(nextloc)+1;
    if (sizeleft < 0) {
	retval = KRB5_KDB_TRUNCATED_RECORD;
	goto error_out;
    }
    retval = krb5_parse_name(context, nextloc, &princ);
    if (retval)
	goto error_out;
    entry->principal = princ;
    nextloc += strlen(nextloc)+1;	/* advance past 1st string */

    if (major_version >= 1) {		/* Get principal type */
	sizeleft -= sizeof(entry->principal->type);
	if (sizeleft < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	memcpy((char *)&entry->principal->type,nextloc,
	       sizeof(entry->principal->type));
	nextloc += sizeof(princ->type);
    }
    
    /*
     * Get the last modified principal for the entry (again stored as
     * string which gets unparased.)
     */
    sizeleft -= strlen(nextloc)+1;	/* check size for 2nd string */
    if (sizeleft < 0) {
	retval = KRB5_KDB_TRUNCATED_RECORD;
	goto error_out;
    }
    retval = krb5_parse_name(context, nextloc, &mod_princ);
    if (retval)
	goto error_out;
    entry->mod_name = mod_princ;
    nextloc += strlen(nextloc)+1;	/* advance past 2nd string */
    
    /*
     * Get the primary key...
     */
    if (entry->key.length) {
	sizeleft -= entry->key.length; 	/* check size for key */
	if (sizeleft < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	entry->key.contents = (unsigned char *)malloc(entry->key.length);
	if (!entry->key.contents) {
	    retval = ENOMEM;
	    goto error_out;
	}
	(void) memcpy((char *)entry->key.contents, nextloc, entry->key.length);
	nextloc += entry->key.length;	/* advance past key */
    }
	
    /*
     * ...and the salt, if present...
     */
    if (entry->salt_length) {
	sizeleft -= entry->salt_length;
	if (sizeleft < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	entry->salt = (krb5_octet *)malloc(entry->salt_length);
	if (!entry->salt) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	(void) memcpy((char *)entry->salt, nextloc, entry->salt_length);
	nextloc += entry->salt_length; /* advance past salt */
    }

    /*
     * ... and the alternate key, if present...
     */
    if (entry->alt_key.length) {
	sizeleft -= entry->alt_key.length; 	/* check size for alt_key */
	if (sizeleft < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	entry->alt_key.contents = (unsigned char *) malloc(entry->alt_key.length);
	if (!entry->alt_key.contents) {
	    retval = ENOMEM;
	    goto error_out;
	}
	(void) memcpy((char *)entry->alt_key.contents, nextloc,
		      entry->alt_key.length);
	nextloc += entry->alt_key.length;	/* advance past alt_key */
    }
	
    /*
     * ...and the alternate key's salt, if present.
     */
    if (entry->alt_salt_length) {
	sizeleft -= entry->alt_salt_length;
	if (sizeleft < 0) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	entry->alt_salt = (krb5_octet *)malloc(entry->alt_salt_length);
	if (!entry->alt_salt) {
	    retval = KRB5_KDB_TRUNCATED_RECORD;
	    goto error_out;
	}
	(void) memcpy((char *)entry->alt_salt, nextloc,
		      entry->alt_salt_length);
	nextloc += entry->alt_salt_length; /* advance past salt */
    }
    
    return 0;
error_out:
    free_decode_princ_contents(context, entry);
    return retval;
}

static void
free_decode_princ_contents(context, entry)
     krb5_context context; 
     krb5_db_entry *entry;
{
    /* erase the key */
    if (entry->key.contents) {
	memset((char *)entry->key.contents, 0, entry->key.length);
	krb5_xfree(entry->key.contents);
    }
    if (entry->salt)
	krb5_xfree(entry->salt);
    
    if (entry->alt_key.contents) {
	memset((char *)entry->alt_key.contents, 0, entry->alt_key.length);
	krb5_xfree(entry->alt_key.contents);
    }
    if (entry->alt_salt)
	krb5_xfree(entry->alt_salt);
    
    if (entry->principal)
	krb5_free_principal(context, entry->principal);
    if (entry->mod_name)
	krb5_free_principal(context, entry->mod_name);
    (void) memset((char *)entry, 0, sizeof(*entry));
    return;
}

krb5_error_code
krb5_dbm_db_lock(context, mode)
    krb5_context context;
    int mode;
{
    int krb5_lock_mode;
    int error;
    db_context_t	*db_ctx;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (db_context_t *) context->db_context;
    if (db_ctx->db_locks_held && (db_ctx->db_lock_mode >= mode)) {
	    /* No need to upgrade lock, just return */
	    db_ctx->db_locks_held++;
	    return(0);
    }

    switch (mode) {
    case KRB5_DBM_EXCLUSIVE:
	krb5_lock_mode = KRB5_LOCKMODE_EXCLUSIVE;
	break;
    case KRB5_DBM_SHARED:
	krb5_lock_mode = KRB5_LOCKMODE_SHARED;
	break;
    default:
	return KRB5_KDB_BADLOCKMODE;
    }
    if (db_ctx->db_nb_locks)
	krb5_lock_mode |= KRB5_LOCKMODE_DONTBLOCK;

    error = krb5_lock_file(context,
			   db_ctx->db_lf_file,
			   db_ctx->db_lf_name,
			   krb5_lock_mode);

    if (error == EBADF && mode == KRB5_DBM_EXCLUSIVE)
	return KRB5_KDB_CANTLOCK_DB;
    if (error)
	return error;
    db_ctx->db_locks_held++;
    return 0;
}

krb5_error_code
krb5_dbm_db_unlock(context)
    krb5_context context;
{
    db_context_t	*db_ctx;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (db_context_t *) context->db_context;
    if (!db_ctx->db_locks_held)		/* lock already unlocked */
	return KRB5_KDB_NOTLOCKED;

    if (--(db_ctx->db_locks_held) == 0) {
      return krb5_lock_file(context,
			    db_ctx->db_lf_file,
			    db_ctx->db_lf_name,
			    KRB5_LOCKMODE_UNLOCK);
    }
    return 0;
}

/*
 * Create the database, assuming it's not there.
 */

krb5_error_code
krb5_dbm_db_create(context, db_name)
    krb5_context context;
    char *db_name;
{
    char *okname;
    int fd;
    register krb5_error_code retval = 0;
#ifndef ODBM
    DBM *db;

    db = KDBM_OPEN(db_name, O_RDWR|O_CREAT|O_EXCL, 0600);
    if (db == NULL)
	retval = errno;
    else
	KDBM_CLOSE(db);
#else /* OLD DBM */
    char *dirname;
    char *pagname;

    dirname = gen_dbsuffix(db_name, ".dir");
    if (!dirname)
	return ENOMEM;
    pagname = gen_dbsuffix(db_name, ".pag");
    if (!pagname) {
	free_dbsuffix(dirname);
	return ENOMEM;
    }    

    fd = open(dirname, O_RDWR|O_CREAT|O_EXCL, 0600);
    if (fd < 0)
	retval = errno;
    else {
	close(fd);
	fd = open (pagname, O_RDWR|O_CREAT|O_EXCL, 0600);
	if (fd < 0)
	    retval = errno;
	else
	    close(fd);
	if (dbminit(db_name) < 0)
	    retval = errno;
    }
    free_dbsuffix(dirname);
    free_dbsuffix(pagname);
#endif /* ODBM */
    if (retval == 0) {
	okname = gen_dbsuffix(db_name, ".ok");
	if (!okname)
	    retval = ENOMEM;
	else {
	    fd = open (okname, O_CREAT|O_RDWR|O_TRUNC, 0600);
	    if (fd < 0)
		retval = errno;
	    else
		close(fd);
	    free_dbsuffix(okname);
	}
    }
    return retval;
}

/*
 * Destroy the database.  Zero's out all of the files, just to be sure.
 */
krb5_error_code
destroy_file_suffix(dbname, suffix)
	char	*dbname;
	char	*suffix;
{
	char	*filename;
	struct stat	statb;
	int		nb,fd,i;
	char		buf[BUFSIZ];

	filename = gen_dbsuffix(dbname, suffix);
	if (filename == 0)
		return ENOMEM;
	if ((fd = open(filename, O_RDWR, 0)) < 0) {
		int retval = errno == ENOENT ? 0 : errno;
		free(filename);
		return retval;
	}
	/* fstat() will probably not fail unless using a remote filesystem
	   (which is inappropriate for the kerberos database) so this check
	   is mostly paranoia.  */
	if (fstat(fd, &statb) == -1) {
		int retval = errno;
		free(filename);
		return retval;
	}
	i = 0;
	while (i < statb.st_size) {
		nb = write(fd, buf, BUFSIZ);
		if (nb < 0) {
			int retval = errno;
			free(filename);
			return retval;
		}
		i += nb;
	}
	/* ??? Is fsync really needed?  I don't know of any non-networked
	   filesystem which will discard queued writes to disk if a file
	   is deleted after it is closed.  --jfc */
#ifndef NOFSYNC
	fsync(fd);
#endif
	close(fd);

	if (unlink(filename)) {
		int retval = errno;
		free(filename);
		return(errno);
	}
	free(filename);
	return(0);
}

krb5_error_code
krb5_dbm_db_destroy(context, dbname)
    krb5_context context;
	char	*dbname;
{
	krb5_error_code	retval;

#ifndef	BERK_DB_DBM
	if (retval = destroy_file_suffix(dbname, ".pag"))
		return(retval);
	if (retval = destroy_file_suffix(dbname, ".dir"))
		return(retval);
#else	/* BERK_DB_DBM */
	if (retval = destroy_file_suffix(dbname, ".db"))
		return(retval);
#endif	/* BERK_DB_DBM */
	if (retval = destroy_file_suffix(dbname, ".ok"))
		return(retval);
	return(0);
}

/*
 * "Atomically" rename the database in a way that locks out read
 * access in the middle of the rename.
 *
 * Not perfect; if we crash in the middle of an update, we don't
 * necessarily know to complete the transaction the rename, but...
 */

krb5_error_code
krb5_dbm_db_rename(context, from, to)
    krb5_context context;
    char *from;
    char *to;
{
    char *fromdir = 0;
    char *todir = 0;
    char *frompag = 0;
    char *topag = 0;
    char *fromok = 0;
    time_t trans;
    krb5_error_code retval;

#ifndef	BERK_DB_DBM
    fromdir = gen_dbsuffix (from, ".dir");
    if (!fromdir)
	return ENOMEM;
    todir = gen_dbsuffix (to, ".dir");
    if (!todir) {
	retval = ENOMEM;
	goto errout;
    }
    frompag = gen_dbsuffix (from, ".pag");
    if (!frompag) {
	retval = ENOMEM;
	goto errout;
    }
    topag = gen_dbsuffix (to, ".pag");
    if (!topag) {
	retval = ENOMEM;
	goto errout;
    }
#else	/* BERK_DB_DBM */
    fromdir = gen_dbsuffix (from, ".db");
    if (!fromdir)
	return ENOMEM;
    todir = gen_dbsuffix (to, ".db");
    if (!todir) {
	retval = ENOMEM;
	goto errout;
    }
#endif	/* BERK_DB_DBM */
    fromok = gen_dbsuffix(from, ".ok");
    if (!fromok) {
	retval = ENOMEM;
	goto errout;
    }

    if (retval = krb5_dbm_db_start_update(context, to, &trans))
	goto errout;
    
    if ((rename (fromdir, todir) == 0)
#ifndef	BERK_DB_DBM
	&& (rename (frompag, topag) == 0)
#endif	/* BERK_DB_DBM */
	) {
	(void) unlink (fromok);
	retval = 0;
    } else
	retval = errno;
    
errout:
    if (fromok)
	free_dbsuffix (fromok);
#ifndef	BERK_DB_DBM
    if (topag)
	free_dbsuffix (topag);
    if (frompag)
	free_dbsuffix (frompag);
#endif	/* BERK_DB_DBM */
    if (todir)
	free_dbsuffix (todir);
    if (fromdir)
	free_dbsuffix (fromdir);

    if (retval == 0)
	return krb5_dbm_db_end_update(context, to, trans);
    else
	return retval;
}

/*
 * look up a principal in the data base.
 * returns number of entries found, and whether there were
 * more than requested. 
 */

krb5_error_code
krb5_dbm_db_get_principal(context, searchfor, entries, nentries, more)
    krb5_context context;
krb5_principal searchfor;
krb5_db_entry *entries;		/* filled in */
int *nentries;				/* how much room/how many found */
krb5_boolean *more;			/* are there more? */
{
    int     found = 0;
    datum   key, contents;
    time_t	transaction;
    int try;
    DBM    *db;
    krb5_error_code retval;
    db_context_t *db_ctx;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (db_context_t *) context->db_context;
    for (try = 0; try < KRB5_DBM_MAX_RETRY; try++) {
	if (retval = krb5_dbm_db_start_read(context, &transaction))
	    return(retval);

	if (retval = krb5_dbm_db_lock(context, KRB5_DBM_SHARED))
	    return(retval);

	if (db_ctx->db_dbm_ctx)
	    db = db_ctx->db_dbm_ctx;
	else {
	    db = KDBM_OPEN(db_ctx->db_name, O_RDONLY, 0600);
	    if (db == NULL) {
		retval = errno;
		(void) krb5_dbm_db_unlock(context);
		return retval;
	    }
	}

	*more = FALSE;

	/* XXX deal with wildcard lookups */
	if (retval = encode_princ_dbmkey(context, &key, searchfor))
	    goto cleanup;

	contents = KDBM_FETCH(db, key);
	free_encode_princ_dbmkey(context, &key);

	if (contents.dptr == NULL)
	    found = 0;
	else if (retval = decode_princ_contents(context, &contents, entries))
	    goto cleanup;
	else found = 1;

	if (db_ctx->db_dbm_ctx == 0)
	    KDBM_CLOSE(db);
	(void) krb5_dbm_db_unlock(context);	/* unlock read lock */
	if (krb5_dbm_db_end_read(context, transaction) == 0)
	    break;
	found = -1;
	if (!db_ctx->db_nb_locks)
	    sleep(1);
    }
    if (found == -1) {
	*nentries = 0;
	return KRB5_KDB_DB_INUSE;
    }
    *nentries = found;
    return(0);

 cleanup:
    if (db_ctx->db_dbm_ctx == 0)
	KDBM_CLOSE(db);
    (void) krb5_dbm_db_unlock(context);	/* unlock read lock */
    return retval;
}

/*
  Free stuff returned by krb5_dbm_db_get_principal.
 */
void
krb5_dbm_db_free_principal(context, entries, nentries)
    krb5_context context;
    krb5_db_entry *entries;
    int nentries;
{
    register int i;
    for (i = 0; i < nentries; i++)
	free_decode_princ_contents(context, &entries[i]);
    return;
}

/*
  Stores the *"nentries" entry structures pointed to by "entries" in the
  database.

  *"nentries" is updated upon return to reflect the number of records
  acutally stored; the first *"nstored" records will have been stored in the
  database (even if an error occurs).

 */

krb5_error_code
krb5_dbm_db_put_principal(context, entries, nentries)
    krb5_context context;
    krb5_db_entry *entries;
    register int *nentries;			/* number of entry structs to
					 * update */

{
    register int i;
    datum   key, contents;
    DBM    *db;
    krb5_error_code retval;
    db_context_t *db_ctx;

#define errout(code) { *nentries = 0; return code; }

    if (!k5dbm_inited(context))
	errout(KRB5_KDB_DBNOTINITED);

    db_ctx = (db_context_t *) context->db_context;
    if (retval = krb5_dbm_db_lock(context, KRB5_DBM_EXCLUSIVE))
	errout(retval);

    if (db_ctx->db_dbm_ctx)
	db = db_ctx->db_dbm_ctx;
    else {
	db = KDBM_OPEN(db_ctx->db_name, O_RDWR, 0600);
	if (db == NULL) {
	    retval = errno;
	    (void) krb5_dbm_db_unlock(context);
	    *nentries = 0;
	    return retval;
	}
    }

#undef errout

    /* for each one, stuff temps, and do replace/append */
    for (i = 0; i < *nentries; i++) {
	if (retval = encode_princ_contents(context, &contents, entries))
	    break;

	if (retval = encode_princ_dbmkey(context, &key, entries->principal)) {
	    free_encode_princ_contents(&contents);
	    break;
	}
	if (KDBM_STORE(db, key, contents, DBM_REPLACE))
	    retval = errno;
	else
	    retval = 0;
	free_encode_princ_contents(&contents);
	free_encode_princ_dbmkey(context, &key);
	if (retval)
	    break;
	entries++;			/* bump to next struct */
    }

    if (db_ctx->db_dbm_ctx == 0)
	KDBM_CLOSE(db);
    (void) krb5_dbm_db_unlock(context);		/* unlock database */
    *nentries = i;
    return (retval);
}

/*
 * delete a principal from the data base.
 * returns number of entries removed
 */

krb5_error_code
krb5_dbm_db_delete_principal(context, searchfor, nentries)
    krb5_context context;
krb5_principal searchfor;
int *nentries;				/* how many found & deleted */
{
    int     found = 0;
    datum   key, contents, contents2;
    krb5_db_entry entry;
    DBM    *db;
    krb5_error_code retval;
    db_context_t *db_ctx;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (db_context_t *) context->db_context;
    if (retval = krb5_dbm_db_lock(context, KRB5_DBM_EXCLUSIVE))
	return(retval);

    if (db_ctx->db_dbm_ctx)
	db = db_ctx->db_dbm_ctx;
    else {
	db = KDBM_OPEN(db_ctx->db_name, O_RDWR, 0600);
	if (db == NULL) {
	    retval = errno;
	    (void) krb5_dbm_db_unlock(context);
	    return retval;
	}
    }

    if (retval = encode_princ_dbmkey(context, &key, searchfor))
	goto cleanup;

    contents = KDBM_FETCH(db, key);
    if (contents.dptr == NULL) {
	found = 0;
	retval = KRB5_KDB_NOENTRY;
    } else {
	if (retval = decode_princ_contents(context, &contents, &entry))
	    goto cleankey;
	found = 1;
	memset((char *)entry.key.contents, 0, entry.key.length);
	if (retval = encode_princ_contents(context, &contents2, &entry))
	    goto cleancontents;

	if (KDBM_STORE(db, key, contents2, DBM_REPLACE))
	    retval = errno;
	else {
	    if (KDBM_DELETE(db, key))
		retval = errno;
	    else
		retval = 0;
	}
	free_encode_princ_contents(&contents2);
    cleancontents:
	free_decode_princ_contents(context, &entry);
    cleankey:
	free_encode_princ_dbmkey(context, &key);
    }

 cleanup:
    if (db_ctx->db_dbm_ctx == 0)
	KDBM_CLOSE(db);
    (void) krb5_dbm_db_unlock(context);	/* unlock write lock */
    *nentries = found;
    return retval;
}

krb5_error_code
krb5_dbm_db_iterate (context, func, func_arg)
    krb5_context context;
    krb5_error_code (*func) PROTOTYPE((krb5_pointer, krb5_db_entry *));
    krb5_pointer func_arg;
{
    datum key, contents;
    krb5_db_entry entries;
    krb5_error_code retval;
    DBM *db;
    db_context_t *db_ctx;
    
    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (db_context_t *) context->db_context;
    if (retval = krb5_dbm_db_lock(context, KRB5_DBM_SHARED))
	return retval;

    if (db_ctx->db_dbm_ctx)
	db = db_ctx->db_dbm_ctx;
    else {
	db = KDBM_OPEN(db_ctx->db_name, O_RDONLY, 0600);
	if (db == NULL) {
	    retval = errno;
	    (void) krb5_dbm_db_unlock(context);
	    return retval;
	}
    }

    for (key = KDBM_FIRSTKEY (db); key.dptr != NULL; key = KDBM_NEXTKEY(db)) {
	contents = KDBM_FETCH (db, key);
	if (retval = decode_princ_contents(context, &contents, &entries))
	    break;
	retval = (*func)(func_arg, &entries);
	free_decode_princ_contents(context, &entries);
	if (retval)
	    break;
    }
    if (db_ctx->db_dbm_ctx == 0)
	KDBM_CLOSE(db);
    (void) krb5_dbm_db_unlock(context);
    return retval;
}

krb5_boolean
krb5_dbm_db_set_lockmode(context, mode)
    krb5_context context;
    krb5_boolean mode;
{
    krb5_boolean old;
    db_context_t *db_ctx;

    old = mode;
    if (db_ctx = (db_context_t *) context->db_context) {
	old = db_ctx->db_nb_locks;
	db_ctx->db_nb_locks = mode;
    }
    return old;
}
