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

/* Obtain dispatch table definitions from kdb.h */
#define	KDB5_DISPATCH
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
    kdb5_dispatch_table	*db_dispatch;	/* Dispatch table		*/
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


#ifdef	BERK_DB_DBM
/*
 * This module contains all of the code which directly interfaces to
 * the underlying representation of the Kerberos database; this
 * implementation uses a Berkeley hashed database file to store the
 * relations, plus a second file as a semaphore to allow the database
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

static kdb5_dispatch_table kdb5_default_dispatch = {
    "Berkeley Hashed Database",
    ".db",			/* Index file name ext	*/
    (char *) NULL,		/* Data file name ext	*/
    ".ok",			/* Lock file name ext	*/
    db_dbm_open,		/* Open Database	*/
    db_dbm_close,		/* Close Database	*/
    db_dbm_fetch,		/* Fetch Key		*/
    db_dbm_firstkey,		/* Fetch First Key	*/
    db_dbm_nextkey,		/* Fetch Next Key	*/
    db_dbm_delete,		/* Delete Key		*/
    db_dbm_store,		/* Store Key		*/
    db_dbm_error,		/* Get Database Error	*/
    db_dbm_clearerr,		/* Clear Database Error	*/
    db_dbm_dirfno,		/* Get DB index FD num	*/
    (int (*)()) NULL		/* Get DB data FD num	*/
};
#else	/* BERK_DB_DBM */
/*
 * The following prototypes are necessary in case dbm_error and
 * dbm_clearerr are in the library but not prototyped
 * (e.g. NetBSD-1.0)
 */
#ifdef MISSING_ERROR_PROTO
int dbm_error PROTOTYPE((DBM *));
#endif
#ifdef MISSING_CLEARERR_PROTO
int dbm_clearerr PROTOTYPE((DBM *));
#endif

/*
 * This module contains all of the code which directly interfaces to
 * the underlying representation of the Kerberos database; this
 * implementation uses the Berkeley hash db to store the relations, plus a
 * second file as a semaphore to allow the database to be replaced out
 * from underneath the KDC server.
 */
static kdb5_dispatch_table kdb5_default_dispatch = {
    "Stock [N]DBM Database",
    ".dir",			/* Index file name ext	*/
    ".pag",			/* Data file name ext	*/
    ".ok",			/* Lock file name ext	*/
    dbm_open,			/* Open Database	*/
    dbm_close,			/* Close Database	*/
    dbm_fetch,			/* Fetch Key		*/
    dbm_firstkey,		/* Fetch First Key	*/
    dbm_nextkey,		/* Fetch Next Key	*/
    dbm_delete,			/* Delete Key		*/
    dbm_store,			/* Store Key		*/
    /*
     * The following are #ifdef'd because they have the potential to be
     * macros rather than functions.
     */
#ifdef	dbm_error
    (int (*)()) NULL,		/* Get Database Error	*/
#else	/* dbm_error */
    dbm_error,			/* Get Database Error	*/
#endif	/* dbm_error */
#ifdef	dbm_clearerr
    (int (*)()) NULL,		/* Clear Database Error	*/
#else	/* dbm_clearerr */
    dbm_clearerr,		/* Clear Database Error	*/
#endif	/* dbm_clearerr */
#ifdef	dbm_dirfno
    (int (*)()) NULL,		/* Get DB index FD num	*/
#else	/* dbm_dirfno */
    dbm_dirfno,			/* Get DB index FD num	*/
#endif	/* dbm_dirfno */
#ifdef	dbm_pagfno
    (int (*)()) NULL,		/* Get DB data FD num	*/
#else	/* dbm_pagfno */
    dbm_pagfno,			/* Get DB data FD num	*/
#endif	/* dbm_pagfno */
};
#endif	/* BERK_DB_DBM */

/*
 * These macros dispatch via the dispatch table.
 */
#define	KDBM_OPEN(dbc, db, fl, mo)	((*(((db_context_t *)dbc)->	\
					    db_dispatch->kdb5_dbm_open)) \
					 (db, fl, mo))
#define	KDBM_CLOSE(dbc, db)		((*(((db_context_t *)dbc)->	\
					    db_dispatch->kdb5_dbm_close))(db))
#define	KDBM_FETCH(dbc, db, key)	((*(((db_context_t *)dbc)->	\
					    db_dispatch->kdb5_dbm_fetch)) \
					 (db, key))
#define	KDBM_FIRSTKEY(dbc, db)		((*(((db_context_t *)dbc)->	\
					    db_dispatch->kdb5_dbm_firstkey)) \
					 (db))
#define	KDBM_NEXTKEY(dbc, db)		((*(((db_context_t *)dbc)->	\
					    db_dispatch->kdb5_dbm_nextkey)) \
					 (db))
#define	KDBM_DELETE(dbc, db, key)	((*(((db_context_t *)dbc)->	\
					    db_dispatch->kdb5_dbm_delete)) \
					 (db, key))
#define	KDBM_STORE(dbc, db, key, c, f)	((*(((db_context_t *)dbc)->	\
					    db_dispatch->kdb5_dbm_store)) \
					 (db, key, c, f))
#define	KDBM_ERROR(dbc, db)		((((db_context_t *)dbc)->	 \
					  db_dispatch->kdb5_dbm_error) ? \
					 ((*(((db_context_t *)dbc)->	 \
					     db_dispatch->kdb5_dbm_error)) \
					  (db)) :			 \
					 dbm_error(db))
#define	KDBM_CLEARERR(dbc, db)		((((db_context_t *)dbc)->	 \
					  db_dispatch->kdb5_dbm_clearerr) ? \
					 ((*(((db_context_t *)dbc)->	 \
					     db_dispatch->kdb5_dbm_clearerr)) \
					  (db)) :			 \
					 dbm_clearerr(db))
#define	KDBM_DIRFNO(dbc, db)		((((db_context_t *)dbc)->	 \
					  db_dispatch->kdb5_dbm_dirfno) ? \
					 ((*(((db_context_t *)dbc)->	 \
					     db_dispatch->kdb5_dbm_dirfno)) \
					  (db)) :			 \
					 dbm_dirfno(db))
#define	KDBM_PAGFNO(dbc, db)		((((db_context_t *)dbc)->	 \
					  db_dispatch->kdb5_dbm_pagfno) ? \
					 ((*(((db_context_t *)dbc)->	 \
					     db_dispatch->kdb5_dbm_pagfno)) \
					  (db)) :			 \
					 dbm_pagfno(db))
#define	KDBM_INDEX_EXT(dbc)		(((db_context_t *)dbc)->	 \
					  db_dispatch->kdb5_db_index_ext)
#define	KDBM_DATA_EXT(dbc)		(((db_context_t *)dbc)->	 \
					  db_dispatch->kdb5_db_data_ext)
#define	KDBM_LOCK_EXT(dbc)		(((db_context_t *)dbc)->	 \
					  db_dispatch->kdb5_db_lock_ext)

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
    dbctx->db_dispatch = &kdb5_default_dispatch;
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
	return((char *) NULL);

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
    if ((kret = k5dbm_init_context(context)))
	return(kret);
    db_ctx = context->db_context;

    filename = gen_dbsuffix (db_ctx->db_name, KDBM_LOCK_EXT(db_ctx));
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

    db_ctx = (db_context_t *) context->db_context;
    retval = 0;
    if (k5dbm_inited(context)) {
	if (db_ctx->db_dbm_ctx) {
	    /* dbm_close returns void, but it is possible for there to be an
	       error in close().  Possible changes to this routine: check errno
	       on return from dbm_close(), call fsync on the database file
	       descriptors.  */
	    KDBM_CLOSE(db_ctx, db_ctx->db_dbm_ctx);
	    db_ctx->db_dbm_ctx = (DBM *) NULL;
	}

	if (fclose(db_ctx->db_lf_file) == EOF)
	    retval = errno;
	else
	    retval = 0;
    }
    if (db_ctx) {
	k5dbm_clear_context(db_ctx);
	free(context->db_context);
	context->db_context = (void *) NULL;
    }
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
  if (!(db_ctx->db_dbm_ctx = (DBM *)KDBM_OPEN(db_ctx,
					      db_ctx->db_name, O_RDWR, 0600)))
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
  KDBM_CLOSE(db_ctx, db_ctx->db_dbm_ctx);
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
    if ((kret = k5dbm_init_context(context)))
	return(kret);
    db_ctx = context->db_context;
    if (name == NULL)
	name = default_db_name;
    db = KDBM_OPEN(db_ctx, name, O_RDONLY, 0);
    if (db == NULL)
	return errno;
    KDBM_CLOSE(db_ctx, db);
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
    okname = gen_dbsuffix(db_name ? db_name : ctxname,
			  KDBM_LOCK_EXT(context->db_context));

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

    okname = gen_dbsuffix(db_name, KDBM_LOCK_EXT(context->db_context));
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
    char okpound[BUFSIZ];

    /* strategy:
       create a new "ok" file, set its modify time to "age",
       and move it on top of the old "ok" file.
     */
    sprintf(okpound, "%s#", KDBM_LOCK_EXT(context->db_context));
    new_okname = gen_dbsuffix(db_name, okpound);
    if (!new_okname)
	return ENOMEM;
    okname = gen_dbsuffix(db_name, KDBM_LOCK_EXT(context->db_context));
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

    if ((retval = krb5_dbm_db_get_age(context, NULL, &age2)))
	return retval;
    if (age2 != age || age == -1) {
	return KRB5_KDB_DB_CHANGED;
    }
    return 0;
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
#else
    char *dirname;
    char *pagname;
#endif


    if ((retval = k5dbm_init_context(context)))
	return(retval);
    
#ifndef ODBM
    db = KDBM_OPEN(context->db_context, db_name, O_RDWR|O_CREAT|O_EXCL, 0600);
    if (db == NULL)
	retval = errno;
    else
	KDBM_CLOSE(context->db_context, db);
#else /* OLD DBM */
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
	okname = gen_dbsuffix(db_name, KDBM_LOCK_EXT(context->db_context));
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
	int		nb,fd,i,j;
	char		buf[BUFSIZ];
	char		zbuf[BUFSIZ];
	int		dowrite;

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
	/*
	 * Stroll through the file, reading in BUFSIZ chunks.  If everything
	 * is zero, then we're done for that block, otherwise, zero the block.
	 * We would like to just blast through everything, but some DB
	 * implementations make holey files and writing data to the holes
	 * causes actual blocks to be allocated which is no good, since
	 * we're just about to unlink it anyways.
	 */
	memset(zbuf, 0, BUFSIZ);
	i = 0;
	while (i < statb.st_size) {
		dowrite = 0;
		nb = read(fd, buf, BUFSIZ);
		if (nb < 0) {
			int retval = errno;
			free(filename);
			return retval;
		}
		for (j=0; j<nb; j++) {
		    if (buf[j] != '\0') {
			dowrite = 1;
			break;
		    }
		}
		if (dowrite) {
			lseek(fd, i, SEEK_SET);
			nb = write(fd, zbuf, nb);
			if (nb < 0) {
				int retval = errno;
				free(filename);
				return retval;
			}
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

/*
 * Since the destroy operation happens outside the init/fini bracket, we
 * have some tomfoolery to undergo here.  If we're operating under no
 * database context, then we initialize with the default.  If the caller
 * wishes a different context (e.g. different dispatch table), it's their
 * responsibility to call kdb5_db_set_dbops() before this call.  That will
 * set up the right dispatch table values (e.g. name extensions).
 */
krb5_error_code
krb5_dbm_db_destroy(context, dbname)
    krb5_context context;
	char	*dbname;
{
	krb5_error_code	retval;
	krb5_boolean tmpcontext;

	tmpcontext = 0;
	if (!context->db_context) {
	    tmpcontext = 1;
	    if ((retval = k5dbm_init_context(context)))
		return(retval);
	}
	if (KDBM_DATA_EXT(context->db_context) &&
	    (retval = destroy_file_suffix(dbname, 
					  KDBM_DATA_EXT(context->db_context))))
		return(retval);
	if (KDBM_INDEX_EXT(context->db_context) &&
	    (retval = destroy_file_suffix(dbname, 
					  KDBM_INDEX_EXT(context->db_context))))
		return(retval);
	if ((retval = destroy_file_suffix(dbname,
					 KDBM_LOCK_EXT(context->db_context))))
		return(retval);
	if (tmpcontext) {
	    k5dbm_clear_context((db_context_t *) context->db_context);
	    free(context->db_context);
	    context->db_context = (void *) NULL;
	}
	return(0);
}

/*
 * "Atomically" rename the database in a way that locks out read
 * access in the middle of the rename.
 *
 * Not perfect; if we crash in the middle of an update, we don't
 * necessarily know to complete the transaction the rename, but...
 */
/*
 * Since the rename operation happens outside the init/fini bracket, we
 * have to go through the same stuff that we went through up in db_destroy.
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
    krb5_boolean tmpcontext;

    tmpcontext = 0;
    if (!context->db_context) {
	tmpcontext = 1;
	if ((retval = k5dbm_init_context(context)))
	    return(retval);
    }
    if (KDBM_INDEX_EXT(context->db_context)) {
	fromdir = gen_dbsuffix (from, KDBM_INDEX_EXT(context->db_context));
	todir = gen_dbsuffix (to, KDBM_INDEX_EXT(context->db_context));
	if (!fromdir || !todir) {
	    retval = ENOMEM;
	    goto errout;
	}
    }

    if (KDBM_DATA_EXT(context->db_context)) {
	frompag = gen_dbsuffix (from, KDBM_DATA_EXT(context->db_context));
	topag = gen_dbsuffix (to, KDBM_DATA_EXT(context->db_context));
	if (!frompag || !topag) {
	    retval = ENOMEM;
	    goto errout;
	}
    }
    fromok = gen_dbsuffix(from, KDBM_LOCK_EXT(context->db_context));
    if (!fromok) {
	retval = ENOMEM;
	goto errout;
    }

    if ((retval = krb5_dbm_db_start_update(context, to, &trans)))
	goto errout;
    
    if (((!fromdir && !todir) ||
	 (fromdir && todir && (rename (fromdir, todir) == 0))) &&
	((!frompag && !topag) ||
	 (frompag && topag && (rename (frompag, topag) == 0)))) {
	(void) unlink (fromok);
	retval = 0;
    } else
	retval = errno;
    
errout:
    if (fromok)
	free_dbsuffix (fromok);
    if (topag)
	free_dbsuffix (topag);
    if (frompag)
	free_dbsuffix (frompag);
    if (todir)
	free_dbsuffix (todir);
    if (fromdir)
	free_dbsuffix (fromdir);

    if (retval == 0)
	return krb5_dbm_db_end_update(context, to, trans);

    if (tmpcontext) {
	k5dbm_clear_context((db_context_t *) context->db_context);
	free(context->db_context);
	context->db_context = (void *) NULL;
    }
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
	if ((retval = krb5_dbm_db_start_read(context, &transaction)))
	    return(retval);

	if ((retval = krb5_dbm_db_lock(context, KRB5_DBM_SHARED)))
	    return(retval);

	if (db_ctx->db_dbm_ctx)
	    db = db_ctx->db_dbm_ctx;
	else {
	    db = KDBM_OPEN(db_ctx, db_ctx->db_name, O_RDONLY, 0600);
	    if (db == NULL) {
		retval = errno;
		(void) krb5_dbm_db_unlock(context);
		return retval;
	    }
	}

	*more = FALSE;

	/* XXX deal with wildcard lookups */
	if ((retval = krb5_encode_princ_dbmkey(context, &key, searchfor)))
	    goto cleanup;

	contents = KDBM_FETCH(db_ctx, db, key);
	krb5_free_princ_dbmkey(context, &key);

	if (contents.dptr == NULL)
	    found = 0;
	else if ((retval = krb5_decode_princ_contents(context,
						      &contents,entries)))
	    goto cleanup;
	else found = 1;

	if (db_ctx->db_dbm_ctx == 0)
	    KDBM_CLOSE(db_ctx, db);
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
	KDBM_CLOSE(db_ctx, db);
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
	krb5_dbe_free_contents(context, &entries[i]);
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
    if ((retval = krb5_dbm_db_lock(context, KRB5_DBM_EXCLUSIVE)))
	errout(retval);

    if (db_ctx->db_dbm_ctx)
	db = db_ctx->db_dbm_ctx;
    else {
	db = KDBM_OPEN(db_ctx, db_ctx->db_name, O_RDWR, 0600);
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
	if ((retval = krb5_encode_princ_contents(context, &contents,
						 entries)))
	    break;

	if ((retval = krb5_encode_princ_dbmkey(context, &key,
					       entries->princ))) {
	    krb5_free_princ_contents(context, &contents);
	    break;
	}
	if (KDBM_STORE(db_ctx, db, key, contents, DBM_REPLACE))
	    retval = errno;
	else
	    retval = 0;
	krb5_free_princ_contents(context, &contents);
	krb5_free_princ_dbmkey(context, &key);
	if (retval)
	    break;
	entries++;			/* bump to next struct */
    }

    if (db_ctx->db_dbm_ctx == 0)
	KDBM_CLOSE(db_ctx, db);
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
    krb5_context 	  context;
    krb5_principal 	  searchfor;
    int 		* nentries;	/* how many found & deleted */
{
    krb5_error_code 	  retval;
    krb5_db_entry 	  entry;
    db_context_t 	* db_ctx;
    datum   		  key, contents, contents2;
    DBM    		* db;
    int			  i;

    if (!k5dbm_inited(context))
	return KRB5_KDB_DBNOTINITED;

    db_ctx = (db_context_t *) context->db_context;
    if ((retval = krb5_dbm_db_lock(context, KRB5_DBM_EXCLUSIVE)))
	return(retval);

    if (db_ctx->db_dbm_ctx)
	db = db_ctx->db_dbm_ctx;
    else {
	db = KDBM_OPEN(db_ctx, db_ctx->db_name, O_RDWR, 0600);
	if (db == NULL) {
	    retval = errno;
	    (void) krb5_dbm_db_unlock(context);
	    return retval;
	}
    }

    if ((retval = krb5_encode_princ_dbmkey(context, &key, searchfor)))
	goto cleanup;

    contents = KDBM_FETCH(db_ctx, db, key);
    if (contents.dptr == NULL) {
	retval = KRB5_KDB_NOENTRY;
	*nentries = 0;
    } else {
	memset((char *)&entry, 0, sizeof(entry));
	if ((retval = krb5_decode_princ_contents(context, &contents,
						 &entry)))
	    goto cleankey;
	*nentries = 1;
	/* Clear encrypted key contents */
	for (i = 0; i < entry.n_key_data; i++) {
	    if (entry.key_data[i].key_data_length[0]) {
		memset((char *)entry.key_data[i].key_data_contents[0], 0, 
		       entry.key_data[i].key_data_length[0]); 
	    }
	}
	if ((retval = krb5_encode_princ_contents(context, &contents2,
						 &entry)))
	    goto cleancontents;

	if (KDBM_STORE(db_ctx, db, key, contents2, DBM_REPLACE))
	    retval = errno;
	else {
	    if (KDBM_DELETE(db_ctx, db, key))
		retval = errno;
	    else
		retval = 0;
	}
	krb5_free_princ_contents(context, &contents2);
    cleancontents:
	krb5_dbe_free_contents(context, &entry);
    cleankey:
	krb5_free_princ_dbmkey(context, &key);
    }

 cleanup:
    if (db_ctx->db_dbm_ctx == 0)
	KDBM_CLOSE(db_ctx, db);
    (void) krb5_dbm_db_unlock(context);	/* unlock write lock */
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
    if ((retval = krb5_dbm_db_lock(context, KRB5_DBM_SHARED)))
	return retval;

    if (db_ctx->db_dbm_ctx)
	db = db_ctx->db_dbm_ctx;
    else {
	db = KDBM_OPEN(db_ctx, db_ctx->db_name, O_RDONLY, 0600);
	if (db == NULL) {
	    retval = errno;
	    (void) krb5_dbm_db_unlock(context);
	    return retval;
	}
    }

    for (key = KDBM_FIRSTKEY (db_ctx, db);
	 key.dptr != NULL; key = KDBM_NEXTKEY(db_ctx, db)) {
	contents = KDBM_FETCH (db_ctx, db, key);
	if ((retval = krb5_decode_princ_contents(context, &contents,
						 &entries)))
	    break;
	retval = (*func)(func_arg, &entries);
	krb5_dbe_free_contents(context, &entries);
	if (retval)
	    break;
    }
    if (db_ctx->db_dbm_ctx == 0)
	KDBM_CLOSE(db_ctx, db);
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
    if ((db_ctx = (db_context_t *) context->db_context)) {
	old = db_ctx->db_nb_locks;
	db_ctx->db_nb_locks = mode;
    }
    return old;
}

/*
 * Set dispatch table.
 */
krb5_error_code
kdb5_db_set_dbops(context, new)
    krb5_context	context;
    kdb5_dispatch_table	*new;
{
    krb5_error_code	kret;
    db_context_t	*db_ctx;

    kret = KRB5_KDB_DBINITED;
    if (!k5dbm_inited(context)) {
	if (!(kret = k5dbm_init_context(context))) {
	    db_ctx = (db_context_t *) context->db_context;
	    db_ctx->db_dispatch = (new) ? new : &kdb5_default_dispatch;
	}
    }
    return(kret);
}
