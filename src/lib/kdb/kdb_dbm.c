/*
 * $Source$
 * $Author$ 
 *
 * Copyright 1988,1989,1990 by the Massachusetts Institute of Technology. 
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>. 
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_krb_dbm_c[] =
"$Id$";
#endif	/* lint */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/dbm.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/ext-proto.h>
#include <krb5/sysincl.h>

#define KRB5_DBM_MAX_RETRY 5

/* exclusive or shared lock flags */
#define	KRB5_DBM_SHARED		0
#define	KRB5_DBM_EXCLUSIVE	1

#ifdef DEBUG
extern int debug;
extern long krb5_dbm_db_debug;
extern char *progname;
#endif


extern int errno;

static int dblfd = -1;
static int mylock = 0;
static int lockmode = 0;
static int inited = 0;

static char default_db_name[] = DEFAULT_DBM_FILE;
static char *current_db_name = default_db_name;

static krb5_boolean non_blocking = FALSE;

static char *gen_dbsuffix PROTOTYPE((char *, char * ));
static krb5_error_code krb5_dbm_db_start_update PROTOTYPE((char *,
							   time_t * ));
static krb5_error_code krb5_dbm_db_end_update PROTOTYPE((char *,
							 time_t ));
static krb5_error_code krb5_dbm_db_start_read PROTOTYPE((time_t * ));
static krb5_error_code krb5_dbm_db_end_read PROTOTYPE((time_t  ));
static krb5_error_code encode_princ_dbmkey PROTOTYPE((datum *,
						      krb5_principal ));
static void free_encode_princ_dbmkey PROTOTYPE((datum * ));
static krb5_error_code encode_princ_contents
    PROTOTYPE((datum *,
	       krb5_db_entry * ));
static void free_encode_princ_contents PROTOTYPE((datum * ));
static krb5_error_code decode_princ_contents
    PROTOTYPE((datum *,
	       krb5_db_entry * ));
static void free_decode_princ_contents PROTOTYPE((krb5_db_entry * ));

#if 0
/* not used */
static krb5_error_code decode_princ_dbmkey PROTOTYPE((datum *,
						      krb5_principal * ));
static void free_decode_princ_dbmkey PROTOTYPE((krb5_principal ));
#endif

/*
 * This module contains all of the code which directly interfaces to
 * the underlying representation of the Kerberos database; this
 * implementation uses a DBM or NDBM indexed "file" (actually
 * implemented as two separate files) to store the relations, plus a
 * third file as a semaphore to allow the database to be replaced out
 * from underneath the KDC server.
 */

/*
 * Locking:
 * 
 * There are two distinct locking protocols used.  One is designed to
 * lock against processes (the admin_server, for one) which make
 * incremental changes to the database; the other is designed to lock
 * against utilities (kdb_util, kpropd) which replace the entire
 * database in one fell swoop.
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
krb5_dbm_db_init()
{
    if (!inited) {
	char *filename = gen_dbsuffix (current_db_name, ".ok");
	if (!filename)
	    return ENOMEM;
	if ((dblfd = open(filename, 0, 0)) < 0) {
	    return errno;
	}
	free(filename);
	inited++;
    }
    return (0);
}
/*
 * gracefully shut down database--must be called by ANY program that does
 * a krb5_dbm_db_init 
 */


krb5_error_code
krb5_dbm_db_fini()
{
    krb5_error_code retval;

    if (!inited)
	return KRB5_KDB_DBNOTINITED;
    if (close(dblfd) == -1)
	retval = errno;
    else
	retval = 0;
    dblfd = -1;
    inited = 0;
    mylock = 0;
    return retval;
}

/*
 * Set the "name" of the current database to some alternate value.
 *
 * Passing a null pointer as "name" will set back to the default.
 * If the alternate database doesn't exist, nothing is changed.
 */

krb5_error_code
krb5_dbm_db_set_name(name)
char *name;
{
    DBM *db;

    if (inited)
	return KRB5_KDB_DBINITED;
    if (name == NULL)
	name = default_db_name;
    db = dbm_open(name, 0, 0);
    if (db == NULL)
	return errno;
    dbm_close(db);
    current_db_name = name;
    return 0;
}

/*
 * Return the last modification time of the database.
 */

krb5_error_code
krb5_dbm_db_get_age(db_name, age)
char *db_name;
time_t *age;
{
    struct stat st;
    char *okname;
    
    okname = gen_dbsuffix(db_name ? db_name : current_db_name, ".ok");

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
krb5_dbm_db_start_update(db_name, age)
char *db_name;
time_t *age;
{
    char *okname;
    krb5_error_code retval;

    okname = gen_dbsuffix(db_name, ".ok");
    if (!okname)
	return ENOMEM;

    retval = krb5_dbm_db_get_age(db_name, age);
    if (!retval && unlink(okname) < 0) {
	if (errno != ENOENT)
	    retval = errno;
    }
    free_dbsuffix (okname);
    return retval;
}

static krb5_error_code
krb5_dbm_db_end_update(db_name, age)
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
	struct timeval tv[2];
	/* only set the time if the new file is "newer" than
	   "age" */
	if ((fstat (fd, &st) == 0) && (st.st_mtime <= age)) {
	    tv[0].tv_sec = st.st_atime;
	    tv[0].tv_usec = 0;
	    tv[1].tv_sec = age;		/* mod time */
	    tv[1].tv_usec = 0;
	    /* set the mod timetimes.. */
	    utimes (new_okname, tv);
	    fsync(fd);
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

   If the value of krb5_dbm_db_get_age(NULL, age) changes while this is
   going on,
   then the reader has encountered a modified database and should retry.
*/

static krb5_error_code
krb5_dbm_db_start_read(age)
time_t *age;
{
    return (krb5_dbm_db_get_age(NULL, age));
}

static krb5_error_code
krb5_dbm_db_end_read(age)
time_t age;
{
    time_t age2;
    krb5_error_code retval;

    if (retval = krb5_dbm_db_get_age(NULL, &age2))
	return retval;
    if (age2 != age || age == -1) {
	return KRB5_KDB_DB_CHANGED;
    }
    return 0;
}


static krb5_error_code
encode_princ_dbmkey(key, principal)
datum  *key;
krb5_principal principal;
{
    char *princ_name;
    krb5_error_code retval;

    if (retval = krb5_unparse_name(principal, &princ_name))
	return(retval);
    key->dptr = princ_name;
    key->dsize = strlen(princ_name)+1;	/* need to store the NULL for
					   decoding */
    return 0;
}

static void
free_encode_princ_dbmkey(key)
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
decode_princ_dbmkey(key, principal)
datum  *key;
krb5_principal *principal;
{
    return(krb5_parse_name(key->dptr, principal));
}

static void
free_decode_princ_dbmkey(principal)
krb5_principal principal;
{
    krb5_free_principal(principal);
    return;
}
#endif

static krb5_error_code
encode_princ_contents(contents, entry)
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
       then the unparsed mod_princ name.
       */
    copy_princ = *entry;
    copy_princ.principal = 0;
    copy_princ.mod_name = 0;

    if (retval = krb5_unparse_name(entry->principal, &unparse_princ))
	return(retval);
    if (retval = krb5_unparse_name(entry->mod_name, &unparse_mod_princ)) {
	free(unparse_princ);
	return(retval);
    }
    princ_size = strlen(unparse_princ)+1;
    mod_size = strlen(unparse_mod_princ)+1;
    contents->dsize = sizeof(copy_princ)+ princ_size + mod_size
		      + entry->key.length;
    contents->dptr = malloc(contents->dsize);
    if (!contents->dptr) {
	free(unparse_princ);
	free(unparse_mod_princ);
	contents->dsize = 0;
	contents->dptr = 0;
	return(ENOMEM);
    }
    (void) memcpy(contents->dptr, (char *)&copy_princ, sizeof(copy_princ));
    nextloc = contents->dptr + sizeof(copy_princ);

    (void) memcpy(nextloc, unparse_princ, princ_size);
    nextloc += princ_size;
    (void) memcpy(nextloc, unparse_mod_princ, mod_size);
    nextloc += mod_size;
    (void) memcpy(nextloc, (char *)entry->key.contents, entry->key.length);
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
decode_princ_contents(contents, entry)
datum  *contents;
krb5_db_entry *entry;
{
    register char *nextloc;
    krb5_principal princ, mod_princ;
    krb5_error_code retval;
    int keysize;

    /* undo the effects of encode_princ_contents.
     */

    nextloc = contents->dptr + sizeof(*entry);
    if (nextloc >= contents->dptr + contents->dsize)
	return KRB5_KDB_TRUNCATED_RECORD;

    memcpy((char *) entry, contents->dptr, sizeof(*entry));

    if (nextloc + strlen(nextloc)+1 >= contents->dptr + contents->dsize)
	return KRB5_KDB_TRUNCATED_RECORD;

    if (retval = krb5_parse_name(nextloc, &princ))
	return(retval);
    entry->principal = princ;

    nextloc += strlen(nextloc)+1;	/* advance past 1st string */
    if ((nextloc + strlen(nextloc)+1 >= contents->dptr + contents->dsize)
	|| (retval = krb5_parse_name(nextloc, &mod_princ))) {
	krb5_free_principal(princ);
	(void) memset((char *) entry, 0, sizeof(*entry));
	return KRB5_KDB_TRUNCATED_RECORD;
    }
    entry->mod_name = mod_princ;
    nextloc += strlen(nextloc)+1;	/* advance past 2nd string */
    keysize = contents->dsize - (nextloc - contents->dptr);
    if (keysize <= 0) {
	krb5_free_principal(princ);
	krb5_free_principal(mod_princ);
	(void) memset((char *) entry, 0, sizeof(*entry));
	return KRB5_KDB_TRUNCATED_RECORD;
    }
    if (!(entry->key.contents = (unsigned char *)malloc(keysize))) {
	krb5_free_principal(princ);
	krb5_free_principal(mod_princ);
	(void) memset((char *) entry, 0, sizeof(*entry));
	return ENOMEM;
    }
    (void) memcpy((char *)entry->key.contents, nextloc, keysize);
    if (keysize != entry->key.length) {
	krb5_free_principal(princ);
	krb5_free_principal(mod_princ);
	free((char *)entry->key.contents);
	(void) memset((char *) entry, 0, sizeof(*entry));
	return KRB5_KDB_TRUNCATED_RECORD;
    }	
    return 0;
}

static void
free_decode_princ_contents(entry)
krb5_db_entry *entry;
{
    /* erase the key */
    memset((char *)entry->key.contents, 0, entry->key.length);
    free((char *)entry->key.contents);

    krb5_free_principal(entry->principal);
    krb5_free_principal(entry->mod_name);
    (void) memset((char *)entry, 0, sizeof(*entry));
    return;
}

krb5_error_code
krb5_dbm_db_lock(mode)
int mode;
{
    int flock_mode;

    if (mylock && (lockmode >= mode)) {
	    mylock++;		/* No need to upgrade lock, just return */
	    return(0);
    }

    switch (mode) {
    case KRB5_DBM_EXCLUSIVE:
	flock_mode = LOCK_EX;
	break;
    case KRB5_DBM_SHARED:
	flock_mode = LOCK_SH;
	break;
    default:
	return KRB5_KDB_BADLOCKMODE;
    }
    lockmode = mode;
    if (non_blocking)
	flock_mode |= LOCK_NB;
    
    if (flock(dblfd, flock_mode) < 0) 
	return errno;
    mylock++;
    return 0;
}

krb5_error_code
krb5_dbm_db_unlock()
{
    if (!mylock)		/* lock already unlocked */
	return KRB5_KDB_NOTLOCKED;

    if (--mylock == 0) {
	    if (flock(dblfd, LOCK_UN) < 0)
		    return errno;
    }
    return 0;
}

/*
 * Create the database, assuming it's not there.
 */

krb5_error_code
krb5_dbm_db_create(db_name)
char *db_name;
{
    char *okname;
    int fd;
    register krb5_error_code retval = 0;
#ifndef ODBM
    DBM *db;

    db = dbm_open(db_name, O_RDWR|O_CREAT|O_EXCL, 0600);
    if (db == NULL)
	retval = errno;
    else
	dbm_close(db);
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
 * "Atomically" rename the database in a way that locks out read
 * access in the middle of the rename.
 *
 * Not perfect; if we crash in the middle of an update, we don't
 * necessarily know to complete the transaction the rename, but...
 */

krb5_error_code
krb5_dbm_db_rename(from, to)
    char *from;
    char *to;
{
    char *fromdir;
    char *todir;
    char *frompag;
    char *topag;
    char *fromok;
    time_t trans;
    krb5_error_code retval;

    fromdir = gen_dbsuffix (from, ".dir");
    if (!fromdir)
	return ENOMEM;
    todir = gen_dbsuffix (to, ".dir");
    if (!todir) {
	retval = ENOMEM;
	goto freefromdir;
    }
    frompag = gen_dbsuffix (from, ".pag");
    if (!frompag) {
	retval = ENOMEM;
	goto freetodir;
    }
    topag = gen_dbsuffix (to, ".pag");
    if (!topag) {
	retval = ENOMEM;
	goto freefrompag;
    }
    fromok = gen_dbsuffix(from, ".ok");
    if (!fromok) {
	retval = ENOMEM;
	goto freetopag;
    }

    if (retval = krb5_dbm_db_start_update(to, &trans))
	return(retval);
    
    if ((rename (fromdir, todir) == 0)
	&& (rename (frompag, topag) == 0)) {
	(void) unlink (fromok);
	retval = 0;
    } else
	retval = errno;
    
    free_dbsuffix (fromok);
 freetopag:
    free_dbsuffix (topag);
 freefrompag:
    free_dbsuffix (frompag);
 freetodir:
    free_dbsuffix (todir);
 freefromdir:
    free_dbsuffix (fromdir);

    if (retval == 0)
	return krb5_dbm_db_end_update(to, trans);
    else
	return retval;
}

/*
 * look up a principal in the data base.
 * returns number of entries found, and whether there were
 * more than requested. 
 */

krb5_error_code
krb5_dbm_db_get_principal(searchfor, entries, nentries, more)
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

    if (!inited)
	return KRB5_KDB_DBNOTINITED;

    for (try = 0; try < KRB5_DBM_MAX_RETRY; try++) {
	if (retval = krb5_dbm_db_start_read(&transaction))
	    return(retval);

	if (retval = krb5_dbm_db_lock(KRB5_DBM_SHARED))
	    return(retval);

	db = dbm_open(current_db_name, O_RDONLY, 0600);
	if (db == NULL) {
	    retval = errno;
	    (void) krb5_dbm_db_unlock();
	    return retval;
	}
	*more = FALSE;

	/* XXX deal with wildcard lookups */
	if (retval = encode_princ_dbmkey(&key, searchfor))
	    goto cleanup;

	contents = dbm_fetch(db, key);
	free_encode_princ_dbmkey(&key);

	if (contents.dptr == NULL)
	    found = 0;
	else if (retval = decode_princ_contents(&contents, entries))
	    goto cleanup;
	else found = 1;

	(void) dbm_close(db);
	(void) krb5_dbm_db_unlock();	/* unlock read lock */
	if (krb5_dbm_db_end_read(transaction) == 0)
	    break;
	found = -1;
	if (!non_blocking)
	    sleep(1);
    }
    if (found == -1) {
	*nentries = 0;
	return KRB5_KDB_DB_INUSE;
    }
    *nentries = found;
    return(0);

 cleanup:
    (void) dbm_close(db);
    (void) krb5_dbm_db_unlock();	/* unlock read lock */
    return retval;
}

/*
  Free stuff returned by krb5_dbm_db_get_principal.
 */
void
krb5_dbm_db_free_principal(entries, nentries)
krb5_db_entry *entries;
int nentries;
{
    register int i;
    for (i = 0; i < nentries; i++)
	free_decode_princ_contents(&entries[i]);
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
krb5_dbm_db_put_principal(entries, nentries)
krb5_db_entry *entries;
register int *nentries;			/* number of entry structs to
					 * update */

{
    register int i;
    datum   key, contents;
    DBM    *db;
    krb5_error_code retval;

#define errout(code) { *nentries = 0; return code; }

    if (!inited)
	errout(KRB5_KDB_DBNOTINITED);

    if (retval = krb5_dbm_db_lock(KRB5_DBM_EXCLUSIVE))
	errout(retval);

    db = dbm_open(current_db_name, O_RDWR, 0600);

    if (db == NULL) {
	retval = errno;
	(void) krb5_dbm_db_unlock();
	errout(errno);
    }

#undef errout

    /* for each one, stuff temps, and do replace/append */
    for (i = 0; i < *nentries; i++) {
	if (retval = encode_princ_contents(&contents, entries))
	    break;

	if (retval = encode_princ_dbmkey(&key, entries->principal)) {
	    free_encode_princ_contents(&contents);
	    break;
	}
	if (dbm_store(db, key, contents, DBM_REPLACE))
	    retval = errno;
	else
	    retval = 0;
	free_encode_princ_contents(&contents);
	free_encode_princ_dbmkey(&key);
	if (retval)
	    break;
	entries++;			/* bump to next struct */
    }

    (void) dbm_close(db);
    (void) krb5_dbm_db_unlock();		/* unlock database */
    *nentries = i;
    return (retval);
}

/*
 * delete a principal from the data base.
 * returns number of entries removed
 */

krb5_error_code
krb5_dbm_db_delete_principal(searchfor, nentries)
krb5_principal searchfor;
int *nentries;				/* how many found & deleted */
{
    int     found = 0;
    datum   key, contents, contents2;
    krb5_db_entry entry;
    DBM    *db;
    krb5_error_code retval;

    if (!inited)
	return KRB5_KDB_DBNOTINITED;

    if (retval = krb5_dbm_db_lock(KRB5_DBM_EXCLUSIVE))
	return(retval);

    db = dbm_open(current_db_name, O_RDWR, 0600);
    if (db == NULL) {
	retval = errno;
	(void) krb5_dbm_db_unlock();
	return retval;
    }
    if (retval = encode_princ_dbmkey(&key, searchfor))
	goto cleanup;

    contents = dbm_fetch(db, key);
    if (contents.dptr == NULL) {
	found = 0;
	retval = KRB5_KDB_NOENTRY;
    } else {
	if (retval = decode_princ_contents(&contents, &entry))
	    goto cleankey;
	found = 1;
	memset((char *)entry.key.contents, 0, entry.key.length);
	if (retval = encode_princ_contents(&contents2, &entry))
	    goto cleancontents;

	if (dbm_store(db, key, contents2, DBM_REPLACE))
	    retval = errno;
	else {
	    if (dbm_delete(db, key))
		retval = errno;
	    else
		retval = 0;
	}
	free_encode_princ_contents(&contents2);
    cleancontents:
	free_decode_princ_contents(&entry);
    cleankey:
	free_encode_princ_dbmkey(&key);
    }

 cleanup:
    (void) dbm_close(db);
    (void) krb5_dbm_db_unlock();	/* unlock write lock */
    *nentries = found;
    return retval;
}

krb5_error_code
krb5_dbm_db_iterate (func, func_arg)
krb5_error_code (*func) PROTOTYPE((krb5_pointer, krb5_db_entry *));
krb5_pointer func_arg;
{
    datum key, contents;
    krb5_db_entry entries;
    krb5_error_code retval;
    DBM *db;
    
    if (!inited)
	return KRB5_KDB_DBNOTINITED;

    if (retval = krb5_dbm_db_lock(KRB5_DBM_SHARED))
	return retval;

    db = dbm_open(current_db_name, O_RDONLY, 0600);

    if (db == NULL) {
	retval = errno;
	(void) krb5_dbm_db_unlock();
	return retval;
    }

    for (key = dbm_firstkey (db); key.dptr != NULL; key = dbm_next(db, key)) {
	contents = dbm_fetch (db, key);
	if (retval = decode_princ_contents(&contents, &entries))
	    break;
	retval = (*func)(func_arg, &entries);
	free_decode_princ_contents(&entries);
	if (retval)
	    break;
    }
    (void) dbm_close(db);
    (void) krb5_dbm_db_unlock();
    return retval;
}

krb5_boolean
krb5_dbm_db_set_lockmode(mode)
    krb5_boolean mode;
{
    krb5_boolean old = non_blocking;
    non_blocking = mode;
    return old;
}
