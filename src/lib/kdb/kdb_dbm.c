/*
 * $Source$
 * $Author$ 
 *
 * Copyright 1988,1989,1990 by the Massachusetts Institute of Technology. 
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>. 
 */

#ifndef	lint
static char rcsid_krb_dbm_c[] =
"$Header$";
#endif	lint

#include <krb5/mit-copyright.h>

#ifndef ODBM
#include <ndbm.h>
#else /*ODBM*/
#include <dbm.h>
#endif /*ODBM*/

#include <krb5/krb5.h>
#include <krb5/kdb5.h>

#define KRB5_DB_MAX_RETRY 5

/* exclusive or shared lock flags */
#define	KRB5_DBM_SHARED		0
#define	KRB5_DBM_EXCLUSIVE	1

#ifdef DEBUG
extern int debug;
extern long krb5_dbm_db_debug;
extern char *progname;
#endif

#ifdef __STDC__
#include <stdlib.h>
#else
extern char *malloc();
#endif /* __STDC__ */

static void encode_princ_key PROTOTYPE(());
static void decode_princ_key PROTOTYPE(());
static void encode_princ_contents PROTOTYPE(());
static void decode_princ_contents PROTOTYPE(());
static void krb5_dbm_dbl_fini PROTOTYPE((void));
static int krb5_dbm_dbl_lock PROTOTYPE(());
static void krb5_dbm_dbl_unlock PROTOTYPE(());

extern int errno;

static int init = 0;
static char default_db_name[] = DBM_FILE;
static char *current_db_name = default_db_name;

static krb5_boolean non_blocking = 0;

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
 * KRB5_DB_MAX_RETRY attempts, it gives up.
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

/* Macros to convert ndbm names to dbm names.
 * Note that dbm_nextkey() cannot be simply converted using a macro, since
 * it is invoked giving the database, and nextkey() needs the previous key.
 *
 * Instead, all routines call "dbm_next" instead.
 */

#ifndef ODBM
#define dbm_next(db,key) dbm_nextkey(db)
#else /* OLD DBM */
typedef char DBM;

#define dbm_open(file, flags, mode) ((dbminit(file) == 0)?"":((char *)0))
#define dbm_fetch(db, key) fetch(key)
#define dbm_store(db, key, content, flag) store(key, content)
#define dbm_firstkey(db) firstkey()
#define dbm_next(db,key) nextkey(key)
#define dbm_close(db) dbmclose()
#endif /* OLD DBM */

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
    init = 1;
    return (0);
}

/*
 * gracefully shut down database--must be called by ANY program that does
 * a krb5_dbm_db_init 
 */

krb5_error_code
krb5_dbm_db_fini()
{
    init = 0;
    return (0);
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

    if (name == NULL)
	name = default_db_name;
    db = dbm_open(name, 0, 0);
    if (db == NULL)
	return errno;
    dbm_close(db);
    krb5_dbm_db_l_fini();
    current_db_name = name;
    return 0;
}

/*
 * Return the last modification time of the database.
 */

krb5_error_code
krb5_dbm_db_get_age(db_name, age)
char *db_name;
krb5_timestamp *age;
{
    struct stat st;
    char *okname;
    long age;
    
    okname = gen_dbsuffix(db_name ? db_name : current_db_name, ".ok");

    if (!okname)
	return ENOMEM;
    if (stat (okname, &st) < 0)
	*age = 0;
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
long *age;
{
    char *okname;
    krb5_error_code retval;

    okname = gen_dbsuffix(db_name, ".ok");
    if (!okname)
	return ENOMEM;

    retval = krb5_dbm_db_get_age(db_name, age);
    if (!retval && unlink(okname) < 0) {
	    retval = errno;
    }
    free_dbsuffix (okname);
    return retval;
}

static krb5_error_code
krb5_dbm_db_end_update(db_name, age)
char *db_name;
long age;
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

   If the value of krb5_dbm_db_get_age(NULL) changes while this is going on,
   then the reader has encountered a modified database and should retry.
*/

static krb5_error_code
krb5_dbm_db_start_read(age)
long *age;
{
    return (krb5_dbm_db_get_age(NULL, age));
}

static krb5_error_code
krb5_dbm_db_end_read(age)
long age;
{
    if ((long) krb5_dbm_db_get_age(NULL) != age || age == -1) {
	return KRB5_KDB_DB_CHANGED;
    }
    return 0;
}


/* XXX start here */
static void
encode_princ_key(key, name, instance)
    datum  *key;
    char   *name, *instance;
{
    static char keystring[ANAME_SZ + INST_SZ];

    bzero(keystring, ANAME_SZ + INST_SZ);
    strncpy(keystring, name, ANAME_SZ);
    strncpy(&keystring[ANAME_SZ], instance, INST_SZ);
    key->dptr = keystring;
    key->dsize = ANAME_SZ + INST_SZ;
}

static void
decode_princ_key(key, name, instance)
    datum  *key;
    char   *name, *instance;
{
    strncpy(name, key->dptr, ANAME_SZ);
    strncpy(instance, key->dptr + ANAME_SZ, INST_SZ);
    name[ANAME_SZ - 1] = '\0';
    instance[INST_SZ - 1] = '\0';
}

static void
encode_princ_contents(contents, principal)
    datum  *contents;
    Principal *principal;
{
    contents->dsize = sizeof(*principal);
    contents->dptr = (char *) principal;
}

static void
decode_princ_contents(contents, principal)
    datum  *contents;
    Principal *principal;
{
    bcopy(contents->dptr, (char *) principal, sizeof(*principal));
}


static int dblfd = -1;
static int mylock = 0;
static int inited = 0;

static krb5_dbm_init()
{
    if (!inited) {
	char *filename = gen_dbsuffix (current_db_name, ".ok");
	if ((dblfd = open(filename, 0)) < 0) {
	    fprintf(stderr, "krb5_dbm_init: couldn't open %s\n", filename);
	    fflush(stderr);
	    perror("open");
	    exit(1);
	}
	free(filename);
	inited++;
    }
    return (0);
}

static void
krb5_dbm_fini()
{
    close(dblfd);
    dblfd = -1;
    inited = 0;
    mylock = 0;
}

static int
krb5_dbm_db_lock(mode)
int mode;
{
    int flock_mode;
    
    if (!inited)
	krb5_dbm_init();
    if (mylock) {		/* Detect lock call when lock already
				 * locked */
	fprintf(stderr, "Kerberos locking error (mylock)\n");
	fflush(stderr);
	exit(1);
    }
    switch (mode) {
    case KRB5_DBM_EXCLUSIVE:
	flock_mode = LOCK_EX;
	break;
    case KRB5_DBM_SHARED:
	flock_mode = LOCK_SH;
	break;
    default:
	fprintf(stderr, "invalid lock mode %d\n", mode);
	abort();
    }
    if (non_blocking)
	flock_mode |= LOCK_NB;
    
    if (flock(dblfd, flock_mode) < 0) 
	return errno;
    mylock++;
    return 0;
}

static void
krb5_dbm_db_unlock()
{
    if (!mylock) {		/* lock already unlocked */
	fprintf(stderr, "Kerberos database lock not locked when unlocking.\n");
	fflush(stderr);
	exit(1);
    }
    if (flock(dblfd, LOCK_UN) < 0) {
	fprintf(stderr, "Kerberos database lock error. (unlocking)\n");
	fflush(stderr);
	perror("flock");
	exit(1);
    }
    mylock = 0;
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
#ifdef NDBM
    DBM *db;

    db = dbm_open(db_name, O_RDWR|O_CREAT|O_EXCL, 0600);
    if (db == NULL)
	retval = errno;
    else
	dbm_close(db);
#else
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
#endif
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
    long trans;
    krb5_error_code retval;
    int ok;

    fromdir = gen_dbsuffix (from, ".dir");
    if (!fromdir)
	return ENOMEM;
    todir = gen_dbsuffix (to, ".dir");
    if (!todir) {
	retval = ENOMEM;
	goto freefromdir;
    }
    frompag = gen_dbsuffix (from , ".pag");
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
 * look up a principal in the data base returns number of principals
 * found , and whether there were more than requested. 
 */

krb5_dbm_db_get_principal(name, inst, principal, max, more)
    char   *name;		/* could have wild card */
    char   *inst;		/* could have wild card */
    Principal *principal;
    unsigned int max;		/* max number of name structs to return */
    int    *more;		/* where there more than 'max' tuples? */

{
    int     found = 0, code;
    extern int errorproc();
    int     wildp, wildi;
    datum   key, contents;
    char    testname[ANAME_SZ], testinst[INST_SZ];
    u_long trans;
    int try;
    DBM    *db;

    if (!init)
	krb5_dbm_db_init();		/* initialize database routines */

    for (try = 0; try < KRB5_DB_MAX_RETRY; try++) {
	trans = krb5_dbm_db_start_read();

	if ((code = krb5_dbm_db_lock(KRB5_DBM_SHARED)) != 0)
	    return -1;

	db = dbm_open(current_db_name, O_RDONLY, 0600);

	*more = 0;

#ifdef DEBUG
	if (krb5_dbm_db_debug & 2)
	    fprintf(stderr,
		    "%s: db_get_principal for %s %s max = %d",
		    progname, name, inst, max);
#endif

	wildp = !strcmp(name, "*");
	wildi = !strcmp(inst, "*");

	if (!wildi && !wildp) {	/* nothing's wild */
	    encode_princ_key(&key, name, inst);
	    contents = dbm_fetch(db, key);
	    if (contents.dptr == NULL) {
		found = 0;
		goto done;
	    }
	    decode_princ_contents(&contents, principal);
#ifdef DEBUG
	    if (krb5_dbm_db_debug & 1) {
		fprintf(stderr, "\t found %s %s p_n length %d t_n length %d\n",
			principal->name, principal->instance,
			strlen(principal->name),
			strlen(principal->instance));
	    }
#endif
	    found = 1;
	    goto done;
	}
	/* process wild cards by looping through entire database */

	for (key = dbm_firstkey(db); key.dptr != NULL;
	     key = dbm_next(db, key)) {
	    decode_princ_key(&key, testname, testinst);
	    if ((wildp || !strcmp(testname, name)) &&
		(wildi || !strcmp(testinst, inst))) { /* have a match */
		if (found >= max) {
		    *more = 1;
		    goto done;
		} else {
		    found++;
		    contents = dbm_fetch(db, key);
		    decode_princ_contents(&contents, principal);
#ifdef DEBUG
		    if (krb5_dbm_db_debug & 1) {
			fprintf(stderr,
				"\tfound %s %s p_n length %d t_n length %d\n",
				principal->name, principal->instance,
				strlen(principal->name),
				strlen(principal->instance));
		    }
#endif
		    principal++; /* point to next */
		}
	    }
	}

    done:
	krb5_dbm_db_unlock();	/* unlock read lock */
	dbm_close(db);
	if (krb5_dbm_db_end_read(trans) == 0)
	    break;
	found = -1;
	if (!non_blocking)
	    sleep(1);
    }
    return (found);
}

/*
 * Update a name in the data base.  Returns number of names
 * successfully updated.
 */

krb5_dbm_db_put_principal(principal, max)
    Principal *principal;
    unsigned int max;		/* number of principal structs to
				 * update */

{
    int     found = 0, code;
    u_long  i;
    extern int errorproc();
    datum   key, contents;
    DBM    *db;

    if (!init)
	krb5_dbm_db_init();

    if ((code = krb5_dbm_db_lock(KRB5_DBM_EXCLUSIVE)) != 0)
	return -1;

    db = dbm_open(current_db_name, O_RDWR, 0600);

#ifdef DEBUG
    if (krb5_dbm_db_debug & 2)
	fprintf(stderr, "%s: krb5_dbm_db_put_principal  max = %d",
	    progname, max);
#endif

    /* for each one, stuff temps, and do replace/append */
    for (i = 0; i < max; i++) {
	encode_princ_contents(&contents, principal);
	encode_princ_key(&key, principal->name, principal->instance);
	dbm_store(db, key, contents, DBM_REPLACE);
#ifdef DEBUG
	if (krb5_dbm_db_debug & 1) {
	    fprintf(stderr, "\n put %s %s\n",
		principal->name, principal->instance);
	}
#endif
	found++;
	principal++;		/* bump to next struct			   */
    }

    dbm_close(db);
    krb5_dbm_db_unlock();		/* unlock database */
    return (found);
}
/*
 * look up a dba in the data base returns number of dbas found , and
 * whether there were more than requested. 
 */

krb5_dbm_db_get_dba(dba_name, dba_inst, dba, max, more)
    char   *dba_name;		/* could have wild card */
    char   *dba_inst;		/* could have wild card */
    Dba    *dba;
    unsigned int max;		/* max number of name structs to return */
    int    *more;		/* where there more than 'max' tuples? */

{
    *more = 0;
    return (0);
}

krb5_error_code
krb5_dbm_db_iterate (func, arg)
krb5_error_code (*func) PROTOTYPE((krb5_pointer, krb5_kdb_principal *));
krb5_pointer arg;
{
    datum key, contents;
    Principal *principal;
    krb5_error_code retval;
    DBM *db;
    
    if (retval = krb5_dbm_db_init())	/* initialize and open the database */
	return(retval);

    if ((retval = krb5_dbm_db_lock(KRB5_DBM_SHARED)) != 0)
	return retval;

    db = dbm_open(current_db_name, O_RDONLY, 0600);

    for (key = dbm_firstkey (db); key.dptr != NULL; key = dbm_next(db, key)) {
	contents = dbm_fetch (db, key);
	/* XXX may not be properly aligned */
	principal = (Principal *) contents.dptr;
	if ((retval = (*func)(arg, principal)) != 0)
	    return retval;
    }
    dbm_close(db);
    krb5_dbm_db_unlock();
    return 0;
}

krb5_boolean
krb5_dbm_db_set_lockmode(mode)
    krb5_boolean mode;
{
    krb5_boolean old = non_blocking;
    non_blocking = mode;
    return old;
}
