/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/kdb/kdb_db2.c
 *
 * Copyright 1997,2006,2007-2009 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <db.h>
#include <stdio.h>
#include <errno.h>
#include <utime.h>
#include "kdb5.h"
#include "kdb_db2.h"
#include "kdb_xdr.h"
#include "policy_db.h"

#define KDB_DB2_DATABASE_NAME "database_name"

static krb5_error_code krb5_db2_start_update(krb5_context);
static krb5_error_code krb5_db2_end_update(krb5_context);

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
#define k5db2_inited(c) (c->dal_handle->db_context                   \
                         && ((krb5_db2_context *) c->dal_handle->db_context)->db_inited)

static krb5_error_code
krb5_db2_get_db_opt(char *input, char **opt, char **val)
{
    char   *pos = strchr(input, '=');
    if (pos == NULL) {
        *opt = NULL;
        *val = strdup(input);
        if (*val == NULL) {
            return ENOMEM;
        }
    } else {
        *opt = malloc((pos - input) + 1);
        *val = strdup(pos + 1);
        if (!*opt || !*val) {
            free(*opt);
            *opt = NULL;
            free(*val);
            *val = NULL;
            return ENOMEM;
        }
        memcpy(*opt, input, pos - input);
        (*opt)[pos - input] = '\0';
    }
    return (0);

}

/*
 * Restore the default context.
 */
static void
k5db2_clear_context(krb5_db2_context *dbctx)
{
    /*
     * Free any dynamically allocated memory.  File descriptors and locks
     * are the caller's problem.
     */
    free(dbctx->db_lf_name);
    free(dbctx->db_name);
    /*
     * Clear the structure and reset the defaults.
     */
    memset(dbctx, 0, sizeof(krb5_db2_context));
    dbctx->db_name = NULL;
    dbctx->db_nb_locks = FALSE;
    dbctx->tempdb = FALSE;
}

static krb5_error_code
k5db2_init_context(krb5_context context)
{
    krb5_db2_context *db_ctx;
    kdb5_dal_handle *dal_handle;

    dal_handle = context->dal_handle;

    if (dal_handle->db_context == NULL) {
        db_ctx = (krb5_db2_context *) malloc(sizeof(krb5_db2_context));
        if (db_ctx == NULL)
            return ENOMEM;
        else {
            memset(db_ctx, 0, sizeof(krb5_db2_context));
            k5db2_clear_context((krb5_db2_context *) db_ctx);
            dal_handle->db_context = (void *) db_ctx;
        }
    }
    return (0);
}

/* Using db_args and the profile, initialize the configurable parameters of the
 * DB context inside context. */
static krb5_error_code
configure_context(krb5_context context, char *conf_section, char **db_args)
{
    krb5_error_code status;
    krb5_db2_context *db_ctx;
    char **t_ptr, *opt = NULL, *val = NULL, *pval = NULL;
    profile_t profile = KRB5_DB_GET_PROFILE(context);
    int bval;

    status = k5db2_init_context(context);
    if (status != 0)
        return status;
    db_ctx = context->dal_handle->db_context;

    for (t_ptr = db_args; t_ptr && *t_ptr; t_ptr++) {
        free(opt);
        free(val);
        status = krb5_db2_get_db_opt(*t_ptr, &opt, &val);
        if (opt && !strcmp(opt, "dbname")) {
            db_ctx->db_name = strdup(val);
            if (db_ctx->db_name == NULL) {
                status = ENOMEM;
                goto cleanup;
            }
        }
        else if (!opt && !strcmp(val, "temporary")) {
            db_ctx->tempdb = 1;
        } else if (!opt && !strcmp(val, "merge_nra")) {
            ;
        } else if (opt && !strcmp(opt, "hash")) {
            db_ctx->hashfirst = TRUE;
        } else {
            status = EINVAL;
            krb5_set_error_message(context, status,
                                   "Unsupported argument \"%s\" for db2",
                                   opt ? opt : val);
            goto cleanup;
        }
    }

    if (db_ctx->db_name == NULL) {
        /* Check for database_name in the db_module section. */
        status = profile_get_string(profile, KDB_MODULE_SECTION, conf_section,
                                    KDB_DB2_DATABASE_NAME, NULL, &pval);
        if (status == 0 && pval == NULL) {
            /* For compatibility, check for database_name in the realm. */
            status = profile_get_string(profile, KDB_REALM_SECTION,
                                        KRB5_DB_GET_REALM(context),
                                        KDB_DB2_DATABASE_NAME,
                                        DEFAULT_KDB_FILE, &pval);
        }
        if (status != 0)
            goto cleanup;
        db_ctx->db_name = strdup(pval);
    }

    status = profile_get_boolean(profile, KDB_MODULE_SECTION, conf_section,
                                 KRB5_CONF_DISABLE_LAST_SUCCESS, FALSE, &bval);
    if (status != 0)
        goto cleanup;
    db_ctx->disable_last_success = bval;

    status = profile_get_boolean(profile, KDB_MODULE_SECTION, conf_section,
                                 KRB5_CONF_DISABLE_LOCKOUT, FALSE, &bval);
    if (status != 0)
        goto cleanup;
    db_ctx->disable_lockout = bval;

cleanup:
    free(opt);
    free(val);
    profile_release_string(pval);
    return status;
}

/*
 * Utility routine: generate name of database file.
 */

static char *
gen_dbsuffix(char *db_name, char *sfx)
{
    char   *dbsuffix;

    if (sfx == NULL)
        return ((char *) NULL);

    if (asprintf(&dbsuffix, "%s%s", db_name, sfx) < 0)
        return (0);
    return dbsuffix;
}

static DB *
k5db2_dbopen(krb5_db2_context *dbc, char *fname, int flags, int mode, int tempdb)
{
    DB     *db;
    BTREEINFO bti;
    HASHINFO hashi;
    bti.flags = 0;
    bti.cachesize = 0;
    bti.psize = 4096;
    bti.lorder = 0;
    bti.minkeypage = 0;
    bti.compare = NULL;
    bti.prefix = NULL;

    if (tempdb) {
        fname = gen_dbsuffix(fname, "~");
    } else {
        fname = strdup(fname);
    }
    if (fname == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }


    hashi.bsize = 4096;
    hashi.cachesize = 0;
    hashi.ffactor = 40;
    hashi.hash = NULL;
    hashi.lorder = 0;
    hashi.nelem = 1;

    db = dbopen(fname, flags, mode,
                dbc->hashfirst ? DB_HASH : DB_BTREE,
                dbc->hashfirst ? (void *) &hashi : (void *) &bti);
    if (db != NULL) {
        free(fname);
        return db;
    }
    switch (errno) {
#ifdef EFTYPE
    case EFTYPE:
#endif
    case EINVAL:
        db = dbopen(fname, flags, mode,
                    dbc->hashfirst ? DB_BTREE : DB_HASH,
                    dbc->hashfirst ? (void *) &bti : (void *) &hashi);
        if (db != NULL)
            dbc->hashfirst = !dbc->hashfirst;
    default:
        free(fname);
        return db;
    }
}

/*
 * initialization for data base routines.
 */

krb5_error_code
krb5_db2_init(krb5_context context)
{
    char   *filename = NULL;
    krb5_db2_context *db_ctx;
    krb5_error_code retval;
    char    policy_db_name[1024], policy_lock_name[1024];

    if (k5db2_inited(context))
        return 0;

    /* Check for presence of our context, if not present, allocate one. */
    if ((retval = k5db2_init_context(context)))
        return (retval);

    db_ctx = context->dal_handle->db_context;
    db_ctx->db = NULL;

    if (!(filename = gen_dbsuffix(db_ctx->db_name, db_ctx->tempdb
                                  ?KDB2_TEMP_LOCK_EXT:KDB2_LOCK_EXT)))
        return ENOMEM;
    db_ctx->db_lf_name = filename;      /* so it gets freed by clear_context */

    /*
     * should be opened read/write so that write locking can work with
     * POSIX systems
     */
    if ((db_ctx->db_lf_file = open(filename, O_RDWR, 0666)) < 0) {
        if ((db_ctx->db_lf_file = open(filename, O_RDONLY, 0666)) < 0) {
            retval = errno;
            goto err_out;
        }
    }
    set_cloexec_fd(db_ctx->db_lf_file);
    db_ctx->db_inited++;

    if ((retval = krb5_db2_get_age(context, NULL, &db_ctx->db_lf_time)))
        goto err_out;

    snprintf(policy_db_name, sizeof(policy_db_name), "%s%s.kadm5",
             db_ctx->db_name, db_ctx->tempdb ? "~" : "");
    snprintf(policy_lock_name, sizeof(policy_lock_name),
             "%s.lock", policy_db_name);

    if ((retval = osa_adb_init_db(&db_ctx->policy_db, policy_db_name,
                                  policy_lock_name, OSA_ADB_POLICY_DB_MAGIC)))
    {
        goto err_out;
    }
    return 0;

err_out:
    db_ctx->db = NULL;
    k5db2_clear_context(db_ctx);
    return (retval);
}

/*
 * gracefully shut down database--must be called by ANY program that does
 * a krb5_db2_init
 */
krb5_error_code
krb5_db2_fini(krb5_context context)
{
    krb5_error_code retval = 0;
    krb5_db2_context *db_ctx;

    db_ctx = context->dal_handle->db_context;
    if (k5db2_inited(context)) {
        if (close(db_ctx->db_lf_file))
            retval = errno;
        else
            retval = 0;
    }
    if (db_ctx) {
        if (db_ctx->policy_db) {
            retval =
                osa_adb_fini_db(db_ctx->policy_db, OSA_ADB_POLICY_DB_MAGIC);
            if (retval)
                return retval;
        }

        k5db2_clear_context(db_ctx);
        free(context->dal_handle->db_context);
        context->dal_handle->db_context = NULL;
    }
    return retval;
}



/* Return successfully if the db2 name set in context can be opened. */
static krb5_error_code
check_openable(krb5_context context)
{
    DB     *db;
    krb5_db2_context *db_ctx;

    db_ctx = context->dal_handle->db_context;
    db = k5db2_dbopen(db_ctx, db_ctx->db_name, O_RDONLY, 0, db_ctx->tempdb);
    if (db == NULL)
        return errno;
    (*db->close) (db);
    return 0;
}

/*
 * Return the last modification time of the database.
 *
 * Think about using fstat.
 */

krb5_error_code
krb5_db2_get_age(krb5_context context, char *db_name, time_t *age)
{
    krb5_db2_context *db_ctx;
    struct stat st;

    if (!k5db2_inited(context))
        return (KRB5_KDB_DBNOTINITED);
    db_ctx = context->dal_handle->db_context;

    if (fstat(db_ctx->db_lf_file, &st) < 0)
        *age = -1;
    else
        *age = st.st_mtime;
    return 0;
}

/*
 * Remove the semaphore file; indicates that database is currently
 * under renovation.
 *
 * This is only for use when moving the database out from underneath
 * the server (for example, during slave updates).
 */

static krb5_error_code
krb5_db2_start_update(krb5_context context)
{
    return 0;
}

static krb5_error_code
krb5_db2_end_update(krb5_context context)
{
    krb5_error_code retval;
    krb5_db2_context *db_ctx;
    struct stat st;
    time_t  now;
    struct utimbuf utbuf;

    if (!k5db2_inited(context))
        return (KRB5_KDB_DBNOTINITED);

    retval = 0;
    db_ctx = context->dal_handle->db_context;
    now = time((time_t *) NULL);
    if (fstat(db_ctx->db_lf_file, &st) == 0) {
        if (st.st_mtime >= now) {
            utbuf.actime = st.st_mtime + 1;
            utbuf.modtime = st.st_mtime + 1;
            if (utime(db_ctx->db_lf_name, &utbuf))
                retval = errno;
        } else {
            if (utime(db_ctx->db_lf_name, (struct utimbuf *) NULL))
                retval = errno;
        }
    } else
        retval = errno;
    if (!retval) {
        if (fstat(db_ctx->db_lf_file, &st) == 0)
            db_ctx->db_lf_time = st.st_mtime;
        else
            retval = errno;
    }
    return (retval);
}

#define MAX_LOCK_TRIES 5

krb5_error_code
krb5_db2_lock(krb5_context context, int in_mode)
{
    krb5_db2_context *db_ctx;
    int     krb5_lock_mode;
    DB     *db;
    krb5_error_code retval;
    time_t  mod_time;
    int     mode, gotlock, tries;

    switch (in_mode) {
    case KRB5_DB_LOCKMODE_PERMANENT:
        mode = KRB5_DB_LOCKMODE_EXCLUSIVE;
        break;
    case KRB5_DB_LOCKMODE_EXCLUSIVE:
        mode = KRB5_LOCKMODE_EXCLUSIVE;
        break;

    case KRB5_DB_LOCKMODE_SHARED:
        mode = KRB5_LOCKMODE_SHARED;
        break;
    default:
        return EINVAL;
    }

    if (!k5db2_inited(context))
        return KRB5_KDB_DBNOTINITED;

    db_ctx = context->dal_handle->db_context;
    if (db_ctx->db_locks_held && (db_ctx->db_lock_mode >= mode)) {
        /* No need to upgrade lock, just return */
        db_ctx->db_locks_held++;
        goto policy_lock;
    }

    if ((mode != KRB5_LOCKMODE_SHARED) && (mode != KRB5_LOCKMODE_EXCLUSIVE))
        return KRB5_KDB_BADLOCKMODE;

    krb5_lock_mode = mode | KRB5_LOCKMODE_DONTBLOCK;
    for (gotlock = tries = 0; tries < MAX_LOCK_TRIES; tries++) {
        retval = krb5_lock_file(context, db_ctx->db_lf_file, krb5_lock_mode);
        if (retval == 0) {
            gotlock++;
            break;
        } else if (retval == EBADF && mode == KRB5_DB_LOCKMODE_EXCLUSIVE)
            /* tried to exclusive-lock something we don't have */
            /* write access to */
            return KRB5_KDB_CANTLOCK_DB;
        sleep(1);
    }
    if (retval == EACCES)
        return KRB5_KDB_CANTLOCK_DB;
    else if (retval == EAGAIN || retval == EWOULDBLOCK)
        return OSA_ADB_CANTLOCK_DB;
    else if (retval != 0)
        return retval;

    if ((retval = krb5_db2_get_age(context, NULL, &mod_time)))
        goto lock_error;

    db = k5db2_dbopen(db_ctx, db_ctx->db_name,
                      mode == KRB5_LOCKMODE_SHARED ? O_RDONLY : O_RDWR, 0600, db_ctx->tempdb);
    if (db) {
        db_ctx->db_lf_time = mod_time;
        db_ctx->db = db;
    } else {
        retval = errno;
        db_ctx->db = NULL;
        goto lock_error;
    }

    db_ctx->db_lock_mode = mode;
    db_ctx->db_locks_held++;

policy_lock:
    if ((retval = osa_adb_get_lock(db_ctx->policy_db, in_mode))) {
        krb5_db2_unlock(context);
    }
    return retval;

lock_error:;
    db_ctx->db_lock_mode = 0;
    db_ctx->db_locks_held = 0;
    krb5_db2_unlock(context);
    return retval;
}

krb5_error_code
krb5_db2_unlock(krb5_context context)
{
    krb5_db2_context *db_ctx;
    DB     *db;
    krb5_error_code retval;

    if (!k5db2_inited(context))
        return KRB5_KDB_DBNOTINITED;

    db_ctx = context->dal_handle->db_context;

    if ((retval = osa_adb_release_lock(db_ctx->policy_db))) {
        return retval;
    }

    if (!db_ctx->db_locks_held) /* lock already unlocked */
        return KRB5_KDB_NOTLOCKED;
    db = db_ctx->db;
    if (--(db_ctx->db_locks_held) == 0) {
        (*db->close) (db);
        db_ctx->db = NULL;

        retval = krb5_lock_file(context, db_ctx->db_lf_file,
                                KRB5_LOCKMODE_UNLOCK);
        db_ctx->db_lock_mode = 0;
        return (retval);
    }
    return 0;
}

/* Create the database, assuming it's not there. */
static krb5_error_code
create_db(krb5_context context, char *db_name)
{
    krb5_error_code retval = 0;
    char   *okname;
    char   *db_name2 = NULL;
    int     fd;
    krb5_db2_context *db_ctx;
    DB     *db;
    char    policy_db_name[1024], policy_lock_name[1024];

    retval = k5db2_init_context(context);
    if (retval != 0)
        return retval;

    db_ctx = context->dal_handle->db_context;
    db = k5db2_dbopen(db_ctx, db_name, O_RDWR | O_CREAT | O_EXCL, 0600,
                      db_ctx->tempdb);
    if (db == NULL)
        return errno;
    (*db->close)(db);

    db_name2 = db_ctx->tempdb ? gen_dbsuffix(db_name, "~") : strdup(db_name);
    if (db_name2 == NULL)
        return ENOMEM;
    okname = gen_dbsuffix(db_name2, KDB2_LOCK_EXT);
    if (!okname)
        retval = ENOMEM;
    else {
        fd = open(okname, O_CREAT | O_RDWR | O_TRUNC, 0600);
        if (fd < 0)
            retval = errno;
        else
            close(fd);
        free_dbsuffix(okname);
    }

    snprintf(policy_db_name, sizeof(policy_db_name), "%s.kadm5", db_name2);
    snprintf(policy_lock_name, sizeof(policy_lock_name),
             "%s.lock", policy_db_name);

    retval = osa_adb_create_db(policy_db_name,
                               policy_lock_name, OSA_ADB_POLICY_DB_MAGIC);
    free(db_name2);
    return retval;
}

/*
 * Destroy the database.  Zero's out all of the files, just to be sure.
 */
static krb5_error_code
destroy_file_suffix(char *dbname, char *suffix)
{
    char   *filename;
    struct stat statb;
    int     nb, fd;
    int     j;
    off_t   pos;
    char    buf[BUFSIZ];
    char    zbuf[BUFSIZ];
    int     dowrite;

    filename = gen_dbsuffix(dbname, suffix);
    if (filename == 0)
        return ENOMEM;
    if ((fd = open(filename, O_RDWR, 0)) < 0) {
        free(filename);
        return errno;
    }
    set_cloexec_fd(fd);
    /* fstat() will probably not fail unless using a remote filesystem
     * (which is inappropriate for the kerberos database) so this check
     * is mostly paranoia.  */
    if (fstat(fd, &statb) == -1) {
        int     retval = errno;
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
    pos = 0;
    while (pos < statb.st_size) {
        dowrite = 0;
        nb = read(fd, buf, BUFSIZ);
        if (nb < 0) {
            int     retval = errno;
            free(filename);
            return retval;
        }
        for (j = 0; j < nb; j++) {
            if (buf[j] != '\0') {
                dowrite = 1;
                break;
            }
        }
        /* For signedness */
        j = nb;
        if (dowrite) {
            lseek(fd, pos, SEEK_SET);
            nb = write(fd, zbuf, j);
            if (nb < 0) {
                int     retval = errno;
                free(filename);
                return retval;
            }
        }
        pos += nb;
    }
    /* ??? Is fsync really needed?  I don't know of any non-networked
     * filesystem which will discard queued writes to disk if a file
     * is deleted after it is closed.  --jfc */
#ifndef NOFSYNC
    fsync(fd);
#endif
    close(fd);

    if (unlink(filename)) {
        free(filename);
        return (errno);
    }
    free(filename);
    return (0);
}

/*
 * Since the destroy operation happens outside the init/fini bracket, we
 * have some tomfoolery to undergo here.  If we're operating under no
 * database context, then we initialize with the default.  If the caller
 * wishes a different context (e.g. different dispatch table), it's their
 * responsibility to call kdb5_db_set_dbops() before this call.  That will
 * set up the right dispatch table values (e.g. name extensions).
 *
 * Not quite valid due to ripping out of dbops...
 */
static krb5_error_code
destroy_db(krb5_context context, char *dbname)
{
    krb5_error_code retval1, retval2;
    krb5_boolean tmpcontext;
    char    policy_db_name[1024], policy_lock_name[1024];

    tmpcontext = 0;
    if (!context->dal_handle->db_context) {
        tmpcontext = 1;
        if ((retval1 = k5db2_init_context(context)))
            return (retval1);
    }

    retval1 = retval2 = 0;
    retval1 = destroy_file_suffix(dbname, "");
    retval2 = destroy_file_suffix(dbname, KDB2_LOCK_EXT);

    if (tmpcontext) {
        k5db2_clear_context(context->dal_handle->db_context);
        free(context->dal_handle->db_context);
        context->dal_handle->db_context = NULL;
    }

    if (retval1 || retval2)
        return (retval1 ? retval1 : retval2);

    snprintf(policy_db_name, sizeof(policy_db_name), "%s.kadm5", dbname);
    snprintf(policy_lock_name, sizeof(policy_lock_name),
             "%s.lock", policy_db_name);

    retval1 = osa_adb_destroy_db(policy_db_name,
                                 policy_lock_name, OSA_ADB_POLICY_DB_MAGIC);

    return retval1;
}

krb5_error_code
krb5_db2_get_principal(krb5_context context, krb5_const_principal searchfor,
                       unsigned int flags, krb5_db_entry **entry)
{
    krb5_db2_context *db_ctx;
    krb5_error_code retval;
    DB     *db;
    DBT     key, contents;
    krb5_data keydata, contdata;
    int     trynum, dbret;

    *entry = NULL;
    if (!k5db2_inited(context))
        return KRB5_KDB_DBNOTINITED;

    db_ctx = context->dal_handle->db_context;

    for (trynum = 0; trynum < KRB5_DB2_MAX_RETRY; trynum++) {
        if ((retval = krb5_db2_lock(context, KRB5_LOCKMODE_SHARED))) {
            if (db_ctx->db_nb_locks)
                return (retval);
            sleep(1);
            continue;
        }
        break;
    }
    if (trynum == KRB5_DB2_MAX_RETRY)
        return KRB5_KDB_DB_INUSE;

    /* XXX deal with wildcard lookups */
    retval = krb5_encode_princ_dbkey(context, &keydata, searchfor);
    if (retval)
        goto cleanup;
    key.data = keydata.data;
    key.size = keydata.length;

    db = db_ctx->db;
    dbret = (*db->get)(db, &key, &contents, 0);
    retval = errno;
    krb5_free_data_contents(context, &keydata);
    switch (dbret) {
    case 1:
        retval = KRB5_KDB_NOENTRY;
        /* Fall through. */
    case -1:
    default:
        goto cleanup;
    case 0:
        contdata.data = contents.data;
        contdata.length = contents.size;
        retval = krb5_decode_princ_entry(context, &contdata, entry);
        break;
    }

cleanup:
    (void) krb5_db2_unlock(context); /* unlock read lock */
    return retval;
}

/* Free an entry returned by krb5_db2_get_principal. */
void
krb5_db2_free_principal(krb5_context context, krb5_db_entry *entry)
{
    krb5_dbe_free(context, entry);
}

krb5_error_code
krb5_db2_put_principal(krb5_context context, krb5_db_entry *entry,
                       char **db_args)
{
    int     dbret;
    DB     *db;
    DBT     key, contents;
    krb5_data contdata, keydata;
    krb5_error_code retval;
    krb5_db2_context *db_ctx;

    krb5_clear_error_message (context);
    if (db_args) {
        /* DB2 does not support db_args DB arguments for principal */
        krb5_set_error_message(context, EINVAL,
                               "Unsupported argument \"%s\" for db2",
                               db_args[0]);
        return EINVAL;
    }

    if (!k5db2_inited(context))
        return KRB5_KDB_DBNOTINITED;

    db_ctx = context->dal_handle->db_context;
    if ((retval = krb5_db2_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
        return retval;

    db = db_ctx->db;
    if ((retval = krb5_db2_start_update(context))) {
        (void) krb5_db2_unlock(context);
        return retval;
    }

    retval = krb5_encode_princ_entry(context, &contdata, entry);
    if (retval)
        goto cleanup;
    contents.data = contdata.data;
    contents.size = contdata.length;
    retval = krb5_encode_princ_dbkey(context, &keydata, entry->princ);
    if (retval) {
        krb5_free_data_contents(context, &contdata);
        goto cleanup;
    }

    key.data = keydata.data;
    key.size = keydata.length;
    dbret = (*db->put)(db, &key, &contents, 0);
    retval = dbret ? errno : 0;
    krb5_free_data_contents(context, &keydata);
    krb5_free_data_contents(context, &contdata);

cleanup:
    (void) krb5_db2_end_update(context);
    (void) krb5_db2_unlock(context); /* unlock database */
    return (retval);
}

krb5_error_code
krb5_db2_delete_principal(krb5_context context, krb5_const_principal searchfor)
{
    krb5_error_code retval;
    krb5_db_entry *entry;
    krb5_db2_context *db_ctx;
    DB     *db;
    DBT     key, contents;
    krb5_data keydata, contdata;
    int     i, dbret;

    if (!k5db2_inited(context))
        return KRB5_KDB_DBNOTINITED;

    db_ctx = context->dal_handle->db_context;
    if ((retval = krb5_db2_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
        return (retval);

    if ((retval = krb5_db2_start_update(context))) {
        (void) krb5_db2_unlock(context);     /* unlock write lock */
        return (retval);
    }

    if ((retval = krb5_encode_princ_dbkey(context, &keydata, searchfor)))
        goto cleanup;
    key.data = keydata.data;
    key.size = keydata.length;

    db = db_ctx->db;
    dbret = (*db->get) (db, &key, &contents, 0);
    retval = errno;
    switch (dbret) {
    case 1:
        retval = KRB5_KDB_NOENTRY;
        /* Fall through. */
    case -1:
    default:
        goto cleankey;
    case 0:
        ;
    }
    contdata.data = contents.data;
    contdata.length = contents.size;
    retval = krb5_decode_princ_entry(context, &contdata, &entry);
    if (retval)
        goto cleankey;

    /* Clear encrypted key contents */
    for (i = 0; i < entry->n_key_data; i++) {
        if (entry->key_data[i].key_data_length[0]) {
            memset(entry->key_data[i].key_data_contents[0], 0,
                   (unsigned) entry->key_data[i].key_data_length[0]);
        }
    }

    retval = krb5_encode_princ_entry(context, &contdata, entry);
    krb5_dbe_free(context, entry);
    if (retval)
        goto cleankey;

    contents.data = contdata.data;
    contents.size = contdata.length;
    dbret = (*db->put) (db, &key, &contents, 0);
    retval = dbret ? errno : 0;
    krb5_free_data_contents(context, &contdata);
    if (retval)
        goto cleankey;
    dbret = (*db->del) (db, &key, 0);
    retval = dbret ? errno : 0;
cleankey:
    krb5_free_data_contents(context, &keydata);

cleanup:
    (void) krb5_db2_end_update(context);
    (void) krb5_db2_unlock(context); /* unlock write lock */
    return retval;
}

krb5_error_code
krb5_db2_iterate_ext(krb5_context context,
                     krb5_error_code(*func) (krb5_pointer, krb5_db_entry *),
                     krb5_pointer func_arg, int backwards, int recursive)
{
    krb5_db2_context *db_ctx;
    DB     *db;
    DBT     key, contents;
    krb5_data contdata;
    krb5_db_entry *entry;
    krb5_error_code retval;
    int     dbret;
    void   *cookie;

    cookie = NULL;
    if (!k5db2_inited(context))
        return KRB5_KDB_DBNOTINITED;

    db_ctx = context->dal_handle->db_context;
    retval = krb5_db2_lock(context, KRB5_LOCKMODE_SHARED);

    if (retval)
        return retval;

    db = db_ctx->db;
    if (recursive && db->type != DB_BTREE) {
        (void) krb5_db2_unlock(context);
        return KRB5_KDB_UK_RERROR;      /* Not optimal, but close enough. */
    }

    if (!recursive) {
        dbret = (*db->seq) (db, &key, &contents, backwards ? R_LAST : R_FIRST);
    } else {
#ifdef HAVE_BT_RSEQ
        dbret = bt_rseq(db, &key, &contents, &cookie,
                        backwards ? R_LAST : R_FIRST);
#else
        (void) krb5_db2_unlock(context);
        return KRB5_KDB_UK_RERROR;      /* Not optimal, but close enough. */
#endif
    }
    while (dbret == 0) {
        krb5_error_code retval2;

        contdata.data = contents.data;
        contdata.length = contents.size;
        retval = krb5_decode_princ_entry(context, &contdata, &entry);
        if (retval)
            break;
        retval = k5_mutex_unlock(krb5_db2_mutex);
        if (retval)
            break;
        retval = (*func)(func_arg, entry);
        krb5_dbe_free(context, entry);
        retval2 = k5_mutex_lock(krb5_db2_mutex);
        /* Note: If re-locking fails, the wrapper in db2_exp.c will
           still try to unlock it again.  That would be a bug.  Fix
           when integrating the locking better.  */
        if (retval)
            break;
        if (retval2) {
            retval = retval2;
            break;
        }
        if (!recursive) {
            dbret = (*db->seq) (db, &key, &contents,
                                backwards ? R_PREV : R_NEXT);
        } else {
#ifdef HAVE_BT_RSEQ
            dbret = bt_rseq(db, &key, &contents, &cookie,
                            backwards ? R_PREV : R_NEXT);
#else
            (void) krb5_db2_unlock(context);
            return KRB5_KDB_UK_RERROR;  /* Not optimal, but close enough. */
#endif
        }
    }
    switch (dbret) {
    case 1:
    case 0:
        break;
    case -1:
    default:
        retval = errno;
    }
    (void) krb5_db2_unlock(context);
    return retval;
}

krb5_error_code
krb5_db2_iterate(krb5_context context, char *match_expr,
                 krb5_error_code(*func) (krb5_pointer, krb5_db_entry *),
                 krb5_pointer func_arg)
{
    return krb5_db2_iterate_ext(context, func, func_arg, 0, 0);
}

krb5_boolean
krb5_db2_set_lockmode(krb5_context context, krb5_boolean mode)
{
    krb5_boolean old;
    krb5_db2_context *db_ctx;

    db_ctx = context->dal_handle->db_context;
    old = mode;
    if (db_ctx) {
        old = db_ctx->db_nb_locks;
        db_ctx->db_nb_locks = mode;
    }
    return old;
}

/*
 *     DAL API functions
 */
krb5_error_code
krb5_db2_lib_init()
{
    return 0;
}

krb5_error_code
krb5_db2_lib_cleanup()
{
    /* right now, no cleanup required */
    return 0;
}

krb5_error_code
krb5_db2_open(krb5_context context, char *conf_section, char **db_args,
              int mode)
{
    krb5_error_code status = 0;

    krb5_clear_error_message(context);
    if (k5db2_inited(context))
        return 0;

    status = configure_context(context, conf_section, db_args);
    if (status != 0)
        return status;

    status = check_openable(context);
    if (status != 0)
        return status;

    return krb5_db2_init(context);
}

krb5_error_code
krb5_db2_create(krb5_context context, char *conf_section, char **db_args)
{
    krb5_error_code status = 0;
    krb5_db2_context *db_ctx;

    krb5_clear_error_message(context);
    if (k5db2_inited(context))
        return 0;

    status = configure_context(context, conf_section, db_args);
    if (status != 0)
        return status;

    status = check_openable(context);
    if (status == 0)
        return EEXIST;

    db_ctx = context->dal_handle->db_context;
    status = create_db(context, db_ctx->db_name);
    if (status != 0)
        return status;

    return krb5_db2_init(context);
}

krb5_error_code
krb5_db2_destroy(krb5_context context, char *conf_section, char **db_args)
{
    krb5_error_code status = 0;
    krb5_db2_context *db_ctx;
    char *db_name;

    if (k5db2_inited(context)) {
        status = krb5_db2_fini(context);
        if (status != 0)
            return status;
    }

    krb5_clear_error_message(context);
    status = configure_context(context, conf_section, db_args);
    if (status != 0)
        return status;

    status = check_openable(context);
    if (status != 0)
        return status;

    db_ctx = context->dal_handle->db_context;
    db_name = gen_dbsuffix(db_ctx->db_name, db_ctx->tempdb ? "~" : "");
    if (db_name == NULL)
        return ENOMEM;
    status = destroy_db(context, db_name);
    free(db_name);
    return status;
}

void   *
krb5_db2_alloc(krb5_context context, void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void
krb5_db2_free(krb5_context context, void *ptr)
{
    free(ptr);
}

/* policy functions */
krb5_error_code
krb5_db2_create_policy(krb5_context context, osa_policy_ent_t policy)
{
    krb5_db2_context *dbc = context->dal_handle->db_context;

    return osa_adb_create_policy(dbc->policy_db, policy);
}

krb5_error_code
krb5_db2_get_policy(krb5_context context,
                    char *name, osa_policy_ent_t *policy)
{
    krb5_db2_context *dbc = context->dal_handle->db_context;

    return osa_adb_get_policy(dbc->policy_db, name, policy);
}

krb5_error_code
krb5_db2_put_policy(krb5_context context, osa_policy_ent_t policy)
{
    krb5_db2_context *dbc = context->dal_handle->db_context;

    return osa_adb_put_policy(dbc->policy_db, policy);
}

krb5_error_code
krb5_db2_iter_policy(krb5_context context,
                     char *match_entry,
                     osa_adb_iter_policy_func func, void *data)
{
    krb5_db2_context *dbc = context->dal_handle->db_context;

    return osa_adb_iter_policy(dbc->policy_db, func, data);
}

krb5_error_code
krb5_db2_delete_policy(krb5_context context, char *policy)
{
    krb5_db2_context *dbc = context->dal_handle->db_context;

    return osa_adb_destroy_policy(dbc->policy_db, policy);
}

void
krb5_db2_free_policy(krb5_context context, osa_policy_ent_t entry)
{
    osa_free_policy_ent(entry);
}


/* */

krb5_error_code
krb5_db2_promote_db(krb5_context context, char *conf_section, char **db_args)
{
    krb5_error_code status = 0;
    char *db_name = NULL;
    char *temp_db_name = NULL;
    char **db_argp;
    int merge_nra = 0;
    krb5_db2_context *db_ctx = context->dal_handle->db_context;

    krb5_clear_error_message (context);

    db_name = strdup(db_ctx->db_name);
    if (db_name == NULL) {
        status = ENOMEM;
        goto clean_n_exit;
    }

    temp_db_name = gen_dbsuffix(db_name, "~");
    if (temp_db_name == NULL) {
        status = ENOMEM;
        goto clean_n_exit;
    }

    for (db_argp = db_args; *db_argp; db_argp++) {
        if (!strcmp(*db_argp, "merge_nra")) {
            merge_nra++;
            break;
        }
    }

    status = krb5_db2_rename(context, temp_db_name, db_name, merge_nra);
    if (status)
        goto clean_n_exit;

clean_n_exit:
    free(db_name);
    free(temp_db_name);
    return status;
}

/*
 * Merge non-replicated attributes from src into dst, setting
 * changed to non-zero if dst was changed.
 *
 * Non-replicated attributes are: last_success, last_failed,
 * fail_auth_count, and any negative TL data values.
 */
static krb5_error_code
krb5_db2_merge_principal(krb5_context context,
                         krb5_db_entry *src,
                         krb5_db_entry *dst,
                         int *changed)
{
    *changed = 0;

    if (dst->last_success != src->last_success) {
        dst->last_success = src->last_success;
        (*changed)++;
    }

    if (dst->last_failed != src->last_failed) {
        dst->last_failed = src->last_failed;
        (*changed)++;
    }

    if (dst->fail_auth_count != src->fail_auth_count) {
        dst->fail_auth_count = src->fail_auth_count;
        (*changed)++;
    }

    return 0;
}

struct nra_context {
    krb5_context kcontext;
    krb5_db2_context *db_context;
};

/*
 * Iteration callback merges non-replicated attributes from
 * old database.
 */
static krb5_error_code
krb5_db2_merge_nra_iterator(krb5_pointer ptr, krb5_db_entry *entry)
{
    struct nra_context *nra = (struct nra_context *)ptr;
    kdb5_dal_handle *dal_handle = nra->kcontext->dal_handle;
    krb5_error_code retval;
    int changed;
    krb5_db_entry *s_entry;
    krb5_db2_context *dst_db;

    memset(&s_entry, 0, sizeof(s_entry));

    dst_db = dal_handle->db_context;
    dal_handle->db_context = nra->db_context;

    /* look up the new principal in the old DB */
    retval = krb5_db2_get_principal(nra->kcontext, entry->princ, 0, &s_entry);
    if (retval != 0) {
        /* principal may be newly created, so ignore */
        dal_handle->db_context = dst_db;
        return 0;
    }

    /* merge non-replicated attributes from the old entry in */
    krb5_db2_merge_principal(nra->kcontext, s_entry, entry, &changed);

    dal_handle->db_context = dst_db;

    /* if necessary, commit the modified new entry to the new DB */
    if (changed) {
        retval = krb5_db2_put_principal(nra->kcontext, entry, NULL);
    } else {
        retval = 0;
    }

    return retval;
}

/*
 * Merge non-replicated attributes (that is, lockout-related
 * attributes and negative TL data types) from the old database
 * into the new one.
 *
 * Note: src_db is locked on success.
 */
static krb5_error_code
krb5_db2_begin_nra_merge(krb5_context context,
                         krb5_db2_context *src_db,
                         krb5_db2_context *dst_db)
{
    krb5_error_code retval;
    kdb5_dal_handle *dal_handle = context->dal_handle;
    struct nra_context nra;

    nra.kcontext = context;
    nra.db_context = dst_db;

    assert(dal_handle->db_context == dst_db);
    dal_handle->db_context = src_db;

    retval = krb5_db2_lock(context, KRB5_LOCKMODE_EXCLUSIVE);
    if (retval) {
        dal_handle->db_context = dst_db;
        return retval;
    }

    retval = krb5_db2_iterate_ext(context, krb5_db2_merge_nra_iterator,
                                  &nra, 0, 0);
    if (retval != 0)
        (void) krb5_db2_unlock(context);

    dal_handle->db_context = dst_db;

    return retval;
}

/*
 * Finish merge of non-replicated attributes by unlocking
 * src_db.
 */
static krb5_error_code
krb5_db2_end_nra_merge(krb5_context context,
                       krb5_db2_context *src_db,
                       krb5_db2_context *dst_db)
{
    krb5_error_code retval;
    kdb5_dal_handle *dal_handle = context->dal_handle;

    dal_handle->db_context = src_db;
    retval = krb5_db2_unlock(context);
    dal_handle->db_context = dst_db;

    return retval;
}

/* Retrieved from pre-DAL code base.  */
/*
 * "Atomically" rename the database in a way that locks out read
 * access in the middle of the rename.
 *
 * Not perfect; if we crash in the middle of an update, we don't
 * necessarily know to complete the transaction the rename, but...
 *
 * Since the rename operation happens outside the init/fini bracket, we
 * have to go through the same stuff that we went through up in db_destroy.
 */
krb5_error_code
krb5_db2_rename(krb5_context context, char *from, char *to, int merge_nra)
{
    char *fromok;
    krb5_error_code retval;
    krb5_db2_context *s_context, *db_ctx;
    kdb5_dal_handle *dal_handle = context->dal_handle;

    s_context = dal_handle->db_context;
    dal_handle->db_context = NULL;
    if ((retval = k5db2_init_context(context)))
        return retval;
    db_ctx = (krb5_db2_context *) dal_handle->db_context;

    /*
     * Create the database if it does not already exist; the
     * files must exist because krb5_db2_lock, called below,
     * will fail otherwise.
     */
    retval = create_db(context, to);
    if (retval != 0 && retval != EEXIST)
        goto errout;

    /*
     * Set the database to the target, so that other processes sharing
     * the target will stop their activity, and notice the new database.
     */
    db_ctx->db_name = strdup(to);
    if (db_ctx->db_name == NULL) {
        retval = ENOMEM;
        goto errout;
    }

    retval = check_openable(context);
    if (retval)
        goto errout;

    retval = krb5_db2_init(context);
    if (retval)
        goto errout;

    db_ctx->db_lf_name = gen_dbsuffix(db_ctx->db_name, KDB2_LOCK_EXT);
    if (db_ctx->db_lf_name == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    db_ctx->db_lf_file = open(db_ctx->db_lf_name, O_RDWR|O_CREAT, 0600);
    if (db_ctx->db_lf_file < 0) {
        retval = errno;
        goto errout;
    }
    set_cloexec_fd(db_ctx->db_lf_file);

    db_ctx->db_inited = 1;

    retval = krb5_db2_get_age(context, NULL, &db_ctx->db_lf_time);
    if (retval)
        goto errout;

    fromok = gen_dbsuffix(from, KDB2_LOCK_EXT);
    if (fromok == NULL) {
        retval = ENOMEM;
        goto errout;
    }

    if ((retval = krb5_db2_lock(context, KRB5_LOCKMODE_EXCLUSIVE)))
        goto errfromok;

    if ((retval = krb5_db2_start_update(context)))
        goto errfromok;

    if (merge_nra) {
        if ((retval = krb5_db2_begin_nra_merge(context, s_context, db_ctx)))
            goto errfromok;
    }

    if (rename(from, to)) {
        retval = errno;
        goto errfromok;
    }
    if (unlink(fromok)) {
        retval = errno;
        goto errfromok;
    }

    if (merge_nra) {
        krb5_db2_end_nra_merge(context, s_context, db_ctx);
    }

    retval = krb5_db2_end_update(context);
    if (retval)
        goto errfromok;

    {
        /* XXX moved so that NRA merge works */
        /* Ugly brute force hack.

           Should be going through nice friendly helper routines for
           this, but it's a mess of jumbled so-called interfaces right
           now.  */
        char    policy[2048], new_policy[2048];
        assert (strlen(db_ctx->db_name) < 2000);
        snprintf(policy, sizeof(policy), "%s.kadm5", db_ctx->db_name);
        snprintf(new_policy, sizeof(new_policy),
                 "%s~.kadm5", db_ctx->db_name);
        if (0 != rename(new_policy, policy)) {
            retval = errno;
            goto errfromok;
        }
        strlcat(new_policy, ".lock",sizeof(new_policy));
        (void) unlink(new_policy);
    }

errfromok:
    free_dbsuffix(fromok);
errout:
    if (dal_handle->db_context) {
        if (db_ctx->db_lf_file >= 0) {
            krb5_db2_unlock(context);
            close(db_ctx->db_lf_file);
        }
        k5db2_clear_context((krb5_db2_context *) dal_handle->db_context);
        free(dal_handle->db_context);
    }

    dal_handle->db_context = s_context;
    (void) krb5_db2_unlock(context); /* unlock saved context db */

    return retval;
}

krb5_error_code
krb5_db2_check_policy_as(krb5_context kcontext, krb5_kdc_req *request,
                         krb5_db_entry *client, krb5_db_entry *server,
                         krb5_timestamp kdc_time, const char **status,
                         krb5_data *e_data)
{
    krb5_error_code retval;

    retval = krb5_db2_lockout_check_policy(kcontext, client, kdc_time);
    if (retval == KRB5KDC_ERR_CLIENT_REVOKED)
        *status = "LOCKED_OUT";
    return retval;
}

void
krb5_db2_audit_as_req(krb5_context kcontext, krb5_kdc_req *request,
                      krb5_db_entry *client, krb5_db_entry *server,
                      krb5_timestamp authtime, krb5_error_code error_code)
{
    (void) krb5_db2_lockout_audit(kcontext, client, authtime, error_code);
}
