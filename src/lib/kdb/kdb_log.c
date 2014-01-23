/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <k5-int.h>
#include <stdlib.h>
#include <limits.h>
#include <syslog.h>
#include "kdb5.h"
#include "kdb_log.h"
#include "kdb5int.h"

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

/* This module includes all the necessary functions that create and modify the
 * Kerberos principal update and header logs. */

#define getpagesize() sysconf(_SC_PAGESIZE)

static int pagesize = 0;

#define INIT_ULOG(ctx)                          \
    log_ctx = ctx->kdblog_context;              \
    assert(log_ctx != NULL);                    \
    ulog = log_ctx->ulog;                       \
    assert(ulog != NULL)

static inline krb5_boolean
time_equal(const kdbe_time_t *a, const kdbe_time_t *b)
{
    return a->seconds == b->seconds && a->useconds == b->useconds;
}

static void
time_current(kdbe_time_t *out)
{
    struct timeval timestamp;

    (void)gettimeofday(&timestamp, NULL);
    out->seconds = timestamp.tv_sec;
    out->useconds = timestamp.tv_usec;
}

/* Sync update entry to disk. */
static krb5_error_code
sync_update(kdb_hlog_t *ulog, kdb_ent_header_t *upd)
{
    unsigned long start, end, size;

    if (ulog == NULL)
        return KRB5_LOG_ERROR;

    if (!pagesize)
        pagesize = getpagesize();

    start = (unsigned long)upd & ~(pagesize - 1);

    end = ((unsigned long)upd + ulog->kdb_block + (pagesize - 1)) &
        ~(pagesize - 1);

    size = end - start;
    return msync((caddr_t)start, size, MS_SYNC);
}

/* Sync memory to disk for the update log header. */
static void
sync_header(kdb_hlog_t *ulog)
{
    if (!pagesize)
        pagesize = getpagesize();

    if (msync((caddr_t)ulog, pagesize, MS_SYNC)) {
        /* Couldn't sync to disk, let's panic. */
        syslog(LOG_ERR, _("could not sync ulog header to disk"));
        abort();
    }
}

/* Return true if the ulog entry for sno matches sno and timestamp. */
static krb5_boolean
check_sno(kdb_log_context *log_ctx, kdb_sno_t sno,
          const kdbe_time_t *timestamp)
{
    unsigned int indx = (sno - 1) % log_ctx->ulogentries;
    kdb_ent_header_t *ent = INDEX(log_ctx->ulog, indx);

    return ent->kdb_entry_sno == sno && time_equal(&ent->kdb_time, timestamp);
}

/*
 * Check last against our ulog and determine whether it is up to date
 * (UPDATE_NIL), so far out of date that a full dump is required
 * (UPDATE_FULL_RESYNC_NEEDED), or okay to update with ulog entries
 * (UPDATE_OK).
 */
static update_status_t
get_sno_status(kdb_log_context *log_ctx, const kdb_last_t *last)
{
    kdb_hlog_t *ulog = log_ctx->ulog;

    /* If last matches the ulog's last serial number and time exactly, it are
     * up to date even if the ulog is empty. */
    if (last->last_sno == ulog->kdb_last_sno &&
        time_equal(&last->last_time, &ulog->kdb_last_time))
        return UPDATE_NIL;

    /* If our ulog is empty or does not contain last_sno, a full resync is
     * required. */
    if (ulog->kdb_num == 0 || last->last_sno > ulog->kdb_last_sno ||
        last->last_sno < ulog->kdb_first_sno)
        return UPDATE_FULL_RESYNC_NEEDED;

    /* If the timestamp in our ulog entry does not match last, then sno was
     * reused and a full resync is required. */
    if (!check_sno(log_ctx, last->last_sno, &last->last_time))
        return UPDATE_FULL_RESYNC_NEEDED;

    /* last is not fully up to date, but can be updated using our ulog. */
    return UPDATE_OK;
}

/* Extend update log file. */
static int
extend_file_to(int fd, unsigned int new_size)
{
    off_t current_offset;
    static const char zero[512];
    ssize_t wrote_size;
    size_t write_size;

    current_offset = lseek(fd, 0, SEEK_END);
    if (current_offset < 0)
        return -1;
    if (new_size > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    while (current_offset < (off_t)new_size) {
        write_size = new_size - current_offset;
        if (write_size > 512)
            write_size = 512;
        wrote_size = write(fd, zero, write_size);
        if (wrote_size < 0)
            return -1;
        if (wrote_size == 0) {
            errno = EINVAL;
            return -1;
        }
        current_offset += wrote_size;
        write_size = new_size - current_offset;
    }
    return 0;
}

/*
 * Resize the array elements.  We reinitialize the update log rather than
 * unrolling the the log and copying it over to a temporary log for obvious
 * performance reasons.  Slaves will subsequently do a full resync, but the
 * need for resizing should be very small.
 */
static krb5_error_code
resize(kdb_hlog_t *ulog, uint32_t ulogentries, int ulogfd,
       unsigned int recsize)
{
    unsigned int new_block, new_size;

    if (ulog == NULL)
        return KRB5_LOG_ERROR;

    new_size = sizeof(kdb_hlog_t);
    new_block = (recsize / ULOG_BLOCK) + 1;
    new_block *= ULOG_BLOCK;
    new_size += ulogentries * new_block;

    if (new_size > MAXLOGLEN)
        return KRB5_LOG_ERROR;

    /* Reinit log with new block size. */
    memset(ulog, 0, sizeof(*ulog));
    ulog->kdb_hmagic = KDB_ULOG_HDR_MAGIC;
    ulog->db_version_num = KDB_VERSION;
    ulog->kdb_state = KDB_STABLE;
    ulog->kdb_block = new_block;
    sync_header(ulog);

    /* Expand log considering new block size. */
    if (extend_file_to(ulogfd, new_size) < 0)
        return errno;

    return 0;
}

static void
reset_header(kdb_hlog_t *ulog)
{
    memset(ulog, 0, sizeof(*ulog));
    ulog->kdb_hmagic = KDB_ULOG_HDR_MAGIC;
    ulog->db_version_num = KDB_VERSION;
    ulog->kdb_state = KDB_STABLE;
    ulog->kdb_block = ULOG_BLOCK;
    time_current(&ulog->kdb_last_time);
}

/*
 * If any database operations will be invoked while the ulog lock is held, the
 * caller must explicitly lock the database before locking the ulog, or
 * deadlock may result.
 */
static krb5_error_code
lock_ulog(krb5_context context, int mode)
{
    kdb_log_context *log_ctx = NULL;
    kdb_hlog_t *ulog = NULL;

    INIT_ULOG(context);
    return krb5_lock_file(context, log_ctx->ulogfd, mode);
}

static void
unlock_ulog(krb5_context context)
{
    (void)lock_ulog(context, KRB5_LOCKMODE_UNLOCK);
}

/*
 * Add an entry to the update log.  The layout of the update log looks like:
 *
 * header log -> [ update header -> xdr(kdb_incr_update_t) ], ...
 */
krb5_error_code
ulog_add_update(krb5_context context, kdb_incr_update_t *upd)
{
    XDR xdrs;
    kdbe_time_t ktime;
    kdb_ent_header_t *indx_log;
    unsigned int i, recsize;
    unsigned long upd_size;
    krb5_error_code retval;
    kdb_sno_t cur_sno;
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog = NULL;
    uint32_t ulogentries;
    int ulogfd;

    INIT_ULOG(context);
    retval = lock_ulog(context, KRB5_LOCKMODE_EXCLUSIVE);
    if (retval)
        return retval;

    ulogentries = log_ctx->ulogentries;
    ulogfd = log_ctx->ulogfd;

    time_current(&ktime);

    upd_size = xdr_sizeof((xdrproc_t)xdr_kdb_incr_update_t, upd);

    recsize = sizeof(kdb_ent_header_t) + upd_size;

    if (recsize > ulog->kdb_block) {
        retval = resize(ulog, ulogentries, ulogfd, recsize);
        if (retval)
            goto cleanup;
    }

    /* If we have reached the last possible serial number, reinitialize the
     * ulog and start over.  Slaves will do a full resync. */
    if (ulog->kdb_last_sno == (kdb_sno_t)-1)
        reset_header(ulog);

    ulog->kdb_state = KDB_UNSTABLE;

    /* Get the next serial number and find its update entry. */
    cur_sno = ulog->kdb_last_sno + 1;
    i = (cur_sno - 1) % ulogentries;
    indx_log = INDEX(ulog, i);

    memset(indx_log, 0, ulog->kdb_block);
    indx_log->kdb_umagic = KDB_ULOG_MAGIC;
    indx_log->kdb_entry_size = upd_size;
    indx_log->kdb_entry_sno = upd->kdb_entry_sno = cur_sno;
    indx_log->kdb_time = upd->kdb_time = ktime;
    indx_log->kdb_commit = upd->kdb_commit = FALSE;

    xdrmem_create(&xdrs, (char *)indx_log->entry_data,
                  indx_log->kdb_entry_size, XDR_ENCODE);
    if (!xdr_kdb_incr_update_t(&xdrs, upd)) {
        retval = KRB5_LOG_CONV;
        goto cleanup;
    }

    indx_log->kdb_commit = TRUE;
    retval = sync_update(ulog, indx_log);
    if (retval)
        goto cleanup;

    if (ulog->kdb_num < ulogentries)
        ulog->kdb_num++;

    ulog->kdb_last_sno = cur_sno;
    ulog->kdb_last_time = ktime;

    if (cur_sno > ulogentries) {
        /* Once we've circled, kdb_first_sno is the sno of the next entry. */
        i = upd->kdb_entry_sno % ulogentries;
        indx_log = INDEX(ulog, i);
        ulog->kdb_first_sno = indx_log->kdb_entry_sno;
        ulog->kdb_first_time = indx_log->kdb_time;
    } else if (cur_sno == 1) {
        /* This is the first update. */
        ulog->kdb_first_sno = 1;
        ulog->kdb_first_time = indx_log->kdb_time;
    }

    ulog->kdb_state = KDB_STABLE;

cleanup:
    sync_header(ulog);
    unlock_ulog(context);
    return retval;
}

/* Used by the slave to update its hash db from the incr update log. */
krb5_error_code
ulog_replay(krb5_context context, kdb_incr_result_t *incr_ret, char **db_args)
{
    krb5_db_entry *entry = NULL;
    kdb_incr_update_t *upd = NULL, *fupd;
    int i, no_of_updates;
    krb5_error_code retval;
    krb5_principal dbprinc;
    kdb_last_t errlast, *last;
    char *dbprincstr;
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog = NULL;

    INIT_ULOG(context);

    /* Lock the DB before the ulog to avoid deadlock. */
    retval = krb5_db_open(context, db_args,
                          KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_ADMIN);
    if (retval)
        return retval;
    retval = krb5_db_lock(context, KRB5_DB_LOCKMODE_EXCLUSIVE);
    if (retval)
        return retval;
    retval = lock_ulog(context, KRB5_LOCKMODE_EXCLUSIVE);
    if (retval) {
        krb5_db_unlock(context);
        return retval;
    }

    no_of_updates = incr_ret->updates.kdb_ulog_t_len;
    upd = incr_ret->updates.kdb_ulog_t_val;
    fupd = upd;

    /* We reset last_sno and last_time to 0, if krb5_db2_db_put_principal or
     * krb5_db2_db_delete_principal fail. */
    errlast.last_sno = (unsigned int)0;
    errlast.last_time.seconds = (unsigned int)0;
    errlast.last_time.useconds = (unsigned int)0;
    last = &errlast;

    for (i = 0; i < no_of_updates; i++) {
        if (!upd->kdb_commit)
            continue;

        if (upd->kdb_deleted) {
            dbprincstr = k5memdup0(upd->kdb_princ_name.utf8str_t_val,
                                   upd->kdb_princ_name.utf8str_t_len, &retval);
            if (dbprincstr == NULL)
                goto cleanup;

            retval = krb5_parse_name(context, dbprincstr, &dbprinc);
            free(dbprincstr);
            if (retval)
                goto cleanup;

            retval = krb5int_delete_principal_no_log(context, dbprinc);
            krb5_free_principal(context, dbprinc);
            if (retval)
                goto cleanup;
        } else {
            entry = k5alloc(sizeof(krb5_db_entry), &retval);
            if (entry == NULL)
                goto cleanup;

            retval = ulog_conv_2dbentry(context, &entry, upd);
            if (retval)
                goto cleanup;

            retval = krb5int_put_principal_no_log(context, entry);
            krb5_db_free_principal(context, entry);
            if (retval)
                goto cleanup;
        }

        upd++;
    }

    last = &incr_ret->lastentry;

cleanup:
    if (fupd)
        ulog_free_entries(fupd, no_of_updates);

    /* Record a new last serial number and timestamp in the ulog header. */
    ulog->kdb_last_sno = last->last_sno;
    ulog->kdb_last_time = last->last_time;
    sync_header(ulog);
    unlock_ulog(context);
    krb5_db_unlock(context);
    return retval;
}

/* Reinitialize the log header. */
krb5_error_code
ulog_init_header(krb5_context context)
{
    krb5_error_code ret;
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog;

    INIT_ULOG(context);
    ret = lock_ulog(context, KRB5_LOCKMODE_EXCLUSIVE);
    if (ret)
        return ret;
    reset_header(ulog);
    sync_header(ulog);
    unlock_ulog(context);
    return 0;
}

/*
 * Map the log file to memory for performance and simplicity.
 *
 * Called by: if iprop_enabled then ulog_map();
 * Assumes that the caller will terminate on ulog_map, hence munmap and
 * closing of the fd are implicitly performed by the caller.
 *
 * Semantics for various values of caller:
 *
 *  - FKPROPLOG
 *
 *    Don't create if it doesn't exist, map as MAP_PRIVATE.
 *
 *  - FKPROPD
 *
 *    Create and initialize if need be, map as MAP_SHARED.
 *
 *  - FKCOMMAND
 *
 *    Create and [re-]initialize if need be, size appropriately, map as
 *    MAP_SHARED.  (Intended for kdb5_util create and kdb5_util load of
 *    non-iprop dump.)
 *
 *  - FKADMIN
 *
 *    Create and [re-]initialize if need be, size appropriately, map as
 *    MAP_SHARED, and check consistency and recover as necessary.  (Intended
 *    for kadmind and kadmin.local.)
 *
 * Returns 0 on success else failure.
 */
krb5_error_code
ulog_map(krb5_context context, const char *logname, uint32_t ulogentries,
         int caller, char **db_args)
{
    struct stat st;
    krb5_error_code retval;
    uint32_t ulog_filesize;
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog = NULL;
    int ulogfd = -1;

    ulog_filesize = sizeof(kdb_hlog_t);

    if (stat(logname, &st) == -1) {
        /* File doesn't exist so we exit with kproplog. */
        if (caller == FKPROPLOG)
            return errno;

        ulogfd = open(logname, O_RDWR | O_CREAT, 0600);
        if (ulogfd == -1)
            return errno;

        if (lseek(ulogfd, 0L, SEEK_CUR) == -1)
            return errno;

        if (caller == FKADMIND || caller == FKCOMMAND)
            ulog_filesize += ulogentries * ULOG_BLOCK;

        if (extend_file_to(ulogfd, ulog_filesize) < 0)
            return errno;
    } else {
        ulogfd = open(logname, O_RDWR, 0600);
        if (ulogfd == -1)
            return errno;
    }

    if (caller == FKPROPLOG) {
        if (fstat(ulogfd, &st) < 0) {
            close(ulogfd);
            return errno;
        }
        ulog_filesize = st.st_size;

        ulog = mmap(0, ulog_filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                    ulogfd, 0);
    } else {
        /* kadmind, kpropd, & kcommands should udpate stores. */
        ulog = mmap(0, MAXLOGLEN, PROT_READ | PROT_WRITE, MAP_SHARED,
                    ulogfd, 0);
    }

    if (ulog == MAP_FAILED) {
        /* Can't map update log file to memory. */
        close(ulogfd);
        return errno;
    }

    if (!context->kdblog_context) {
        log_ctx = k5alloc(sizeof(kdb_log_context), &retval);
        if (log_ctx == NULL)
            return retval;
        memset(log_ctx, 0, sizeof(*log_ctx));
        context->kdblog_context = log_ctx;
    } else {
        log_ctx = context->kdblog_context;
    }
    log_ctx->ulog = ulog;
    log_ctx->ulogentries = ulogentries;
    log_ctx->ulogfd = ulogfd;

    retval = lock_ulog(context, KRB5_LOCKMODE_EXCLUSIVE);
    if (retval)
        return retval;

    if (ulog->kdb_hmagic != KDB_ULOG_HDR_MAGIC && ulog->kdb_hmagic != 0) {
        unlock_ulog(context);
        return KRB5_LOG_CORRUPT;
    }

    if (ulog->kdb_hmagic != KDB_ULOG_HDR_MAGIC) {
        reset_header(ulog);
        if (caller != FKPROPLOG)
            sync_header(ulog);
        unlock_ulog(context);
        return 0;
    }

    if (caller == FKPROPLOG || caller == FKPROPD) {
        /* kproplog and kpropd don't need to do anything else. */
        unlock_ulog(context);
        return 0;
    }

    assert(caller == FKADMIND || caller == FKCOMMAND);

    /* Reinit ulog if the log is being truncated or expanded after we have
     * circled. */
    if (ulog->kdb_num != ulogentries) {
        if (ulog->kdb_num != 0 &&
            (ulog->kdb_last_sno > ulog->kdb_num ||
             ulog->kdb_num > ulogentries)) {
            reset_header(ulog);
            sync_header(ulog);
        }

        /* Expand ulog if we have specified a greater size. */
        if (ulog->kdb_num < ulogentries) {
            ulog_filesize += ulogentries * ulog->kdb_block;

            if (extend_file_to(ulogfd, ulog_filesize) < 0) {
                unlock_ulog(context);
                return errno;
            }
        }
    }
    unlock_ulog(context);

    return 0;
}

/* Get the last set of updates seen, (last+1) to n is returned. */
krb5_error_code
ulog_get_entries(krb5_context context, const kdb_last_t *last,
                 kdb_incr_result_t *ulog_handle)
{
    XDR xdrs;
    kdb_ent_header_t *indx_log;
    kdb_incr_update_t *upd;
    unsigned int indx, count;
    uint32_t sno;
    krb5_error_code retval;
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog = NULL;
    uint32_t ulogentries;

    INIT_ULOG(context);
    ulogentries = log_ctx->ulogentries;

    retval = lock_ulog(context, KRB5_LOCKMODE_SHARED);
    if (retval)
        return retval;

    /* If another process terminated mid-update, reset the ulog and force full
     * resyncs. */
    if (ulog->kdb_state != KDB_STABLE)
        reset_header(ulog);

    ulog_handle->ret = get_sno_status(log_ctx, last);
    if (ulog_handle->ret != UPDATE_OK)
        goto cleanup;

    sno = last->last_sno;
    count = ulog->kdb_last_sno - sno;
    upd = calloc(count, sizeof(kdb_incr_update_t));
    if (upd == NULL) {
        ulog_handle->ret = UPDATE_ERROR;
        retval = ENOMEM;
        goto cleanup;
    }
    ulog_handle->updates.kdb_ulog_t_val = upd;

    for (; sno < ulog->kdb_last_sno; sno++) {
        indx = sno % ulogentries;
        indx_log = INDEX(ulog, indx);

        memset(upd, 0, sizeof(kdb_incr_update_t));
        xdrmem_create(&xdrs, (char *)indx_log->entry_data,
                      indx_log->kdb_entry_size, XDR_DECODE);
        if (!xdr_kdb_incr_update_t(&xdrs, upd)) {
            ulog_handle->ret = UPDATE_ERROR;
            retval = KRB5_LOG_CONV;
            goto cleanup;
        }

        /* Mark commitment since we didn't want to decode and encode the incr
         * update record the first time. */
        upd->kdb_commit = indx_log->kdb_commit;
        upd++;
    }

    ulog_handle->updates.kdb_ulog_t_len = count;

    ulog_handle->lastentry.last_sno = ulog->kdb_last_sno;
    ulog_handle->lastentry.last_time.seconds = ulog->kdb_last_time.seconds;
    ulog_handle->lastentry.last_time.useconds = ulog->kdb_last_time.useconds;
    ulog_handle->ret = UPDATE_OK;

cleanup:
    unlock_ulog(context);
    return retval;
}

krb5_error_code
ulog_set_role(krb5_context ctx, iprop_role role)
{
    if (ctx->kdblog_context == NULL) {
        ctx->kdblog_context = calloc(1, sizeof(*ctx->kdblog_context));
        if (ctx->kdblog_context == NULL)
            return ENOMEM;
    }
    ctx->kdblog_context->iproprole = role;
    return 0;
}

update_status_t
ulog_get_sno_status(krb5_context context, const kdb_last_t *last)
{
    update_status_t status;

    if (lock_ulog(context, KRB5_LOCKMODE_SHARED) != 0)
        return UPDATE_ERROR;
    status = get_sno_status(context->kdblog_context, last);
    unlock_ulog(context);
    return status;
}

krb5_error_code
ulog_get_last(krb5_context context, kdb_last_t *last_out)
{
    krb5_error_code ret;
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog;

    INIT_ULOG(context);
    ret = lock_ulog(context, KRB5_LOCKMODE_SHARED);
    if (ret)
        return ret;
    last_out->last_sno = log_ctx->ulog->kdb_last_sno;
    last_out->last_time = log_ctx->ulog->kdb_last_time;
    unlock_ulog(context);
    return 0;
}

krb5_error_code
ulog_set_last(krb5_context context, const kdb_last_t *last)
{
    krb5_error_code ret;
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog;

    INIT_ULOG(context);
    ret = lock_ulog(context, KRB5_LOCKMODE_EXCLUSIVE);
    if (ret)
        return ret;
    ulog->kdb_last_sno = last->last_sno;
    ulog->kdb_last_time = last->last_time;
    sync_header(ulog);
    unlock_ulog(context);
    return 0;
}
