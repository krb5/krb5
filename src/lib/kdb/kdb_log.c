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

static int extend_file_to(int fd, unsigned int new_size);

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

krb5_error_code
ulog_lock(krb5_context ctx, int mode)
{
    kdb_log_context *log_ctx = NULL;
    kdb_hlog_t *ulog = NULL;

    if (ctx == NULL)
        return KRB5_LOG_ERROR;
    if (ctx->kdblog_context == NULL ||
        ctx->kdblog_context->iproprole == IPROP_NULL)
        return 0;
    INIT_ULOG(ctx);
    return krb5_lock_file(ctx, log_ctx->ulogfd, mode);
}

/* Sync update entry to disk. */
static krb5_error_code
ulog_sync_update(kdb_hlog_t *ulog, kdb_ent_header_t *upd)
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
void
ulog_sync_header(kdb_hlog_t *ulog)
{

    if (!pagesize)
        pagesize = getpagesize();

    if (msync((caddr_t)ulog, pagesize, MS_SYNC)) {
        /* Couldn't sync to disk, let's panic. */
        syslog(LOG_ERR, _("ulog_sync_header: could not sync to disk"));
        abort();
    }
}

/*
 * Resize the array elements.  We reinitialize the update log rather than
 * unrolling the the log and copying it over to a temporary log for obvious
 * performance reasons.  Slaves will subsequently do a full resync, but the
 * need for resizing should be very small.
 */
static krb5_error_code
ulog_resize(kdb_hlog_t *ulog, uint32_t ulogentries, int ulogfd,
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
    ulog_sync_header(ulog);

    /* Expand log considering new block size. */
    if (extend_file_to(ulogfd, new_size) < 0)
        return errno;

    return 0;
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
    ulogentries = log_ctx->ulogentries;
    ulogfd = log_ctx->ulogfd;

    if (upd == NULL)
        return KRB5_LOG_ERROR;

    time_current(&ktime);

    upd_size = xdr_sizeof((xdrproc_t)xdr_kdb_incr_update_t, upd);

    recsize = sizeof(kdb_ent_header_t) + upd_size;

    if (recsize > ulog->kdb_block) {
        retval = ulog_resize(ulog, ulogentries, ulogfd, recsize);
        if (retval)
            return retval;
    }

    cur_sno = ulog->kdb_last_sno;

    /*
     * If we need to, wrap our sno around to 1.  A slaves will do a full resync
     * since its sno will be out of range of the ulog (or in extreme cases,
     * its timestamp won't match).
     */
    if (cur_sno == (kdb_sno_t)-1)
        cur_sno = 1;
    else
        cur_sno++;

    /* Squirrel this away for finish_update() to index. */
    upd->kdb_entry_sno = cur_sno;

    i = (cur_sno - 1) % ulogentries;
    indx_log = (kdb_ent_header_t *)INDEX(ulog, i);

    memset(indx_log, 0, ulog->kdb_block);
    indx_log->kdb_umagic = KDB_ULOG_MAGIC;
    indx_log->kdb_entry_size = upd_size;
    indx_log->kdb_entry_sno = cur_sno;
    indx_log->kdb_time = upd->kdb_time = ktime;
    indx_log->kdb_commit = upd->kdb_commit = FALSE;

    ulog->kdb_state = KDB_UNSTABLE;

    xdrmem_create(&xdrs, (char *)indx_log->entry_data,
                  indx_log->kdb_entry_size, XDR_ENCODE);
    if (!xdr_kdb_incr_update_t(&xdrs, upd))
        return KRB5_LOG_CONV;

    retval = ulog_sync_update(ulog, indx_log);
    if (retval)
        return retval;

    if (ulog->kdb_num < ulogentries)
        ulog->kdb_num++;

    ulog->kdb_last_sno = cur_sno;
    ulog->kdb_last_time = ktime;

    if (cur_sno > ulogentries) {
        /* Once we've circled, kdb_first_sno is the sno of the next entry. */
        i = upd->kdb_entry_sno % ulogentries;
        indx_log = (kdb_ent_header_t *)INDEX(ulog, i);
        ulog->kdb_first_sno = indx_log->kdb_entry_sno;
        ulog->kdb_first_time = indx_log->kdb_time;
    } else if (cur_sno == 1) {
        /* This is the first update, or we wrapped. */
        ulog->kdb_first_sno = 1;
        ulog->kdb_first_time = indx_log->kdb_time;
    }

    ulog_sync_header(ulog);
    return 0;
}

/* Mark the log entry as committed and sync the memory mapped log to file. */
krb5_error_code
ulog_finish_update(krb5_context context, kdb_incr_update_t *upd)
{
    krb5_error_code retval;
    kdb_ent_header_t *indx_log;
    unsigned int i;
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog = NULL;
    uint32_t ulogentries;

    INIT_ULOG(context);
    ulogentries = log_ctx->ulogentries;

    i = (upd->kdb_entry_sno - 1) % ulogentries;

    indx_log = (kdb_ent_header_t *)INDEX(ulog, i);
    indx_log->kdb_commit = TRUE;

    ulog->kdb_state = KDB_STABLE;

    retval = ulog_sync_update(ulog, indx_log);
    if (retval)
        return retval;

    ulog_sync_header(ulog);
    return 0;
}

/* Set the header log details on the slave and sync it to file. */
static void
ulog_finish_update_slave(kdb_hlog_t *ulog, kdb_last_t lastentry)
{
    ulog->kdb_last_sno = lastentry.last_sno;
    ulog->kdb_last_time = lastentry.last_time;
    ulog_sync_header(ulog);
}

/* Delete an entry to the update log. */
krb5_error_code
ulog_delete_update(krb5_context context, kdb_incr_update_t *upd)
{
    upd->kdb_deleted = TRUE;
    return ulog_add_update(context, upd);
}

/* Used by the slave to update its hash db from* the incr update log.  Must be
 * called with lock held. */
krb5_error_code
ulog_replay(krb5_context context, kdb_incr_result_t *incr_ret, char **db_args)
{
    krb5_db_entry *entry = NULL;
    kdb_incr_update_t *upd = NULL, *fupd;
    int i, no_of_updates;
    krb5_error_code retval;
    krb5_principal dbprinc;
    kdb_last_t errlast;
    char *dbprincstr;
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog = NULL;

    INIT_ULOG(context);

    no_of_updates = incr_ret->updates.kdb_ulog_t_len;
    upd = incr_ret->updates.kdb_ulog_t_val;
    fupd = upd;

    /* We reset last_sno and last_time to 0, if krb5_db2_db_put_principal or
     * krb5_db2_db_delete_principal fail. */
    errlast.last_sno = (unsigned int)0;
    errlast.last_time.seconds = (unsigned int)0;
    errlast.last_time.useconds = (unsigned int)0;

    retval = krb5_db_open(context, db_args,
                          KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_ADMIN);
    if (retval)
        goto cleanup;

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

cleanup:
    if (fupd)
        ulog_free_entries(fupd, no_of_updates);

    if (retval)
        ulog_finish_update_slave(ulog, errlast);
    else
        ulog_finish_update_slave(ulog, incr_ret->lastentry);

    return retval;
}

static void
ulog_reset(kdb_hlog_t *ulog)
{
    memset(ulog, 0, sizeof(*ulog));
    ulog->kdb_hmagic = KDB_ULOG_HDR_MAGIC;
    ulog->db_version_num = KDB_VERSION;
    ulog->kdb_state = KDB_STABLE;
    ulog->kdb_block = ULOG_BLOCK;
    time_current(&ulog->kdb_last_time);
}

/* Reinitialize the log header.  Locking is the caller's responsibility. */
void
ulog_init_header(krb5_context context)
{
    kdb_log_context *log_ctx;
    kdb_hlog_t *ulog;

    INIT_ULOG(context);
    ulog_reset(ulog);
    ulog_sync_header(ulog);
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
 *  - FKLOAD
 *
 *    Create if need be, initialize (even if the ulog was already present), map
 *    as MAP_SHARED.  (Intended for kdb5_util load of iprop dump.)
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

    retval = ulog_lock(context, KRB5_LOCKMODE_EXCLUSIVE);
    if (retval)
        return retval;

    if (ulog->kdb_hmagic != KDB_ULOG_HDR_MAGIC && ulog->kdb_hmagic != 0) {
        ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return KRB5_LOG_CORRUPT;
    }

    if (ulog->kdb_hmagic != KDB_ULOG_HDR_MAGIC || caller == FKLOAD) {
        ulog_reset(ulog);
        if (caller != FKPROPLOG)
            ulog_sync_header(ulog);
        ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return 0;
    }

    if (caller == FKPROPLOG || caller == FKPROPD) {
        /* kproplog and kpropd don't need to do anything else. */
        ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return 0;
    }

    assert(caller == FKADMIND || caller == FKCOMMAND);

    /* Reinit ulog if the log is being truncated or expanded after we have
     * circled. */
    if (ulog->kdb_num != ulogentries) {
        if (ulog->kdb_num != 0 &&
            (ulog->kdb_last_sno > ulog->kdb_num ||
             ulog->kdb_num > ulogentries)) {
            ulog_reset(ulog);
            ulog_sync_header(ulog);
        }

        /* Expand ulog if we have specified a greater size. */
        if (ulog->kdb_num < ulogentries) {
            ulog_filesize += ulogentries * ulog->kdb_block;

            if (extend_file_to(ulogfd, ulog_filesize) < 0) {
                ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
                return errno;
            }
        }
    }
    ulog_lock(context, KRB5_LOCKMODE_UNLOCK);

    return 0;
}

/* Get the last set of updates seen, (last+1) to n is returned. */
krb5_error_code
ulog_get_entries(krb5_context context, kdb_last_t last,
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

    retval = ulog_lock(context, KRB5_LOCKMODE_SHARED);
    if (retval)
        return retval;

    /* Check to make sure we don't have a corrupt ulog first. */
    if (ulog->kdb_state == KDB_CORRUPT) {
        ulog_handle->ret = UPDATE_ERROR;
        (void)ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return KRB5_LOG_CORRUPT;
    }

    /*
     * We need to lock out other processes here, such as kadmin.local, since we
     * are looking at the last_sno and looking up updates.  So we can share
     * with other readers.
     */
    retval = krb5_db_lock(context, KRB5_LOCKMODE_SHARED);
    if (retval) {
        (void)ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return retval;
    }

    /* If we have the same sno and timestamp, return a nil update.  If a
     * different timestamp, the sno was reused and we need a full resync. */
    if (last.last_sno == ulog->kdb_last_sno) {
        ulog_handle->ret = time_equal(&last.last_time, &ulog->kdb_last_time) ?
            UPDATE_NIL : UPDATE_FULL_RESYNC_NEEDED;
        goto cleanup;
    }

    /* We may have overflowed the update log or shrunk the log, or the client
     * may have created its ulog. */
    if (last.last_sno > ulog->kdb_last_sno ||
        last.last_sno < ulog->kdb_first_sno) {
        ulog_handle->lastentry.last_sno = ulog->kdb_last_sno;
        ulog_handle->ret = UPDATE_FULL_RESYNC_NEEDED;
        goto cleanup;
    }

    sno = last.last_sno;
    indx = (sno - 1) % ulogentries;
    indx_log = (kdb_ent_header_t *)INDEX(ulog, indx);

    if (!time_equal(&indx_log->kdb_time, &last.last_time)) {
        /* We have time stamp mismatch or we no longer have the slave's last
         * sno, so we brute force it. */
        ulog_handle->ret = UPDATE_FULL_RESYNC_NEEDED;
        goto cleanup;
    }

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
        indx_log = (kdb_ent_header_t *)INDEX(ulog, indx);

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
    (void)ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
    (void)krb5_db_unlock(context);
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
