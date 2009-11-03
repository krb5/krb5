/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/ccache/cc_keyring.c
 *
 * Copyright (c) 2006
 * The Regents of the University of Michigan
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 *
 */
/*
 * Copyright 1990,1991,1992,1993,1994,2000,2004 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Original stdio support copyright 1995 by Cygnus Support.
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
 */

/*
 * Implementation of a credentials cache stored in the Linux keyring facility
 *
 * Some assumptions:
 *
 *      - A credentials cache "file" == a keyring with separate keys
 *        for the information in the ccache (see below)
 *      - A credentials cache keyring will contain only keys,
 *        not other keyrings
 *      - Each Kerberos ticket will have its own key within the ccache keyring
 *      - The principal information for the ccache is stored in a
 *        special key, which is not counted in the 'numkeys' count
 */

#include "cc-int.h"

#ifdef USE_KEYRING_CCACHE

#include <errno.h>
#include <keyutils.h>

#ifdef DEBUG
#define KRCC_DEBUG          1
#endif

#if KRCC_DEBUG
void debug_print(char *fmt, ...);       /* prototype to silence warning */
#include <syslog.h>
#define DEBUG_PRINT(x) debug_print x
void
debug_print(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
#ifdef DEBUG_STDERR
    vfprintf(stderr, fmt, ap);
#else
    vsyslog(LOG_ERR, fmt, ap);
#endif
    va_end(ap);
}
#else
#define DEBUG_PRINT(x)
#endif

/*
 * We always use "user" key type
 */
#define KRCC_KEY_TYPE_USER "user"

/*
 * We create ccaches as separate keyrings
 */
#define KRCC_KEY_TYPE_KEYRING "keyring"

/*
 * Special name of the key within a ccache keyring
 * holding principal information
 */
#define KRCC_SPEC_PRINC_KEYNAME "__krb5_princ__"

/*
 * XXX The following two really belong in some external
 * header since outside programs will need to use these
 * same names.
 */
/*
 * Special name for key to communicate key serial numbers
 * This is used by the Linux gssd process to pass the
 * user's keyring values it gets in an upcall.
 * The format of the contents should be
 *    <session_key>:<process_key>:<thread_key>
 */
#define KRCC_SPEC_IDS_KEYNAME "_gssd_keyring_ids_"

/*
 * Special name for the key to communicate the name(s)
 * of credentials caches to be used for requests.
 * This should currently contain a single name, but
 * in the future may contain a list that may be
 * intelligently chosen from.
 */
#define KRCC_SPEC_CCACHE_SET_KEYNAME "__krb5_cc_set__"

#define KRB5_OK 0

/* Hopefully big enough to hold a serialized credential */
#define GUESS_CRED_SIZE 4096

#define ALLOC(NUM,TYPE)                         \
    (((NUM) <= (((size_t)0-1)/ sizeof(TYPE)))   \
     ? (TYPE *) calloc((NUM), sizeof(TYPE))     \
     : (errno = ENOMEM,(TYPE *) 0))

#define CHECK_N_GO(ret, errdest) if (ret != KRB5_OK) goto errdest
#define CHECK(ret) if (ret != KRB5_OK) goto errout
#define CHECK_OUT(ret) if (ret != KRB5_OK) return ret

typedef struct krb5_krcc_ring_ids {
    key_serial_t        session;
    key_serial_t        process;
    key_serial_t        thread;
} krb5_krcc_ring_ids_t;

typedef struct _krb5_krcc_cursor
{
    int     numkeys;
    int     currkey;
    key_serial_t princ_id;
    key_serial_t *keys;
} *krb5_krcc_cursor;

/*
 * This represents a credentials cache "file"
 * where ring_id is the keyring serial number for
 * this credentials cache "file".  Each key
 * in the keyring contains a separate key.
 */
typedef struct _krb5_krcc_data
{
    char   *name;               /* Name for this credentials cache */
    k5_cc_mutex lock;           /* synchronization */
    key_serial_t parent_id;     /* parent keyring of this ccache keyring */
    key_serial_t ring_id;       /* keyring representing ccache */
    key_serial_t princ_id;      /* key holding principal info */
    int     numkeys;            /* # of keys in this ring
                                 * (does NOT include principal info) */
    krb5_timestamp changetime;
} krb5_krcc_data;

/* Passed internally to assure we don't go past the bounds of our buffer */
typedef struct _krb5_krcc_buffer_cursor
{
    char   *bpp;
    char   *endp;
} krb5_krcc_bc;

/* Global mutex */
k5_cc_mutex krb5int_krcc_mutex = K5_CC_MUTEX_PARTIAL_INITIALIZER;

/*
 * Internal functions (exported via the krb5_krcc_ops)
 */

extern const krb5_cc_ops krb5_krcc_ops;

static const char *KRB5_CALLCONV krb5_krcc_get_name
(krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_krcc_resolve
(krb5_context, krb5_ccache * id, const char *residual);

static krb5_error_code KRB5_CALLCONV krb5_krcc_generate_new
(krb5_context, krb5_ccache * id);

static krb5_error_code KRB5_CALLCONV krb5_krcc_initialize
(krb5_context, krb5_ccache id, krb5_principal princ);

static krb5_error_code KRB5_CALLCONV krb5_krcc_destroy
(krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_krcc_close
(krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_krcc_store
(krb5_context, krb5_ccache id, krb5_creds * creds);

static krb5_error_code KRB5_CALLCONV krb5_krcc_retrieve
(krb5_context, krb5_ccache id, krb5_flags whichfields,
 krb5_creds * mcreds, krb5_creds * creds);

static krb5_error_code KRB5_CALLCONV krb5_krcc_get_principal
(krb5_context, krb5_ccache id, krb5_principal * princ);

static krb5_error_code KRB5_CALLCONV krb5_krcc_start_seq_get
(krb5_context, krb5_ccache id, krb5_cc_cursor * cursor);

static krb5_error_code KRB5_CALLCONV krb5_krcc_next_cred
(krb5_context, krb5_ccache id, krb5_cc_cursor * cursor,
 krb5_creds * creds);

static krb5_error_code KRB5_CALLCONV krb5_krcc_end_seq_get
(krb5_context, krb5_ccache id, krb5_cc_cursor * cursor);

static krb5_error_code KRB5_CALLCONV krb5_krcc_remove_cred
(krb5_context context, krb5_ccache cache, krb5_flags flags,
 krb5_creds * creds);

static krb5_error_code KRB5_CALLCONV krb5_krcc_set_flags
(krb5_context, krb5_ccache id, krb5_flags flags);

static krb5_error_code KRB5_CALLCONV krb5_krcc_get_flags
(krb5_context context, krb5_ccache id, krb5_flags * flags);

static krb5_error_code KRB5_CALLCONV krb5_krcc_last_change_time
(krb5_context, krb5_ccache, krb5_timestamp *);

static krb5_error_code KRB5_CALLCONV krb5_krcc_lock
(krb5_context context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_krcc_unlock
(krb5_context context, krb5_ccache id);

/*
 * Internal utility functions
 */

static krb5_error_code krb5_krcc_clearcache
(krb5_context context, krb5_ccache id);

static krb5_error_code krb5_krcc_new_data
(const char *, key_serial_t ring, key_serial_t parent_ring,
 krb5_krcc_data **);

static krb5_error_code krb5_krcc_save_principal
(krb5_context context, krb5_ccache id, krb5_principal princ);

static krb5_error_code krb5_krcc_retrieve_principal
(krb5_context context, krb5_ccache id, krb5_principal * princ);

static int krb5_krcc_get_ring_ids(krb5_krcc_ring_ids_t *p);

/* Routines to parse a key from a keyring into a cred structure */
static krb5_error_code krb5_krcc_parse
(krb5_context, krb5_ccache id, krb5_pointer buf, unsigned int len,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_cred
(krb5_context context, krb5_ccache id, krb5_creds * creds,
 char *payload, int psize);
static krb5_error_code krb5_krcc_parse_principal
(krb5_context context, krb5_ccache id, krb5_principal * princ,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_keyblock
(krb5_context context, krb5_ccache id, krb5_keyblock * keyblock,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_times
(krb5_context context, krb5_ccache id, krb5_ticket_times * t,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_krb5data
(krb5_context context, krb5_ccache id, krb5_data * data,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_int32
(krb5_context context, krb5_ccache id, krb5_int32 * i, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_octet
(krb5_context context, krb5_ccache id, krb5_octet * octet,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_addrs
(krb5_context context, krb5_ccache id, krb5_address *** a,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_addr
(krb5_context context, krb5_ccache id, krb5_address * a,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_authdata
(krb5_context context, krb5_ccache id, krb5_authdata *** ad,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_authdatum
(krb5_context context, krb5_ccache id, krb5_authdata * ad,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_ui_2
(krb5_context, krb5_ccache id, krb5_ui_2 * i, krb5_krcc_bc * bc);

/* Routines to unparse a cred structure into keyring key */
static krb5_error_code krb5_krcc_unparse
(krb5_context, krb5_ccache id, krb5_pointer buf, unsigned int len,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_cred
(krb5_context context, krb5_ccache id, krb5_creds * creds,
 char **datapp, unsigned int *lenptr);
static krb5_error_code krb5_krcc_unparse_principal
(krb5_context, krb5_ccache id, krb5_principal princ, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_keyblock
(krb5_context, krb5_ccache id, krb5_keyblock * keyblock,
 krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_times
(krb5_context, krb5_ccache id, krb5_ticket_times * t, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_krb5data
(krb5_context, krb5_ccache id, krb5_data * data, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_int32
(krb5_context, krb5_ccache id, krb5_int32 i, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_octet
(krb5_context, krb5_ccache id, krb5_int32 i, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_addrs
(krb5_context, krb5_ccache, krb5_address ** a, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_addr
(krb5_context, krb5_ccache, krb5_address * a, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_authdata
(krb5_context, krb5_ccache, krb5_authdata ** ad, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_authdatum
(krb5_context, krb5_ccache, krb5_authdata * ad, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_ui_4
(krb5_context, krb5_ccache id, krb5_ui_4 i, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_ui_2
(krb5_context, krb5_ccache id, krb5_int32 i, krb5_krcc_bc * bc);
static void krb5_krcc_update_change_time
(krb5_krcc_data *);

/* Note the following is a stub function for Linux */
extern krb5_error_code krb5_change_cache(void);

/*
 * Determine how many keys exist in a ccache keyring.
 * Subtracts out the "hidden" key holding the principal information.
 */
static int KRB5_CALLCONV
krb5_krcc_getkeycount(key_serial_t cred_ring)
{
    int res, nkeys;

    res = keyctl_read(cred_ring, NULL, 0);
    if (res > 0)
        nkeys = (res / sizeof(key_serial_t)) - 1;
    else
        nkeys = 0;
    return(nkeys);
}

/*
 * Modifies:
 * id
 *
 * Effects:
 * Creates/refreshes the cred cache id.  If the cache exists, its
 * contents are destroyed.
 *
 * Errors:
 * system errors
 * permission errors
 */

static krb5_error_code KRB5_CALLCONV
krb5_krcc_initialize(krb5_context context, krb5_ccache id,
                     krb5_principal princ)
{
    krb5_error_code kret;

    DEBUG_PRINT(("krb5_krcc_initialize: entered\n"));

    kret = k5_cc_mutex_lock(context, &((krb5_krcc_data *) id->data)->lock);
    if (kret)
        return kret;

    kret = krb5_krcc_clearcache(context, id);
    if (kret != KRB5_OK)
        goto out;

    kret = krb5_krcc_save_principal(context, id, princ);
    if (kret == KRB5_OK)
        krb5_change_cache();

out:
    k5_cc_mutex_unlock(context, &((krb5_krcc_data *) id->data)->lock);
    return kret;
}

/*
 * Modifies:
 * id
 *
 * Effects:
 * Invalidates the id, and frees any resources associated with the cache.
 * (Does NOT destroy the underlying ccache in the keyring.)
 */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_close(krb5_context context, krb5_ccache id)
{
    krb5_krcc_data *d;

    DEBUG_PRINT(("krb5_krcc_close: entered\n"));

    d = (krb5_krcc_data *) id->data;

    free(d->name);
    k5_cc_mutex_destroy(&d->lock);
    free(d);

    free(id);

    return KRB5_OK;
}

/*
 * Modifies:
 * id
 *
 * Effects:
 * Clears out a ccache keyring, unlinking all keys within it
 * (Including the "hidden" key with the principal information)
 *
 * Requires:
 * Must be called with mutex locked.
 *
 * Errors:
 * system errors
 */

static  krb5_error_code
krb5_krcc_clearcache(krb5_context context, krb5_ccache id)
{
    krb5_krcc_data *d;
    int     res;

    k5_cc_mutex_assert_locked(context, &((krb5_krcc_data *) id->data)->lock);

    d = (krb5_krcc_data *) id->data;

    DEBUG_PRINT(("krb5_krcc_clearcache: ring_id %d, princ_id %d, "
                 "numkeys is %d\n", d->ring_id, d->princ_id, d->numkeys));

    res = keyctl_clear(d->ring_id);
    if (res != 0) {
        return errno;
    }
    d->numkeys = 0;
    d->princ_id = 0;
    krb5_krcc_update_change_time(d);

    return KRB5_OK;
}

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_destroy(krb5_context context, krb5_ccache id)
{
    krb5_error_code kret;
    krb5_krcc_data *d;
    int     res;

    DEBUG_PRINT(("krb5_krcc_destroy: entered\n"));

    d = (krb5_krcc_data *) id->data;

    kret = k5_cc_mutex_lock(context, &d->lock);
    if (kret)
        return kret;

    krb5_krcc_clearcache(context, id);
    free(d->name);
    res = keyctl_unlink(d->ring_id, d->parent_id);
    if (res < 0) {
        kret = errno;
        DEBUG_PRINT(("krb5_krcc_destroy: unlinking key %d from ring %d: %s",
                     d->ring_id, d->parent_id, error_message(errno)));
        goto cleanup;
    }
cleanup:
    k5_cc_mutex_unlock(context, &d->lock);
    k5_cc_mutex_destroy(&d->lock);
    free(d);
    free(id);

    krb5_change_cache();

    return KRB5_OK;
}


/*
 * Requires:
 * residual is a legal path name, and a null-terminated string
 *
 * Modifies:
 * id
 *
 * Effects:
 * creates a cred cache that will reside in the keyring with
 * a name of <residual>.
 *
 * Returns:
 * A filled in krb5_ccache structure "id".
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 *              krb5_ccache.  id is undefined.
 * permission errors
 */

static krb5_error_code KRB5_CALLCONV
krb5_krcc_resolve(krb5_context context, krb5_ccache * id, const char *full_residual)
{
    krb5_ccache lid;
    krb5_error_code kret;
    krb5_krcc_data *d;
    key_serial_t key;
    key_serial_t pkey = 0;
    int     nkeys = 0;
    int     res;
    krb5_krcc_ring_ids_t ids;
    key_serial_t ring_id;
    const char *residual;

    DEBUG_PRINT(("krb5_krcc_resolve: entered with name '%s'\n",
                 full_residual));

    res = krb5_krcc_get_ring_ids(&ids);
    if (res) {
        kret = EINVAL;
        DEBUG_PRINT(("krb5_krcc_resolve: Error getting ring id values!\n"));
        return kret;
    }

    if (strncmp(full_residual, "thread:", 7) == 0) {
        residual = full_residual + 7;
        ring_id = ids.thread;
    } else if (strncmp(full_residual, "process:", 8) == 0) {
        residual = full_residual + 8;
        ring_id = ids.process;
    } else {
        residual = full_residual;
        ring_id = ids.session;
    }

    DEBUG_PRINT(("krb5_krcc_resolve: searching ring %d for residual '%s'\n",
                 ring_id, residual));

    /*
     * Use keyctl_search instead of request_key. If we're supposed
     * to be looking for a process ccache, we shouldn't find a
     * thread ccache.
     * XXX But should we look in the session ring if we don't find it
     * in the process ring?  Same goes for thread.  Should we look in
     * the process and session rings if not found in the thread ring?
     *
     */
    key = keyctl_search(ring_id, KRCC_KEY_TYPE_KEYRING, residual, 0);
    if (key < 0) {
        key = add_key(KRCC_KEY_TYPE_KEYRING, residual, NULL, 0, ring_id);
        if (key < 0) {
            kret = errno;
            DEBUG_PRINT(("krb5_krcc_resolve: Error adding new "
                         "keyring '%s': %s\n", residual, strerror(errno)));
            return kret;
        }
        DEBUG_PRINT(("krb5_krcc_resolve: new keyring '%s', "
                     "key %d, added to keyring %d\n",
                     residual, key, ring_id));
    } else {
        DEBUG_PRINT(("krb5_krcc_resolve: found existing "
                     "key %d, with name '%s' in keyring %d\n",
                     key, residual, ring_id));
        /* Determine key containing principal information */
        pkey = keyctl_search(key, KRCC_KEY_TYPE_USER,
                             KRCC_SPEC_PRINC_KEYNAME, 0);
        if (pkey < 0) {
            DEBUG_PRINT(("krb5_krcc_resolve: Error locating principal "
                         "info for existing ccache in ring %d: %s\n",
                         key, strerror(errno)));
            pkey = 0;
        }
        /* Determine how many keys exist */
        nkeys = krb5_krcc_getkeycount(key);
    }

    lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
    if (lid == NULL)
        return KRB5_CC_NOMEM;


    kret = krb5_krcc_new_data(residual, key, ring_id, &d);
    if (kret) {
        free(lid);
        return kret;
    }

    DEBUG_PRINT(("krb5_krcc_resolve: ring_id %d, princ_id %d, "
                 "nkeys %d\n", key, pkey, nkeys));
    d->princ_id = pkey;
    d->numkeys = nkeys;
    lid->ops = &krb5_krcc_ops;
    lid->data = d;
    lid->magic = KV5M_CCACHE;
    *id = lid;
    return KRB5_OK;
}

/*
 * Effects:
 * Prepares for a sequential search of the credentials cache.
 * Returns a krb5_cc_cursor to be used with krb5_krcc_next_cred and
 * krb5_krcc_end_seq_get.
 *
 * If the cache is modified between the time of this call and the time
 * of the final krb5_krcc_end_seq_get, the results are undefined.
 *
 * Errors:
 * KRB5_CC_NOMEM
 * system errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_start_seq_get(krb5_context context, krb5_ccache id,
                        krb5_cc_cursor * cursor)
{
    krb5_krcc_cursor krcursor;
    krb5_error_code kret;
    krb5_krcc_data *d;
    unsigned int size;
    int     res;

    DEBUG_PRINT(("krb5_krcc_start_seq_get: entered\n"));

    d = id->data;
    kret = k5_cc_mutex_lock(context, &d->lock);
    if (kret)
        return kret;

    /*
     * Determine how many keys currently exist and update numkeys.
     * We cannot depend on the current value of numkeys because
     * the ccache may have been updated elsewhere
     */
    d->numkeys = krb5_krcc_getkeycount(d->ring_id);

    size = sizeof(*krcursor) + ((d->numkeys + 1) * sizeof(key_serial_t));

    krcursor = (krb5_krcc_cursor) malloc(size);
    if (krcursor == NULL) {
        k5_cc_mutex_unlock(context, &d->lock);
        return KRB5_CC_NOMEM;
    }

    krcursor->keys = (key_serial_t *) ((char *) krcursor + sizeof(*krcursor));
    res = keyctl_read(d->ring_id, (char *) krcursor->keys,
                      ((d->numkeys + 1) * sizeof(key_serial_t)));
    if (res < 0 || res > ((d->numkeys + 1) * sizeof(key_serial_t))) {
        DEBUG_PRINT(("Read %d bytes from keyring, numkeys %d: %s\n",
                     res, d->numkeys, strerror(errno)));
        free(krcursor);
        k5_cc_mutex_unlock(context, &d->lock);
        return KRB5_CC_IO;
    }

    krcursor->numkeys = d->numkeys;
    krcursor->currkey = 0;
    krcursor->princ_id = d->princ_id;

    k5_cc_mutex_unlock(context, &d->lock);
    *cursor = (krb5_cc_cursor) krcursor;
    return KRB5_OK;
}

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_krcc_start_seq_get.
 *
 * Modifes:
 * cursor, creds
 *
 * Effects:
 * Fills in creds with the "next" credentals structure from the cache
 * id.  The actual order the creds are returned in is arbitrary.
 * Space is allocated for the variable length fields in the
 * credentials structure, so the object returned must be passed to
 * krb5_destroy_credential.
 *
 * The cursor is updated for the next call to krb5_krcc_next_cred.
 *
 * Errors:
 * system errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_next_cred(krb5_context context, krb5_ccache id,
                    krb5_cc_cursor * cursor, krb5_creds * creds)
{
    krb5_krcc_cursor krcursor;
    krb5_error_code kret;
    int     psize;
    void   *payload = NULL;

    DEBUG_PRINT(("krb5_krcc_next_cred: entered\n"));

    /*
     * The cursor has the entire list of keys.
     * (Note that we don't support _remove_cred.)
     */
    krcursor = (krb5_krcc_cursor) * cursor;
    if (krcursor == NULL)
        return KRB5_CC_END;
    memset(creds, 0, sizeof(krb5_creds));

    /* If we're pointing past the end of the keys array, there are no more */
    if (krcursor->currkey > krcursor->numkeys)
        return KRB5_CC_END;

    /* If we're pointing at the entry with the principal, skip it */
    if (krcursor->keys[krcursor->currkey] == krcursor->princ_id) {
        krcursor->currkey++;
        /* Check if we have now reached the end */
        if (krcursor->currkey > krcursor->numkeys)
            return KRB5_CC_END;
    }

    /* Read the key, the right size buffer will ba allocated and returned */
    psize = keyctl_read_alloc(krcursor->keys[krcursor->currkey], &payload);
    if (psize == -1) {
        DEBUG_PRINT(("Error reading key %d: %s\n",
                     krcursor->keys[krcursor->currkey],
                     strerror(errno)));
        kret = KRB5_FCC_NOFILE;
        goto freepayload;
    }
    krcursor->currkey++;

    kret = krb5_krcc_parse_cred(context, id, creds, payload, psize);

freepayload:
    if (payload) free(payload);
    return kret;
}

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_krcc_start_seq_get.
 *
 * Modifies:
 * id, cursor
 *
 * Effects:
 * Finishes sequential processing of the keyring credentials ccache id,
 * and invalidates the cursor (it must never be used after this call).
 */
/* ARGSUSED */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_end_seq_get(krb5_context context, krb5_ccache id,
                      krb5_cc_cursor * cursor)
{
    DEBUG_PRINT(("krb5_krcc_end_seq_get: entered\n"));

    free(*cursor);
    *cursor = 0L;
    return KRB5_OK;
}

/* Utility routine: Creates the back-end data for a keyring cache.

   Call with the global list lock held.  */
static  krb5_error_code
krb5_krcc_new_data(const char *name, key_serial_t ring,
                   key_serial_t parent_ring, krb5_krcc_data ** datapp)
{
    krb5_error_code kret;
    krb5_krcc_data *d;

    d = malloc(sizeof(krb5_krcc_data));
    if (d == NULL)
        return KRB5_CC_NOMEM;

    kret = k5_cc_mutex_init(&d->lock);
    if (kret) {
        free(d);
        return kret;
    }

    d->name = strdup(name);
    if (d->name == NULL) {
        k5_cc_mutex_destroy(&d->lock);
        free(d);
        return KRB5_CC_NOMEM;
    }
    d->princ_id = 0;
    d->ring_id = ring;
    d->parent_id = parent_ring;
    d->numkeys = 0;
    d->changetime = 0;
    krb5_krcc_update_change_time(d);

    *datapp = d;
    return 0;
}

/*
 * Effects:
 * Creates a new keyring cred cache whose name is guaranteed to be
 * unique.
 *
 * Returns:
 * The filled in krb5_ccache id.
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 *              krb5_ccache.  id is undefined.
 */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_generate_new(krb5_context context, krb5_ccache * id)
{
    krb5_ccache lid;
    char uniquename[8];
    krb5_error_code kret;
    krb5_krcc_data *d;
    key_serial_t ring_id = KEY_SPEC_SESSION_KEYRING;
    key_serial_t key;

    DEBUG_PRINT(("krb5_krcc_generate_new: entered\n"));

    /* Allocate memory */
    lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
    if (lid == NULL)
        return KRB5_CC_NOMEM;

    lid->ops = &krb5_krcc_ops;

    kret = k5_cc_mutex_lock(context, &krb5int_krcc_mutex);
    if (kret) {
        free(lid);
        return kret;
    }

/* XXX These values are platform-specific and should not be here! */
/* XXX There is a bug in FC5 where these are not included in errno.h  */
#ifndef ENOKEY
#define ENOKEY          126     /* Required key not available */
#endif
#ifndef EKEYEXPIRED
#define EKEYEXPIRED     127     /* Key has expired */
#endif
#ifndef EKEYREVOKED
#define EKEYREVOKED     128     /* Key has been revoked */
#endif
#ifndef EKEYREJECTED
#define EKEYREJECTED    129     /* Key was rejected by service */
#endif

    /*
     * Loop until we successfully create a new ccache keyring with
     * a unique name, or we get an error.
     */
    while (1) {
        kret = krb5int_random_string(context, uniquename, sizeof(uniquename));
        if (kret) {
            k5_cc_mutex_unlock(context, &krb5int_krcc_mutex);
            free(lid);
            return kret;
        }

        DEBUG_PRINT(("krb5_krcc_generate_new: searching for name '%s'\n",
                     uniquename));
        key = keyctl_search(ring_id, KRCC_KEY_TYPE_KEYRING, uniquename, 0);
        /*XXX*/ DEBUG_PRINT(("krb5_krcc_generate_new: after searching for '%s', key = %d, errno = %d\n", uniquename, key, errno));
        if (key < 0 && errno == ENOKEY) {
            /* name does not already exist, create it to reserve the name */
            key = add_key(KRCC_KEY_TYPE_KEYRING, uniquename, NULL, 0, ring_id);
            if (key < 0) {
                kret = errno;
                DEBUG_PRINT(("krb5_krcc_generate_new: '%s' trying to "
                             "create '%s'\n", strerror(errno), uniquename));
                k5_cc_mutex_unlock(context, &krb5int_krcc_mutex);
                return kret;
            }
            break;
        }
    }

    kret = krb5_krcc_new_data(uniquename, key, ring_id, &d);
    k5_cc_mutex_unlock(context, &krb5int_krcc_mutex);
    if (kret) {
        free(lid);
        return kret;
    }
    lid->data = d;
    *id = lid;
    krb5_change_cache();
    return KRB5_OK;
}

/*
 * Requires:
 * id is a keyring credential cache
 *
 * Returns:
 * The name of the keyring cred cache id.
 */
static const char *KRB5_CALLCONV
krb5_krcc_get_name(krb5_context context, krb5_ccache id)
{
    DEBUG_PRINT(("krb5_krcc_get_name: entered\n"));
    return (char *) ((krb5_krcc_data *) id->data)->name;
}

/*
 * Modifies:
 * id, princ
 *
 * Effects:
 * Retrieves the primary principal from id, as set with
 * krb5_krcc_initialize.  The principal is returned is allocated
 * storage that must be freed by the caller via krb5_free_principal.
 *
 * Errors:
 * system errors
 * KRB5_CC_NOMEM
 */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_get_principal(krb5_context context, krb5_ccache id,
                        krb5_principal * princ)
{
    DEBUG_PRINT(("krb5_krcc_get_principal: entered\n"));

    return krb5_krcc_retrieve_principal(context, id, princ);
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_retrieve(krb5_context context, krb5_ccache id,
                   krb5_flags whichfields, krb5_creds * mcreds,
                   krb5_creds * creds)
{
    DEBUG_PRINT(("krb5_krcc_retrieve: entered\n"));

    return krb5_cc_retrieve_cred_default(context, id, whichfields,
                                         mcreds, creds);
}

/*
 * Non-functional stub implementation for krb5_krcc_remove
 *
 * Errors:
 *    KRB5_CC_NOSUPP - not implemented
 */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_remove_cred(krb5_context context, krb5_ccache cache,
                      krb5_flags flags, krb5_creds * creds)
{
    DEBUG_PRINT(("krb5_krcc_remove_cred: entered (returning KRB5_CC_NOSUPP)\n"));

    return KRB5_CC_NOSUPP;
}

/*
 * Requires:
 * id is a cred cache returned by krb5_krcc_resolve or
 * krb5_krcc_generate_new, but has not been opened by krb5_krcc_initialize.
 *
 * Modifies:
 * id
 *
 * Effects:
 * Sets the operational flags of id to flags.
 */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_set_flags(krb5_context context, krb5_ccache id, krb5_flags flags)
{
    DEBUG_PRINT(("krb5_krcc_set_flags: entered\n"));

    return KRB5_OK;
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_get_flags(krb5_context context, krb5_ccache id, krb5_flags * flags)
{
    DEBUG_PRINT(("krb5_krcc_get_flags: entered\n"));

    *flags = 0;
    return KRB5_OK;
}

/* store: Save away creds in the ccache keyring.  */
static krb5_error_code KRB5_CALLCONV
krb5_krcc_store(krb5_context context, krb5_ccache id, krb5_creds * creds)
{
    krb5_error_code kret;
    krb5_krcc_data *d = (krb5_krcc_data *) id->data;
    char   *payload = NULL;
    unsigned int payloadlen;
    key_serial_t newkey;
    char   *keyname = NULL;

    DEBUG_PRINT(("krb5_krcc_store: entered\n"));

    kret = k5_cc_mutex_lock(context, &d->lock);
    if (kret)
        return kret;

    /* Get the service principal name and use it as the key name */
    kret = krb5_unparse_name(context, creds->server, &keyname);
    if (kret) {
        DEBUG_PRINT(("Error unparsing service principal name!\n"));
        goto errout;
    }

    /* Serialize credential into memory */
    kret = krb5_krcc_unparse_cred(context, id, creds, &payload, &payloadlen);
    if (kret != KRB5_OK)
        goto errout;

    /* Add new key (credentials) into keyring */
    DEBUG_PRINT(("krb5_krcc_store: adding new key '%s' to keyring %d\n",
                 keyname, d->ring_id));
    newkey = add_key(KRCC_KEY_TYPE_USER, keyname, payload,
                     payloadlen, d->ring_id);
    if (newkey < 0) {
        kret = errno;
        DEBUG_PRINT(("Error adding user key '%s': %s\n",
                     keyname, strerror(kret)));
    } else {
        d->numkeys++;
        kret = KRB5_OK;
        krb5_krcc_update_change_time(d);
    }

errout:
    if (keyname)
        krb5_free_unparsed_name(context, keyname);
    if (payload)
        free(payload);

    k5_cc_mutex_unlock(context, &d->lock);
    return kret;
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_last_change_time(krb5_context context, krb5_ccache id,
                           krb5_timestamp *change_time)
{
    krb5_error_code ret = 0;
    krb5_krcc_data *data = (krb5_krcc_data *) id->data;

    *change_time = 0;

    ret = k5_cc_mutex_lock(context, &data->lock);
    if (!ret) {
        *change_time = data->changetime;
        k5_cc_mutex_unlock(context, &data->lock);
    }

    return ret;
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_lock(krb5_context context, krb5_ccache id)
{
    krb5_error_code ret = 0;
    krb5_krcc_data *data = (krb5_krcc_data *) id->data;
    ret = k5_cc_mutex_lock(context, &data->lock);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_unlock(krb5_context context, krb5_ccache id)
{
    krb5_error_code ret = 0;
    krb5_krcc_data *data = (krb5_krcc_data *) id->data;
    ret = k5_cc_mutex_unlock(context, &data->lock);
    return ret;
}


static  krb5_error_code
krb5_krcc_save_principal(krb5_context context, krb5_ccache id,
                         krb5_principal princ)
{
    krb5_krcc_data *d;
    krb5_error_code kret;
    char   *payload;
    key_serial_t newkey;
    unsigned int payloadsize;
    krb5_krcc_bc bc;

    k5_cc_mutex_assert_locked(context, &((krb5_krcc_data *) id->data)->lock);

    d = (krb5_krcc_data *) id->data;

    payload = malloc(GUESS_CRED_SIZE);
    if (payload == NULL)
        return KRB5_CC_NOMEM;

    bc.bpp = payload;
    bc.endp = payload + GUESS_CRED_SIZE;

    kret = krb5_krcc_unparse_principal(context, id, princ, &bc);
    CHECK_N_GO(kret, errout);

    /* Add new key into keyring */
    payloadsize = bc.bpp - payload;
#ifdef KRCC_DEBUG
    {
        krb5_error_code rc;
        char *princname = NULL;
        rc = krb5_unparse_name(context, princ, &princname);
        DEBUG_PRINT(("krb5_krcc_save_principal: adding new key '%s' "
                     "to keyring %d for principal '%s'\n",
                     KRCC_SPEC_PRINC_KEYNAME, d->ring_id,
                     rc ? "<unknown>" : princname));
        if (rc == 0)
            krb5_free_unparsed_name(context, princname);
    }
#endif
    newkey = add_key(KRCC_KEY_TYPE_USER, KRCC_SPEC_PRINC_KEYNAME, payload,
                     payloadsize, d->ring_id);
    if (newkey < 0) {
        kret = errno;
        DEBUG_PRINT(("Error adding principal key: %s\n", strerror(kret)));
    } else {
        d->princ_id = newkey;
        kret = KRB5_OK;
        krb5_krcc_update_change_time(d);
    }

errout:
    free(payload);
    return kret;
}

static  krb5_error_code
krb5_krcc_retrieve_principal(krb5_context context, krb5_ccache id,
                             krb5_principal * princ)
{
    krb5_krcc_data *d = (krb5_krcc_data *) id->data;
    krb5_error_code kret;
    void   *payload = NULL;
    int     psize;
    krb5_krcc_bc bc;

    kret = k5_cc_mutex_lock(context, &d->lock);
    if (kret)
        return kret;

    if (!d->princ_id) {
        princ = 0L;
        kret = KRB5_FCC_NOFILE;
        goto errout;
    }

    psize = keyctl_read_alloc(d->princ_id, &payload);
    if (psize == -1) {
        DEBUG_PRINT(("Reading principal key %d: %s\n",
                     d->princ_id, strerror(errno)));
        kret = KRB5_CC_IO;
        goto errout;
    }
    bc.bpp = payload;
    bc.endp = (char *)payload + psize;
    kret = krb5_krcc_parse_principal(context, id, princ, &bc);

errout:
    if (payload)
        free(payload);
    k5_cc_mutex_unlock(context, &d->lock);
    return kret;
}

static int
krb5_krcc_get_ring_ids(krb5_krcc_ring_ids_t *p)
{
    key_serial_t ids_key;
    char ids_buf[128];
    key_serial_t session, process, thread;
    long val;

    DEBUG_PRINT(("krb5_krcc_get_ring_ids: entered\n"));

    if (!p)
        return EINVAL;

    /* Use the defaults in case we find no ids key */
    p->session = KEY_SPEC_SESSION_KEYRING;
    p->process = KEY_SPEC_PROCESS_KEYRING;
    p->thread = KEY_SPEC_THREAD_KEYRING;

    /*
     * Note that in the "normal" case, this will not be found.
     * The Linux gssd creates this key while creating a
     * context to communicate the user's key serial numbers.
     */
    ids_key = request_key(KRCC_KEY_TYPE_USER, KRCC_SPEC_IDS_KEYNAME, NULL, 0);
    if (ids_key < 0)
        goto out;

    DEBUG_PRINT(("krb5_krcc_get_ring_ids: processing '%s' key %d\n",
                 KRCC_SPEC_IDS_KEYNAME, ids_key));
    /*
     * Read and parse the ids file
     */
    memset(ids_buf, '\0', sizeof(ids_buf));
    val = keyctl_read(ids_key, ids_buf, sizeof(ids_buf));
    if (val > sizeof(ids_buf))
        goto out;

    val = sscanf(ids_buf, "%d:%d:%d", &session, &process, &thread);
    if (val != 3)
        goto out;

    p->session = session;
    p->process = process;
    p->thread = thread;

out:
    DEBUG_PRINT(("krb5_krcc_get_ring_ids: returning %d:%d:%d\n",
                 p->session, p->process, p->thread));
    return 0;
}

/*
 * ===============================================================
 * INTERNAL functions to parse a credential from a key payload
 * (Borrowed heavily from krb5_fcc_{read|store}_ funtions.)
 * ===============================================================
 */

/*
 * Effects:
 * Copies len bytes from the key payload buffer into buf.
 * Updates payload pointer and returns KRB5_CC_END if we
 * try to read past the end of the payload buffer's data.
 *
 * Requires:
 * Must be called with mutex locked.
 *
 * Errors:
 * KRB5_CC_END - there were not len bytes available
 */
static  krb5_error_code
krb5_krcc_parse(krb5_context context, krb5_ccache id, krb5_pointer buf,
                unsigned int len, krb5_krcc_bc * bc)
{
    DEBUG_PRINT(("krb5_krcc_parse: entered\n"));

    if ((bc->endp == bc->bpp) || (bc->endp - bc->bpp) < len)
        return KRB5_CC_END;

    memcpy(buf, bc->bpp, len);
    bc->bpp += len;

    return KRB5_OK;
}

/*
 * Take a key (credential) read from a keyring entry
 * and parse it into a credential structure.
 */
static  krb5_error_code
krb5_krcc_parse_cred(krb5_context context, krb5_ccache id, krb5_creds * creds,
                     char *payload, int psize)
{
    krb5_error_code kret;
    krb5_octet octet;
    krb5_int32 int32;
    krb5_krcc_bc bc;

    /* Parse the pieces of the credential */
    bc.bpp = payload;
    bc.endp = bc.bpp + psize;
    kret = krb5_krcc_parse_principal(context, id, &creds->client, &bc);
    CHECK_N_GO(kret, out);

    kret = krb5_krcc_parse_principal(context, id, &creds->server, &bc);
    CHECK_N_GO(kret, cleanclient);

    kret = krb5_krcc_parse_keyblock(context, id, &creds->keyblock, &bc);
    CHECK_N_GO(kret, cleanserver);

    kret = krb5_krcc_parse_times(context, id, &creds->times, &bc);
    CHECK_N_GO(kret, cleanserver);

    kret = krb5_krcc_parse_octet(context, id, &octet, &bc);
    CHECK_N_GO(kret, cleanserver);
    creds->is_skey = octet;

    kret = krb5_krcc_parse_int32(context, id, &int32, &bc);
    CHECK_N_GO(kret, cleanserver);
    creds->ticket_flags = int32;

    kret = krb5_krcc_parse_addrs(context, id, &creds->addresses, &bc);
    CHECK_N_GO(kret, cleanblock);

    kret = krb5_krcc_parse_authdata(context, id, &creds->authdata, &bc);
    CHECK_N_GO(kret, cleanaddrs);

    kret = krb5_krcc_parse_krb5data(context, id, &creds->ticket, &bc);
    CHECK_N_GO(kret, cleanauthdata);

    kret = krb5_krcc_parse_krb5data(context, id, &creds->second_ticket, &bc);
    CHECK_N_GO(kret, cleanticket);

    kret = KRB5_OK;
    goto out;

cleanticket:
    memset(creds->ticket.data, 0, (unsigned) creds->ticket.length);
    free(creds->ticket.data);
cleanauthdata:
    krb5_free_authdata(context, creds->authdata);
cleanaddrs:
    krb5_free_addresses(context, creds->addresses);
cleanblock:
    free(creds->keyblock.contents);
cleanserver:
    krb5_free_principal(context, creds->server);
cleanclient:
    krb5_free_principal(context, creds->client);

out:
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_principal(krb5_context context, krb5_ccache id,
                          krb5_principal * princ, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    register krb5_principal tmpprinc;
    krb5_int32 length, type;
    int     i;

    /* Read principal type */
    kret = krb5_krcc_parse_int32(context, id, &type, bc);
    if (kret != KRB5_OK)
        return kret;

    /* Read the number of components */
    kret = krb5_krcc_parse_int32(context, id, &length, bc);
    if (kret != KRB5_OK)
        return kret;

    if (length < 0)
        return KRB5_CC_NOMEM;

    tmpprinc = (krb5_principal) malloc(sizeof(krb5_principal_data));
    if (tmpprinc == NULL)
        return KRB5_CC_NOMEM;
    if (length) {
        size_t  msize = length;
        if (msize != length) {
            free(tmpprinc);
            return KRB5_CC_NOMEM;
        }
        tmpprinc->data = ALLOC(msize, krb5_data);
        if (tmpprinc->data == 0) {
            free(tmpprinc);
            return KRB5_CC_NOMEM;
        }
    } else
        tmpprinc->data = 0;
    tmpprinc->magic = KV5M_PRINCIPAL;
    tmpprinc->length = length;
    tmpprinc->type = type;

    kret = krb5_krcc_parse_krb5data(context, id,
                                    krb5_princ_realm(context, tmpprinc), bc);
    i = 0;
    CHECK(kret);

    for (i = 0; i < length; i++) {
        kret = krb5_krcc_parse_krb5data(context, id,
                                        krb5_princ_component(context, tmpprinc,
                                                             i), bc);
        CHECK(kret);
    }
    *princ = tmpprinc;
    return KRB5_OK;

errout:
    while (--i >= 0)
        free(krb5_princ_component(context, tmpprinc, i)->data);
    free(krb5_princ_realm(context, tmpprinc)->data);
    free(tmpprinc->data);
    free(tmpprinc);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_keyblock(krb5_context context, krb5_ccache id,
                         krb5_keyblock * keyblock, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_ui_2 ui2;
    krb5_int32 int32;

    keyblock->magic = KV5M_KEYBLOCK;
    keyblock->contents = 0;

    kret = krb5_krcc_parse_ui_2(context, id, &ui2, bc);
    CHECK(kret);
    keyblock->enctype = ui2;

    kret = krb5_krcc_parse_int32(context, id, &int32, bc);
    CHECK(kret);
    if (int32 < 0)
        return KRB5_CC_NOMEM;
    keyblock->length = int32;
    /* Overflow check.  */
    if (keyblock->length != int32)
        return KRB5_CC_NOMEM;
    if (keyblock->length == 0)
        return KRB5_OK;
    keyblock->contents = ALLOC(keyblock->length, krb5_octet);
    if (keyblock->contents == NULL)
        return KRB5_CC_NOMEM;

    kret = krb5_krcc_parse(context, id, keyblock->contents,
                           keyblock->length, bc);
    CHECK(kret);

    return KRB5_OK;
errout:
    if (keyblock->contents)
        free(keyblock->contents);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_times(krb5_context context, krb5_ccache id,
                      krb5_ticket_times * t, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 i;

    kret = krb5_krcc_parse_int32(context, id, &i, bc);
    CHECK(kret);
    t->authtime = i;

    kret = krb5_krcc_parse_int32(context, id, &i, bc);
    CHECK(kret);
    t->starttime = i;

    kret = krb5_krcc_parse_int32(context, id, &i, bc);
    CHECK(kret);
    t->endtime = i;

    kret = krb5_krcc_parse_int32(context, id, &i, bc);
    CHECK(kret);
    t->renew_till = i;

    return 0;
errout:
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_krb5data(krb5_context context, krb5_ccache id,
                         krb5_data * data, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 len;

    data->magic = KV5M_DATA;
    data->data = 0;

    kret = krb5_krcc_parse_int32(context, id, &len, bc);
    CHECK(kret);
    if (len < 0)
        return KRB5_CC_NOMEM;
    data->length = len;
    if (data->length != len || data->length + 1 == 0)
        return KRB5_CC_NOMEM;

    if (data->length == 0) {
        data->data = 0;
        return KRB5_OK;
    }

    data->data = (char *) malloc(data->length + 1);
    if (data->data == NULL)
        return KRB5_CC_NOMEM;

    kret = krb5_krcc_parse(context, id, data->data, (unsigned) data->length,
                           bc);
    CHECK(kret);

    data->data[data->length] = 0;       /* Null terminate, just in case.... */
    return KRB5_OK;
errout:
    if (data->data)
        free(data->data);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_int32(krb5_context context, krb5_ccache id, krb5_int32 * i,
                      krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    unsigned char buf[4];

    kret = krb5_krcc_parse(context, id, buf, 4, bc);
    if (kret)
        return kret;
    *i = load_32_be(buf);
    return 0;
}

static  krb5_error_code
krb5_krcc_parse_octet(krb5_context context, krb5_ccache id, krb5_octet * i,
                      krb5_krcc_bc * bc)
{
    return krb5_krcc_parse(context, id, (krb5_pointer) i, 1, bc);
}

static  krb5_error_code
krb5_krcc_parse_addrs(krb5_context context, krb5_ccache id,
                      krb5_address *** addrs, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 length;
    size_t  msize;
    int     i;

    *addrs = 0;

    /* Read the number of components */
    kret = krb5_krcc_parse_int32(context, id, &length, bc);
    CHECK(kret);

    /*
     * Make *addrs able to hold length pointers to krb5_address structs
     * Add one extra for a null-terminated list
     */
    msize = length;
    msize += 1;
    if (msize == 0 || msize - 1 != length || length < 0)
        return KRB5_CC_NOMEM;
    *addrs = ALLOC(msize, krb5_address *);
    if (*addrs == NULL)
        return KRB5_CC_NOMEM;

    for (i = 0; i < length; i++) {
        (*addrs)[i] = (krb5_address *) malloc(sizeof(krb5_address));
        if ((*addrs)[i] == NULL) {
            krb5_free_addresses(context, *addrs);
            return KRB5_CC_NOMEM;
        }
        kret = krb5_krcc_parse_addr(context, id, (*addrs)[i], bc);
        CHECK(kret);
    }

    return KRB5_OK;
errout:
    if (*addrs)
        krb5_free_addresses(context, *addrs);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_addr(krb5_context context, krb5_ccache id, krb5_address * addr,
                     krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_ui_2 ui2;
    krb5_int32 int32;

    addr->magic = KV5M_ADDRESS;
    addr->contents = 0;

    kret = krb5_krcc_parse_ui_2(context, id, &ui2, bc);
    CHECK(kret);
    addr->addrtype = ui2;

    kret = krb5_krcc_parse_int32(context, id, &int32, bc);
    CHECK(kret);
    if ((int32 & VALID_INT_BITS) != int32)      /* Overflow int??? */
        return KRB5_CC_NOMEM;
    addr->length = int32;
    /*
     * Length field is "unsigned int", which may be smaller
     * than 32 bits.
     */
    if (addr->length != int32)
        return KRB5_CC_NOMEM;   /* XXX */

    if (addr->length == 0)
        return KRB5_OK;

    addr->contents = (krb5_octet *) malloc(addr->length);
    if (addr->contents == NULL)
        return KRB5_CC_NOMEM;

    kret = krb5_krcc_parse(context, id, addr->contents, addr->length, bc);
    CHECK(kret);

    return KRB5_OK;
errout:
    if (addr->contents)
        free(addr->contents);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_authdata(krb5_context context, krb5_ccache id,
                         krb5_authdata *** a, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 length;
    size_t  msize;
    int     i;

    *a = 0;

    /* Read the number of components */
    kret = krb5_krcc_parse_int32(context, id, &length, bc);
    CHECK(kret);

    if (length == 0)
        return KRB5_OK;

    /*
     * Make *a able to hold length pointers to krb5_authdata structs
     * Add one extra for a null-terminated list
     */
    msize = length;
    msize += 1;
    if (msize == 0 || msize - 1 != length || length < 0)
        return KRB5_CC_NOMEM;
    *a = ALLOC(msize, krb5_authdata *);
    if (*a == NULL)
        return KRB5_CC_NOMEM;

    for (i = 0; i < length; i++) {
        (*a)[i] = (krb5_authdata *) malloc(sizeof(krb5_authdata));
        if ((*a)[i] == NULL) {
            krb5_free_authdata(context, *a);
            *a = NULL;
            return KRB5_CC_NOMEM;
        }
        kret = krb5_krcc_parse_authdatum(context, id, (*a)[i], bc);
        CHECK(kret);
    }

    return KRB5_OK;
errout:
    if (*a) {
        krb5_free_authdata(context, *a);
        *a = NULL;
    }
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_authdatum(krb5_context context, krb5_ccache id,
                          krb5_authdata * a, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 int32;
    krb5_ui_2 ui2;

    a->magic = KV5M_AUTHDATA;
    a->contents = NULL;

    kret = krb5_krcc_parse_ui_2(context, id, &ui2, bc);
    CHECK(kret);
    a->ad_type = (krb5_authdatatype) ui2;
    kret = krb5_krcc_parse_int32(context, id, &int32, bc);
    CHECK(kret);
    if ((int32 & VALID_INT_BITS) != int32)      /* Overflow int??? */
        return KRB5_CC_NOMEM;
    a->length = int32;
    /*
     * Value could have gotten truncated if int is
     * smaller than 32 bits.
     */
    if (a->length != int32)
        return KRB5_CC_NOMEM;   /* XXX */

    if (a->length == 0)
        return KRB5_OK;

    a->contents = (krb5_octet *) malloc(a->length);
    if (a->contents == NULL)
        return KRB5_CC_NOMEM;

    kret = krb5_krcc_parse(context, id, a->contents, a->length, bc);
    CHECK(kret);

    return KRB5_OK;
errout:
    if (a->contents)
        free(a->contents);
    return kret;

}

static  krb5_error_code
krb5_krcc_parse_ui_2(krb5_context context, krb5_ccache id, krb5_ui_2 * i,
                     krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    unsigned char buf[2];

    kret = krb5_krcc_parse(context, id, buf, 2, bc);
    if (kret)
        return kret;
    *i = load_16_be(buf);
    return 0;
}

/*
 * Requires:
 * locked mutex
 *
 * Effects:
 * Copies len bytes from buf into the payload buffer (bc->bpp).
 * Detects attempts to write past end of the payload buffer.
 * Updates payload buffer pointer accordingly.
 *
 * Errors:
 * system errors
 */
static  krb5_error_code
krb5_krcc_unparse(krb5_context context, krb5_ccache id, krb5_pointer buf,
                  unsigned int len, krb5_krcc_bc * bc)
{
    if (bc->bpp + len > bc->endp)
        return KRB5_CC_WRITE;

    memcpy(bc->bpp, buf, len);
    bc->bpp += len;

    return KRB5_OK;
}

static  krb5_error_code
krb5_krcc_unparse_principal(krb5_context context, krb5_ccache id,
                            krb5_principal princ, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 i, length, tmp, type;

    type = krb5_princ_type(context, princ);
    tmp = length = krb5_princ_size(context, princ);

    kret = krb5_krcc_unparse_int32(context, id, type, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_int32(context, id, tmp, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_krb5data(context, id,
                                      krb5_princ_realm(context, princ), bc);
    CHECK_OUT(kret);

    for (i = 0; i < length; i++) {
        kret = krb5_krcc_unparse_krb5data(context, id,
                                          krb5_princ_component(context, princ,
                                                               i), bc);
        CHECK_OUT(kret);
    }

    return KRB5_OK;
}

static  krb5_error_code
krb5_krcc_unparse_keyblock(krb5_context context, krb5_ccache id,
                           krb5_keyblock * keyblock, krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_ui_2(context, id, keyblock->enctype, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_ui_4(context, id, keyblock->length, bc);
    CHECK_OUT(kret);
    return krb5_krcc_unparse(context, id, (char *) keyblock->contents,
                             keyblock->length, bc);
}

static  krb5_error_code
krb5_krcc_unparse_times(krb5_context context, krb5_ccache id,
                        krb5_ticket_times * t, krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_int32(context, id, t->authtime, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_int32(context, id, t->starttime, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_int32(context, id, t->endtime, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_int32(context, id, t->renew_till, bc);
    CHECK_OUT(kret);
    return 0;
}

static  krb5_error_code
krb5_krcc_unparse_krb5data(krb5_context context, krb5_ccache id,
                           krb5_data * data, krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_ui_4(context, id, data->length, bc);
    CHECK_OUT(kret);
    return krb5_krcc_unparse(context, id, data->data, data->length, bc);
}

static  krb5_error_code
krb5_krcc_unparse_int32(krb5_context context, krb5_ccache id, krb5_int32 i,
                        krb5_krcc_bc * bc)
{
    return krb5_krcc_unparse_ui_4(context, id, (krb5_ui_4) i, bc);
}

static  krb5_error_code
krb5_krcc_unparse_octet(krb5_context context, krb5_ccache id, krb5_int32 i,
                        krb5_krcc_bc * bc)
{
    krb5_octet ibuf;

    ibuf = (krb5_octet) i;
    return krb5_krcc_unparse(context, id, (char *) &ibuf, 1, bc);
}

static  krb5_error_code
krb5_krcc_unparse_addrs(krb5_context context, krb5_ccache id,
                        krb5_address ** addrs, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_address **temp;
    krb5_int32 i, length = 0;

    /* Count the number of components */
    if (addrs) {
        temp = addrs;
        while (*temp++)
            length += 1;
    }

    kret = krb5_krcc_unparse_int32(context, id, length, bc);
    CHECK_OUT(kret);
    for (i = 0; i < length; i++) {
        kret = krb5_krcc_unparse_addr(context, id, addrs[i], bc);
        CHECK_OUT(kret);
    }

    return KRB5_OK;
}

static  krb5_error_code
krb5_krcc_unparse_addr(krb5_context context, krb5_ccache id,
                       krb5_address * addr, krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_ui_2(context, id, addr->addrtype, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_ui_4(context, id, addr->length, bc);
    CHECK_OUT(kret);
    return krb5_krcc_unparse(context, id, (char *) addr->contents,
                             addr->length, bc);
}

static  krb5_error_code
krb5_krcc_unparse_authdata(krb5_context context, krb5_ccache id,
                           krb5_authdata ** a, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_authdata **temp;
    krb5_int32 i, length = 0;

    if (a != NULL) {
        for (temp = a; *temp; temp++)
            length++;
    }

    kret = krb5_krcc_unparse_int32(context, id, length, bc);
    CHECK_OUT(kret);
    for (i = 0; i < length; i++) {
        kret = krb5_krcc_unparse_authdatum(context, id, a[i], bc);
        CHECK_OUT(kret);
    }
    return KRB5_OK;
}

static  krb5_error_code
krb5_krcc_unparse_authdatum(krb5_context context, krb5_ccache id,
                            krb5_authdata * a, krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_ui_2(context, id, a->ad_type, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_ui_4(context, id, a->length, bc);
    CHECK_OUT(kret);
    return krb5_krcc_unparse(context, id, (krb5_pointer) a->contents,
                             a->length, bc);
}

static  krb5_error_code
krb5_krcc_unparse_ui_4(krb5_context context, krb5_ccache id, krb5_ui_4 i,
                       krb5_krcc_bc * bc)
{
    unsigned char buf[4];

    store_32_be(i, buf);
    return krb5_krcc_unparse(context, id, buf, 4, bc);
}

static  krb5_error_code
krb5_krcc_unparse_ui_2(krb5_context context, krb5_ccache id, krb5_int32 i,
                       krb5_krcc_bc * bc)
{
    unsigned char buf[2];

    store_16_be(i, buf);
    return krb5_krcc_unparse(context, id, buf, 2, bc);
}

/*
 * ===============================================================
 * INTERNAL functions to unparse a credential into a key payload
 * (Borrowed heavily from krb5_fcc_{read|store}_ funtions.)
 * ===============================================================
 */

/*
 * Take a credential structure and unparse it (serialize)
 * for storage into a keyring key entry.
 * Caller is responsible for freeing returned buffer.
 */
static  krb5_error_code
krb5_krcc_unparse_cred(krb5_context context, krb5_ccache id,
                       krb5_creds * creds, char **datapp, unsigned int *lenptr)
{
    krb5_error_code kret;
    char   *buf;
    krb5_krcc_bc bc;

    if (!creds || !datapp || !lenptr)
        return EINVAL;

    *datapp = NULL;
    *lenptr = 0;

    buf = malloc(GUESS_CRED_SIZE);
    if (buf == NULL)
        return KRB5_CC_NOMEM;

    bc.bpp = buf;
    bc.endp = buf + GUESS_CRED_SIZE;

    kret = krb5_krcc_unparse_principal(context, id, creds->client, &bc);
    CHECK_N_GO(kret, errout);

    kret = krb5_krcc_unparse_principal(context, id, creds->server, &bc);
    CHECK_N_GO(kret, errout);

    kret = krb5_krcc_unparse_keyblock(context, id, &creds->keyblock, &bc);
    CHECK_N_GO(kret, errout);

    kret = krb5_krcc_unparse_times(context, id, &creds->times, &bc);
    CHECK_N_GO(kret, errout);

    kret = krb5_krcc_unparse_octet(context, id, (krb5_int32) creds->is_skey,
                                   &bc);
    CHECK_N_GO(kret, errout);

    kret = krb5_krcc_unparse_int32(context, id, creds->ticket_flags, &bc);
    CHECK_N_GO(kret, errout);

    kret = krb5_krcc_unparse_addrs(context, id, creds->addresses, &bc);
    CHECK_N_GO(kret, errout);

    kret = krb5_krcc_unparse_authdata(context, id, creds->authdata, &bc);
    CHECK_N_GO(kret, errout);

    kret = krb5_krcc_unparse_krb5data(context, id, &creds->ticket, &bc);
    CHECK_N_GO(kret, errout);

    kret = krb5_krcc_unparse_krb5data(context, id, &creds->second_ticket, &bc);
    CHECK_N_GO(kret, errout);

    /* Success! */
    *datapp = buf;
    *lenptr = bc.bpp - buf;
    kret = KRB5_OK;

errout:
    return kret;
}

/*
 * Utility routine: called by krb5_krcc_* functions to keep
 * result of krb5_krcc_last_change_time up to date.
 * Value monotonically increases -- based on but not guaranteed to be actual
 * system time.
 */

static void
krb5_krcc_update_change_time(krb5_krcc_data *d)
{
    krb5_timestamp now_time = time(NULL);
    d->changetime = (d->changetime >= now_time) ?
        d->changetime + 1 : now_time;
}


/*
 * ccache implementation storing credentials in the Linux keyring facility
 * The default is to put them at the session keyring level.
 * If "KEYRING:process:" or "KEYRING:thread:" is specified, then they will
 * be stored at the process or thread level respectively.
 */
const krb5_cc_ops krb5_krcc_ops = {
    0,
    "KEYRING",
    krb5_krcc_get_name,
    krb5_krcc_resolve,
    krb5_krcc_generate_new,
    krb5_krcc_initialize,
    krb5_krcc_destroy,
    krb5_krcc_close,
    krb5_krcc_store,
    krb5_krcc_retrieve,
    krb5_krcc_get_principal,
    krb5_krcc_start_seq_get,
    krb5_krcc_next_cred,
    krb5_krcc_end_seq_get,
    krb5_krcc_remove_cred,
    krb5_krcc_set_flags,
    krb5_krcc_get_flags,        /* added after 1.4 release */
    NULL,
    NULL,
    NULL,
    NULL, /* move */
    krb5_krcc_last_change_time, /* lastchange */
    NULL, /* wasdefault */
    krb5_krcc_lock,
    krb5_krcc_unlock,
};

#else /* !USE_KEYRING_CCACHE */

/*
 * Export this, but it shouldn't be used.
 */
const krb5_cc_ops krb5_krcc_ops = {
    0,
    "KEYRING",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,                       /* added after 1.4 release */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif  /* USE_KEYRING_CCACHE */
