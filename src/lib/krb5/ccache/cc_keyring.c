/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/ccache/cc_keyring.c */
/*
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
 */
/*
 * Copyright 1990,1991,1992,1993,1994,2000,2004 Massachusetts Institute of
 * Technology.  All Rights Reserved.
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
 * This file implements a collection-enabled credential cache type where the
 * credentials are stored in the Linux keyring facility.
 *
 * A residual of this type can have three forms:
 *    anchor:collection:subsidiary
 *    anchor:collection
 *    collection
 *
 * The anchor name is "process", "thread", or "legacy" and determines where we
 * search for keyring collections.  In the third form, the anchor name is
 * presumed to be "legacy".  The anchor keyring for legacy caches is the
 * session keyring.
 *
 * If the subsidiary name is present, the residual identifies a single cache
 * within a collection.  Otherwise, the residual identifies the collection
 * itself.  When a residual identifying a collection is resolved, the
 * collection's primary key is looked up (or initialized, using the collection
 * name as the subsidiary name), and the resulting cache's name will use the
 * first name form and will identify the primary cache.
 *
 * Keyring collections are named "_krb_<collection>" and are linked from the
 * anchor keyring.  The keys within a keyring collection are links to cache
 * keyrings, plus a link to one user key named "krb_ccache:primary" which
 * contains a serialized representation of the collection version (currently 1)
 * and the primary name of the collection.
 *
 * Cache keyrings contain one user key per credential which contains a
 * serialized representation of the credential.  There is also one user key
 * named "__krb5_princ__" which contains a serialized representation of the
 * cache's default principal.
 *
 * If the anchor name is "legacy", then the initial primary cache (the one
 * named with the collection name) is also linked to the session keyring, and
 * we look for a cache in that location when initializing the collection.  This
 * extra link allows that cache to be visible to old versions of the KEYRING
 * cache type, and allows us to see caches created by that code.
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
 * We try to use the big_key key type for credentials except in legacy caches.
 * We fall back to the user key type if the kernel does not support big_key.
 * If the library doesn't support keyctl_get_persistent(), we don't even try
 * big_key since the two features were added at the same time.
 */
#ifdef HAVE_PERSISTENT_KEYRING
#define KRCC_CRED_KEY_TYPE "big_key"
#else
#define KRCC_CRED_KEY_TYPE "user"
#endif

/*
 * We use the "user" key type for collection primary names, for cache principal
 * names, and for credentials in legacy caches.
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
 * Special name for the key to communicate the name(s)
 * of credentials caches to be used for requests.
 * This should currently contain a single name, but
 * in the future may contain a list that may be
 * intelligently chosen from.
 */
#define KRCC_SPEC_CCACHE_SET_KEYNAME "__krb5_cc_set__"

/*
 * This name identifies the key containing the name of the current primary
 * cache within a collection.
 */
#define KRCC_COLLECTION_PRIMARY "krb_ccache:primary"

/*
 * If the library context does not specify a keyring collection, unique ccaches
 * will be created within this collection.
 */
#define KRCC_DEFAULT_UNIQUE_COLLECTION "session:__krb5_unique__"

/*
 * Collection keyring names begin with this prefix.  We use a prefix so that a
 * cache keyring with the collection name itself can be linked directly into
 * the anchor, for legacy session keyring compatibility.
 */
#define KRCC_CCCOL_PREFIX "_krb_"

/*
 * For the "persistent" anchor type, we look up or create this fixed keyring
 * name within the per-UID persistent keyring.
 */
#define KRCC_PERSISTENT_KEYRING_NAME "_krb"

/*
 * Name of the key holding time offsets for the individual cache
 */
#define KRCC_TIME_OFFSETS "__krb5_time_offsets__"

/*
 * Keyring name prefix and length of random name part
 */
#define KRCC_NAME_PREFIX "krb_ccache_"
#define KRCC_NAME_RAND_CHARS 8

#define KRCC_COLLECTION_VERSION 1

#define KRCC_PERSISTENT_ANCHOR "persistent"
#define KRCC_PROCESS_ANCHOR "process"
#define KRCC_THREAD_ANCHOR "thread"
#define KRCC_SESSION_ANCHOR "session"
#define KRCC_USER_ANCHOR "user"
#define KRCC_LEGACY_ANCHOR "legacy"

#define KRB5_OK 0

/* Hopefully big enough to hold a serialized credential */
#define MAX_CRED_SIZE (1024*1024)

#define CHECK_N_GO(ret, errdest) if (ret != KRB5_OK) goto errdest
#define CHECK(ret) if (ret != KRB5_OK) goto errout
#define CHECK_OUT(ret) if (ret != KRB5_OK) return ret

typedef struct _krb5_krcc_cursor
{
    int     numkeys;
    int     currkey;
    key_serial_t princ_id;
    key_serial_t offsets_id;
    key_serial_t *keys;
} *krb5_krcc_cursor;

/*
 * This represents a credentials cache "file"
 * where cache_id is the keyring serial number for
 * this credentials cache "file".  Each key
 * in the keyring contains a separate key.
 */
typedef struct _krb5_krcc_data
{
    char   *name;               /* Name for this credentials cache */
    k5_cc_mutex lock;           /* synchronization */
    key_serial_t collection_id; /* collection containing this cache keyring */
    key_serial_t cache_id;      /* keyring representing ccache */
    key_serial_t princ_id;      /* key holding principal info */
    krb5_timestamp changetime;
    krb5_boolean is_legacy_type;
} krb5_krcc_data;

/* Passed internally to assure we don't go past the bounds of our buffer */
typedef struct _krb5_krcc_buffer_cursor
{
    char   *bpp;
    char   *endp;
    size_t  size;               /* For dry-run length calculation */
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

static krb5_error_code KRB5_CALLCONV krb5_krcc_ptcursor_new
(krb5_context context, krb5_cc_ptcursor *cursor_out);

static krb5_error_code KRB5_CALLCONV krb5_krcc_ptcursor_next
(krb5_context context, krb5_cc_ptcursor cursor, krb5_ccache *cache_out);

static krb5_error_code KRB5_CALLCONV krb5_krcc_ptcursor_free
(krb5_context context, krb5_cc_ptcursor *cursor);

static krb5_error_code KRB5_CALLCONV krb5_krcc_switch_to
(krb5_context context, krb5_ccache cache);

/*
 * Internal utility functions
 */

static krb5_error_code krb5_krcc_clearcache
(krb5_context context, krb5_ccache id);

static krb5_error_code krb5_krcc_new_data
(const char *anchor_name, const char *collection_name,
 const char *subsidiary_name, key_serial_t cache_id,
 key_serial_t collection_id, krb5_krcc_data **datapp);

static krb5_error_code krb5_krcc_save_principal
(krb5_context context, krb5_ccache id, krb5_principal princ);

static krb5_error_code krb5_krcc_retrieve_principal
(krb5_context context, krb5_ccache id, krb5_principal * princ);
static krb5_error_code krb5_krcc_save_time_offsets
(krb5_context context, krb5_ccache id, krb5_int32 time_offset,
 krb5_int32 usec_offset);
static krb5_error_code krb5_krcc_get_time_offsets
(krb5_context context, krb5_ccache id, krb5_int32 *time_offset,
 krb5_int32 *usec_offset);

/* Routines to parse a key from a keyring into a cred structure */
static krb5_error_code krb5_krcc_parse
(krb5_context, krb5_pointer buf, unsigned int len, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_cred
(krb5_context context, krb5_creds * creds, char *payload, int psize);
static krb5_error_code krb5_krcc_parse_principal
(krb5_context context, krb5_principal * princ, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_keyblock
(krb5_context context, krb5_keyblock * keyblock, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_times
(krb5_context context, krb5_ticket_times * t, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_krb5data
(krb5_context context, krb5_data * data, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_int32
(krb5_context context, krb5_int32 * i, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_octet
(krb5_context context, krb5_octet * octet, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_addrs
(krb5_context context, krb5_address *** a, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_addr
(krb5_context context, krb5_address * a, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_authdata
(krb5_context context, krb5_authdata *** ad, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_authdatum
(krb5_context context, krb5_authdata * ad, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_parse_ui_2
(krb5_context, krb5_ui_2 * i, krb5_krcc_bc * bc);

/* Routines to unparse a cred structure into keyring key */
static krb5_error_code krb5_krcc_unparse
(krb5_context, krb5_pointer buf, unsigned int len, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_cred_alloc
(krb5_context context, krb5_creds * creds,
 char **datapp, unsigned int *lenptr);
static krb5_error_code krb5_krcc_unparse_cred
(krb5_context context, krb5_creds * creds, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_principal
(krb5_context, krb5_principal princ, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_keyblock
(krb5_context, krb5_keyblock * keyblock, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_times
(krb5_context, krb5_ticket_times * t, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_krb5data
(krb5_context, krb5_data * data, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_int32
(krb5_context, krb5_int32 i, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_octet
(krb5_context, krb5_int32 i, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_addrs
(krb5_context, krb5_address ** a, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_addr
(krb5_context, krb5_address * a, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_authdata
(krb5_context, krb5_authdata ** ad, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_authdatum
(krb5_context, krb5_authdata * ad, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_ui_4
(krb5_context, krb5_ui_4 i, krb5_krcc_bc * bc);
static krb5_error_code krb5_krcc_unparse_ui_2
(krb5_context, krb5_int32 i, krb5_krcc_bc * bc);
static void krb5_krcc_update_change_time
(krb5_krcc_data *);

static krb5_error_code
krb5_krcc_parse_index(krb5_context context, krb5_int32 *version,
                      char **primary, void *payload, int psize);
static krb5_error_code
krb5_krcc_unparse_index(krb5_context context, krb5_int32 version,
                        const char *primary, void **datapp, int *lenptr);
static krb5_error_code
krb5_krcc_parse_offsets(krb5_context context, krb5_int32 *time_offset,
                        krb5_int32 *usec_offset, void *payload, int psize);
static krb5_error_code
krb5_krcc_unparse_offsets(krb5_context context, krb5_int32 time_offset,
                          krb5_int32 usec_offset, void **datapp, int *lenptr);

/* Note the following is a stub function for Linux */
extern krb5_error_code krb5_change_cache(void);

/*
 * GET_PERSISTENT(uid) acquires the persistent keyring for uid, or falls back
 * to the user keyring if uid matches the current effective uid.
 */

static key_serial_t
get_persistent_fallback(uid_t uid)
{
    return (uid == geteuid()) ? KEY_SPEC_USER_KEYRING : -1;
}

#ifdef HAVE_PERSISTENT_KEYRING
#define GET_PERSISTENT get_persistent_real
static key_serial_t
get_persistent_real(uid_t uid)
{
    key_serial_t key;

    key = keyctl_get_persistent(uid, KEY_SPEC_PROCESS_KEYRING);
    return (key == -1 && errno == ENOTSUP) ? get_persistent_fallback(uid) :
        key;
}
#else
#define GET_PERSISTENT get_persistent_fallback
#endif

/*
 * If a process has no explicitly set session keyring, KEY_SPEC_SESSION_KEYRING
 * will resolve to the user session keyring for ID lookup and reading, but in
 * some kernel versions, writing to that special keyring will instead create a
 * new empty session keyring for the process.  We do not want that; the keys we
 * create would be invisible to other processes.  We can work around that
 * behavior by explicitly writing to the user session keyring when it matches
 * the session keyring.  This function returns the keyring we should write to
 * for the session anchor.
 */
static key_serial_t
session_write_anchor()
{
    key_serial_t s, u;

    s = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
    u = keyctl_get_keyring_ID(KEY_SPEC_USER_SESSION_KEYRING, 0);
    return (s == u) ? KEY_SPEC_USER_SESSION_KEYRING : KEY_SPEC_SESSION_KEYRING;
}

/*
 * Find or create a keyring within parent with the given name.  If possess is
 * nonzero, also make sure the key is linked from possess.  This is necessary
 * to ensure that we have possession rights on the key when the parent is the
 * user or persistent keyring.
 */
static krb5_error_code
find_or_create_keyring(key_serial_t parent, key_serial_t possess,
                       const char *name, key_serial_t *key_out)
{
    key_serial_t key;

    *key_out = -1;
    key = keyctl_search(parent, KRCC_KEY_TYPE_KEYRING, name, possess);
    if (key == -1) {
        if (possess != 0) {
            key = add_key(KRCC_KEY_TYPE_KEYRING, name, NULL, 0, possess);
            if (key == -1)
                return errno;
            if (keyctl_link(key, parent) == -1)
                return errno;
        } else {
            key = add_key(KRCC_KEY_TYPE_KEYRING, name, NULL, 0, parent);
            if (key == -1)
                return errno;
        }
    }
    *key_out = key;
    return 0;
}

/* Parse a residual name into an anchor name, a collection name, and possibly a
 * subsidiary name. */
static krb5_error_code
parse_residual(const char *residual, char **anchor_name_out,
               char **collection_name_out, char **subsidiary_name_out)
{
    krb5_error_code ret;
    char *anchor_name = NULL, *collection_name = NULL, *subsidiary_name = NULL;
    const char *sep;

    *anchor_name_out = 0;
    *collection_name_out = NULL;
    *subsidiary_name_out = NULL;

    /* Parse out the anchor name.  Use the legacy anchor if not present. */
    sep = strchr(residual, ':');
    if (sep == NULL) {
        anchor_name = strdup(KRCC_LEGACY_ANCHOR);
        if (anchor_name == NULL)
            goto oom;
    } else {
        anchor_name = k5memdup0(residual, sep - residual, &ret);
        if (anchor_name == NULL)
            goto oom;
        residual = sep + 1;
    }

    /* Parse out the collection and subsidiary name. */
    sep = strchr(residual, ':');
    if (sep == NULL) {
        collection_name = strdup(residual);
        if (collection_name == NULL)
            goto oom;
        subsidiary_name = NULL;
    } else {
        collection_name = k5memdup0(residual, sep - residual, &ret);
        if (collection_name == NULL)
            goto oom;
        subsidiary_name = strdup(sep + 1);
        if (subsidiary_name == NULL)
            goto oom;
    }

    *anchor_name_out = anchor_name;
    *collection_name_out = collection_name;
    *subsidiary_name_out = subsidiary_name;
    return 0;

oom:
    free(anchor_name);
    free(collection_name);
    free(subsidiary_name);
    return ENOMEM;
}

/*
 * Return true if residual identifies a subsidiary cache which should be linked
 * into the anchor so it can be visible to old code.  This is the case if the
 * residual has the legacy anchor and the subsidiary name matches the
 * collection name.
 */
static krb5_boolean
is_legacy_cache_name(const char *residual)
{
    const char *sep, *aname, *cname, *sname;
    size_t alen, clen, legacy_len = sizeof(KRCC_LEGACY_ANCHOR) - 1;

    /* Get pointers to the anchor, collection, and subsidiary names. */
    aname = residual;
    sep = strchr(residual, ':');
    if (sep == NULL)
        return FALSE;
    alen = sep - aname;
    cname = sep + 1;
    sep = strchr(cname, ':');
    if (sep == NULL)
        return FALSE;
    clen = sep - cname;
    sname = sep + 1;

    return alen == legacy_len && clen == strlen(sname) &&
        strncmp(aname, KRCC_LEGACY_ANCHOR, alen) == 0 &&
        strncmp(cname, sname, clen) == 0;
}

/* If the default cache name for context is a KEYRING cache, parse its residual
 * string.  Otherwise set all outputs to NULL. */
static krb5_error_code
get_default(krb5_context context, char **anchor_name_out,
            char **collection_name_out, char **subsidiary_name_out)
{
    const char *defname;

    *anchor_name_out = *collection_name_out = *subsidiary_name_out = NULL;
    defname = krb5_cc_default_name(context);
    if (defname == NULL || strncmp(defname, "KEYRING:", 8) != 0)
        return 0;
    return parse_residual(defname + 8, anchor_name_out, collection_name_out,
                          subsidiary_name_out);
}

/* Create a residual identifying a subsidiary cache. */
static krb5_error_code
make_subsidiary_residual(const char *anchor_name, const char *collection_name,
                         const char *subsidiary_name, char **residual_out)
{
    if (asprintf(residual_out, "%s:%s:%s", anchor_name, collection_name,
                 subsidiary_name) < 0) {
        *residual_out = NULL;
        return ENOMEM;
    }
    return 0;
}

/* Retrieve or create a keyring for collection_name within the anchor, and set
 * *collection_id_out to its serial number. */
static krb5_error_code
get_collection(const char *anchor_name, const char *collection_name,
               key_serial_t *collection_id_out)
{
    krb5_error_code ret;
    key_serial_t persistent_id, anchor_id, possess_id = 0;
    char *ckname, *cnend;
    long uidnum;

    *collection_id_out = 0;

    if (strcmp(anchor_name, KRCC_PERSISTENT_ANCHOR) == 0) {
        /*
         * The collection name is a uid (or empty for the current effective
         * uid), and we look up a fixed keyring name within the persistent
         * keyring for that uid.  We link it to the process keyring to ensure
         * that we have possession rights on the collection key.
         */
        if (*collection_name != '\0') {
            errno = 0;
            uidnum = strtol(collection_name, &cnend, 10);
            if (errno || *cnend != '\0')
                return KRB5_KCC_INVALID_UID;
        } else {
            uidnum = geteuid();
        }
        persistent_id = GET_PERSISTENT(uidnum);
        if (persistent_id == -1)
            return KRB5_KCC_INVALID_UID;
        return find_or_create_keyring(persistent_id, KEY_SPEC_PROCESS_KEYRING,
                                      KRCC_PERSISTENT_KEYRING_NAME,
                                      collection_id_out);
    }

    if (strcmp(anchor_name, KRCC_PROCESS_ANCHOR) == 0) {
        anchor_id = KEY_SPEC_PROCESS_KEYRING;
    } else if (strcmp(anchor_name, KRCC_THREAD_ANCHOR) == 0) {
        anchor_id = KEY_SPEC_THREAD_KEYRING;
    } else if (strcmp(anchor_name, KRCC_SESSION_ANCHOR) == 0) {
        anchor_id = session_write_anchor();
    } else if (strcmp(anchor_name, KRCC_USER_ANCHOR) == 0) {
        /* The user keyring does not confer possession, so we need to link the
         * collection to the process keyring to maintain possession rights. */
        anchor_id = KEY_SPEC_USER_KEYRING;
        possess_id = KEY_SPEC_PROCESS_KEYRING;
    } else if (strcmp(anchor_name, KRCC_LEGACY_ANCHOR) == 0) {
        anchor_id = session_write_anchor();
    } else {
        return KRB5_KCC_INVALID_ANCHOR;
    }

    /* Look up the collection keyring name within the anchor keyring. */
    if (asprintf(&ckname, "%s%s", KRCC_CCCOL_PREFIX, collection_name) == -1)
        return ENOMEM;
    ret = find_or_create_keyring(anchor_id, possess_id, ckname,
                                 collection_id_out);
    free(ckname);
    return ret;
}

/* Store subsidiary_name into the primary index key for collection_id. */
static krb5_error_code
set_primary_name(krb5_context context, key_serial_t collection_id,
                 const char *subsidiary_name)
{
    krb5_error_code ret;
    key_serial_t key;
    void *payload = NULL;
    int payloadlen;

    ret = krb5_krcc_unparse_index(context, KRCC_COLLECTION_VERSION,
                                  subsidiary_name, &payload, &payloadlen);
    if (ret)
        return ret;
    key = add_key(KRCC_KEY_TYPE_USER, KRCC_COLLECTION_PRIMARY,
                  payload, payloadlen, collection_id);
    free(payload);
    return (key == -1) ? errno : 0;
}

/*
 * Get or initialize the primary name within collection_id and set
 * *subsidiary_out to its value.  If initializing a legacy collection, look
 * for a legacy cache and add it to the collection.
 */
static krb5_error_code
get_primary_name(krb5_context context, const char *anchor_name,
                 const char *collection_name, key_serial_t collection_id,
                 char **subsidiary_out)
{
    krb5_error_code ret;
    key_serial_t primary_id, legacy;
    void *payload = NULL;
    int payloadlen;
    krb5_int32 version;
    char *subsidiary_name = NULL;

    *subsidiary_out = NULL;

    primary_id = keyctl_search(collection_id, KRCC_KEY_TYPE_USER,
                               KRCC_COLLECTION_PRIMARY, 0);
    if (primary_id == -1) {
        /* Initialize the primary key using the collection name.  We can't name
         * a key with the empty string, so map that to an arbitrary string. */
        subsidiary_name = strdup((*collection_name == '\0') ? "tkt" :
                                 collection_name);
        if (subsidiary_name == NULL) {
            ret = ENOMEM;
            goto cleanup;
        }
        ret = set_primary_name(context, collection_id, subsidiary_name);
        if (ret)
            goto cleanup;

        if (strcmp(anchor_name, KRCC_LEGACY_ANCHOR) == 0) {
            /* Look for a cache created by old code.  If we find one, add it to
             * the collection. */
            legacy = keyctl_search(KEY_SPEC_SESSION_KEYRING,
                                   KRCC_KEY_TYPE_KEYRING, subsidiary_name, 0);
            if (legacy != -1 && keyctl_link(legacy, collection_id) == -1) {
                ret = errno;
                goto cleanup;
            }
        }
    } else {
        /* Read, parse, and free the primary key's payload. */
        payloadlen = keyctl_read_alloc(primary_id, &payload);
        if (payloadlen == -1) {
            ret = errno;
            goto cleanup;
        }
        ret = krb5_krcc_parse_index(context, &version, &subsidiary_name,
                                    payload, payloadlen);
        if (ret)
            goto cleanup;

        if (version != KRCC_COLLECTION_VERSION) {
            ret = KRB5_KCC_UNKNOWN_VERSION;
            goto cleanup;
        }
    }

    *subsidiary_out = subsidiary_name;
    subsidiary_name = NULL;

cleanup:
    free(payload);
    free(subsidiary_name);
    return ret;
}

/*
 * Create a keyring with a unique random name within collection_id.  Set
 * *subsidiary to its name and *cache_id_out to its key serial number.
 */
static krb5_error_code
unique_keyring(krb5_context context, key_serial_t collection_id,
               char **subsidiary_out, key_serial_t *cache_id_out)
{
    key_serial_t key;
    krb5_error_code ret;
    char uniquename[sizeof(KRCC_NAME_PREFIX) + KRCC_NAME_RAND_CHARS];
    int prefixlen = sizeof(KRCC_NAME_PREFIX) - 1;
    int tries;

    *subsidiary_out = NULL;
    *cache_id_out = 0;

    memcpy(uniquename, KRCC_NAME_PREFIX, sizeof(KRCC_NAME_PREFIX));
    k5_cc_mutex_lock(context, &krb5int_krcc_mutex);

    /* Loop until we successfully create a new ccache keyring with
     * a unique name, or we get an error. Limit to 100 tries. */
    tries = 100;
    while (tries-- > 0) {
        ret = krb5int_random_string(context, uniquename + prefixlen,
                                    KRCC_NAME_RAND_CHARS);
        if (ret)
            goto cleanup;

        key = keyctl_search(collection_id, KRCC_KEY_TYPE_KEYRING, uniquename,
                            0);
        if (key < 0) {
            /* Name does not already exist.  Create it to reserve the name. */
            key = add_key(KRCC_KEY_TYPE_KEYRING, uniquename, NULL, 0,
                          collection_id);
            if (key < 0) {
                ret = errno;
                goto cleanup;
            }
            break;
        }
    }

    if (tries <= 0) {
        ret = KRB5_CC_BADNAME;
        goto cleanup;
    }

    *subsidiary_out = strdup(uniquename);
    if (*subsidiary_out == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }
    *cache_id_out = key;
    ret = KRB5_OK;
cleanup:
    k5_cc_mutex_unlock(context, &krb5int_krcc_mutex);
    return ret;
}

static krb5_error_code
add_cred_key(const char *name, const void *payload, size_t plen,
             key_serial_t cache_id, krb5_boolean legacy_type,
             key_serial_t *key_out)
{
    key_serial_t key;

    *key_out = -1;
    if (!legacy_type) {
        /* Try the preferred cred key type; fall back if no kernel support. */
        key = add_key(KRCC_CRED_KEY_TYPE, name, payload, plen, cache_id);
        if (key != -1) {
            *key_out = key;
            return 0;
        } else if (errno != EINVAL && errno != ENODEV) {
            return errno;
        }
    }
    /* Use the user key type. */
    key = add_key(KRCC_KEY_TYPE_USER, name, payload, plen, cache_id);
    if (key == -1)
        return errno;
    *key_out = key;
    return 0;
}

static void
update_keyring_expiration(krb5_context context, krb5_ccache id)
{
    krb5_krcc_data *d = (krb5_krcc_data *)id->data;
    krb5_cc_cursor cursor;
    krb5_creds creds;
    krb5_timestamp now, endtime = 0;
    unsigned int timeout;

    /*
     * We have no way to know what is the actual timeout set on the keyring.
     * We also cannot keep track of it in a local variable as another process
     * can always modify the keyring independently, so just always enumerate
     * all keys and find out the highest endtime time.
     */

    /* Find the maximum endtime of all creds in the cache. */
    if (krb5_krcc_start_seq_get(context, id, &cursor) != 0)
        return;
    for (;;) {
        if (krb5_krcc_next_cred(context, id, &cursor, &creds) != 0)
            break;
        if (creds.times.endtime > endtime)
            endtime = creds.times.endtime;
        krb5_free_cred_contents(context, &creds);
    }
    (void)krb5_krcc_end_seq_get(context, id, &cursor);

    if (endtime == 0)        /* No creds with end times */
        return;

    if (krb5_timeofday(context, &now) != 0)
        return;

    /* Setting the timeout to zero would reset the timeout, so we set it to one
     * second instead if creds are already expired. */
    timeout = (endtime > now) ? endtime - now : 1;
    (void)keyctl_set_timeout(d->cache_id, timeout);
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
    krb5_krcc_data *data = (krb5_krcc_data *)id->data;
    krb5_os_context os_ctx = &context->os_context;
    krb5_error_code kret;
    const char *cache_name, *p;

    DEBUG_PRINT(("krb5_krcc_initialize: entered\n"));

    k5_cc_mutex_lock(context, &data->lock);

    kret = krb5_krcc_clearcache(context, id);
    if (kret != KRB5_OK)
        goto out;

    if (!data->cache_id) {
        /* The key didn't exist at resolve time.  Check again and create the
         * key if it still isn't there. */
        p = strrchr(data->name, ':');
        cache_name = (p != NULL) ? p + 1 : data->name;
        kret = find_or_create_keyring(data->collection_id, 0, cache_name,
                                      &data->cache_id);
        if (kret)
            goto out;
    }

    /* If this is the legacy cache in a legacy session collection, link it
     * directly to the session keyring so that old code can see it. */
    if (is_legacy_cache_name(data->name))
        (void)keyctl_link(data->cache_id, session_write_anchor());

    kret = krb5_krcc_save_principal(context, id, princ);

    /* Save time offset if it is valid and this is not a legacy cache.  Legacy
     * applications would fail to parse the new key in the cache keyring. */
    if (!is_legacy_cache_name(data->name) &&
        (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)) {
        kret = krb5_krcc_save_time_offsets(context, id, os_ctx->time_offset,
                                           os_ctx->usec_offset);
    }

    if (kret == KRB5_OK)
        krb5_change_cache();

out:
    k5_cc_mutex_unlock(context, &data->lock);
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

    DEBUG_PRINT(("krb5_krcc_clearcache: cache_id %d, princ_id %d\n",
                 d->cache_id, d->princ_id));

    if (d->cache_id) {
        res = keyctl_clear(d->cache_id);
        if (res != 0)
            return errno;
    }
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
    krb5_error_code kret = 0;
    krb5_krcc_data *d;
    int     res;

    DEBUG_PRINT(("krb5_krcc_destroy: entered\n"));

    d = (krb5_krcc_data *) id->data;

    k5_cc_mutex_lock(context, &d->lock);

    krb5_krcc_clearcache(context, id);
    if (d->cache_id) {
        res = keyctl_unlink(d->cache_id, d->collection_id);
        if (res < 0) {
            kret = errno;
            DEBUG_PRINT(("unlinking key %d from ring %d: %s",
                         d->cache_id, d->collection_id, error_message(errno)));
        }
        /* If this is a legacy cache, unlink it from the session anchor. */
        if (is_legacy_cache_name(d->name))
            (void)keyctl_unlink(d->cache_id, session_write_anchor());
    }

    k5_cc_mutex_unlock(context, &d->lock);
    k5_cc_mutex_destroy(&d->lock);
    free(d->name);
    free(d);
    free(id);

    krb5_change_cache();

    return kret;
}

/* Create a cache handle for a cache ID. */
static krb5_error_code
make_cache(key_serial_t collection_id, key_serial_t cache_id,
           const char *anchor_name, const char *collection_name,
           const char *subsidiary_name, krb5_ccache *cache_out)
{
    krb5_error_code ret;
    krb5_ccache ccache = NULL;
    krb5_krcc_data *d;
    key_serial_t pkey = 0;

    /* Determine the key containing principal information, if present. */
    pkey = keyctl_search(cache_id, KRCC_KEY_TYPE_USER, KRCC_SPEC_PRINC_KEYNAME,
                         0);
    if (pkey < 0)
        pkey = 0;

    ccache = malloc(sizeof(struct _krb5_ccache));
    if (!ccache)
        return ENOMEM;

    ret = krb5_krcc_new_data(anchor_name, collection_name, subsidiary_name,
                             cache_id, collection_id, &d);
    if (ret) {
        free(ccache);
        return ret;
    }

    d->princ_id = pkey;
    ccache->ops = &krb5_krcc_ops;
    ccache->data = d;
    ccache->magic = KV5M_CCACHE;
    *cache_out = ccache;
    return 0;
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
krb5_krcc_resolve(krb5_context context, krb5_ccache *id, const char *residual)
{
    krb5_os_context os_ctx = &context->os_context;
    krb5_error_code ret;
    key_serial_t collection_id, cache_id;
    char *anchor_name = NULL, *collection_name = NULL, *subsidiary_name = NULL;

    ret = parse_residual(residual, &anchor_name, &collection_name,
                         &subsidiary_name);
    if (ret)
        goto cleanup;
    ret = get_collection(anchor_name, collection_name, &collection_id);
    if (ret)
        goto cleanup;

    if (subsidiary_name == NULL) {
        /* Retrieve or initialize the primary name for the collection. */
        ret = get_primary_name(context, anchor_name, collection_name,
                               collection_id, &subsidiary_name);
        if (ret)
            goto cleanup;
    }

    /* Look up the cache keyring ID, if the cache is already initialized. */
    cache_id = keyctl_search(collection_id, KRCC_KEY_TYPE_KEYRING,
                             subsidiary_name, 0);
    if (cache_id < 0)
        cache_id = 0;

    ret = make_cache(collection_id, cache_id, anchor_name, collection_name,
                     subsidiary_name, id);
    if (ret)
        goto cleanup;

    /* Lookup time offsets if necessary. */
    if ((context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) &&
        !(os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)) {
        if (krb5_krcc_get_time_offsets(context, *id,
                                       &os_ctx->time_offset,
                                       &os_ctx->usec_offset) == 0) {
            os_ctx->os_flags &= ~KRB5_OS_TOFFSET_TIME;
            os_ctx->os_flags |= KRB5_OS_TOFFSET_VALID;
        }
    }

cleanup:
    free(anchor_name);
    free(collection_name);
    free(subsidiary_name);
    return ret;
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
    krb5_krcc_data *d;
    void *keys;
    long size;

    DEBUG_PRINT(("krb5_krcc_start_seq_get: entered\n"));

    d = id->data;
    k5_cc_mutex_lock(context, &d->lock);

    if (!d->cache_id) {
        k5_cc_mutex_unlock(context, &d->lock);
        return KRB5_FCC_NOFILE;
    }

    size = keyctl_read_alloc(d->cache_id, &keys);
    if (size == -1) {
        DEBUG_PRINT(("Error getting from keyring: %s\n", strerror(errno)));
        k5_cc_mutex_unlock(context, &d->lock);
        return KRB5_CC_IO;
    }

    krcursor = calloc(1, sizeof(*krcursor));
    if (krcursor == NULL) {
        free(keys);
        k5_cc_mutex_unlock(context, &d->lock);
        return KRB5_CC_NOMEM;
    }

    krcursor->princ_id = d->princ_id;
    krcursor->offsets_id = keyctl_search(d->cache_id, KRCC_KEY_TYPE_USER,
                                         KRCC_TIME_OFFSETS, 0);
    krcursor->numkeys = size / sizeof(key_serial_t);
    krcursor->keys = keys;

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
    if (krcursor->currkey >= krcursor->numkeys)
        return KRB5_CC_END;

    /* If we're pointing at the entry with the principal, or at the key
     * with the time offsets, skip it. */
    while (krcursor->keys[krcursor->currkey] == krcursor->princ_id ||
           krcursor->keys[krcursor->currkey] == krcursor->offsets_id) {
        krcursor->currkey++;
        /* Check if we have now reached the end */
        if (krcursor->currkey >= krcursor->numkeys)
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

    kret = krb5_krcc_parse_cred(context, creds, payload, psize);

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
    krb5_krcc_cursor krcursor = (krb5_krcc_cursor)*cursor;
    DEBUG_PRINT(("krb5_krcc_end_seq_get: entered\n"));

    if (krcursor != NULL) {
        free(krcursor->keys);
        free(krcursor);
    }
    *cursor = NULL;
    return KRB5_OK;
}

/* Utility routine: Creates the back-end data for a keyring cache.

   Call with the global list lock held.  */
static krb5_error_code
krb5_krcc_new_data(const char *anchor_name, const char *collection_name,
                   const char *subsidiary_name, key_serial_t cache_id,
                   key_serial_t collection_id, krb5_krcc_data **datapp)
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

    kret = make_subsidiary_residual(anchor_name, collection_name,
                                    subsidiary_name, &d->name);
    if (kret) {
        k5_cc_mutex_destroy(&d->lock);
        free(d);
        return kret;
    }
    d->princ_id = 0;
    d->cache_id = cache_id;
    d->collection_id = collection_id;
    d->changetime = 0;
    d->is_legacy_type = (strcmp(anchor_name, KRCC_LEGACY_ANCHOR) == 0);
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
    krb5_ccache lid = NULL;
    krb5_error_code kret;
    char *anchor_name = NULL, *collection_name = NULL, *subsidiary_name = NULL;
    char *new_subsidiary_name = NULL, *new_residual = NULL;
    krb5_krcc_data *d;
    key_serial_t collection_id;
    key_serial_t cache_id = 0;

    DEBUG_PRINT(("krb5_krcc_generate_new: entered\n"));

    /* Determine the collection in which we will create the cache.*/
    kret = get_default(context, &anchor_name, &collection_name,
                       &subsidiary_name);
    if (kret)
        return kret;
    if (anchor_name == NULL) {
        kret = parse_residual(KRCC_DEFAULT_UNIQUE_COLLECTION, &anchor_name,
                              &collection_name, &subsidiary_name);
        if (kret)
            return kret;
    }
    if (subsidiary_name != NULL) {
        krb5_set_error_message(context, KRB5_DCC_CANNOT_CREATE,
                               _("Can't create new subsidiary cache because "
                                 "default cache is already a subsdiary"));
        kret = KRB5_DCC_CANNOT_CREATE;
        goto cleanup;
    }

    /* Allocate memory */
    lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
    if (lid == NULL) {
        kret = ENOMEM;
        goto cleanup;
    }

    lid->ops = &krb5_krcc_ops;

    /* Make a unique keyring within the chosen collection. */
    kret = get_collection(anchor_name, collection_name, &collection_id);
    if (kret)
        goto cleanup;
    kret = unique_keyring(context, collection_id, &new_subsidiary_name,
                          &cache_id);
    if (kret)
        goto cleanup;

    kret = krb5_krcc_new_data(anchor_name, collection_name,
                              new_subsidiary_name, cache_id, collection_id,
                              &d);
    if (kret)
        goto cleanup;

    lid->data = d;
    krb5_change_cache();

cleanup:
    free(anchor_name);
    free(collection_name);
    free(subsidiary_name);
    free(new_subsidiary_name);
    free(new_residual);
    if (kret) {
        free(lid);
        return kret;
    }
    *id = lid;
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

    return k5_cc_retrieve_cred_default(context, id, whichfields, mcreds,
                                       creds);
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
    char   *keyname = NULL;
    key_serial_t cred_key;
    krb5_timestamp now;

    DEBUG_PRINT(("krb5_krcc_store: entered\n"));

    k5_cc_mutex_lock(context, &d->lock);

    if (!d->cache_id) {
        k5_cc_mutex_unlock(context, &d->lock);
        return KRB5_FCC_NOFILE;
    }

    /* Get the service principal name and use it as the key name */
    kret = krb5_unparse_name(context, creds->server, &keyname);
    if (kret) {
        DEBUG_PRINT(("Error unparsing service principal name!\n"));
        goto errout;
    }

    /* Serialize credential into memory */
    kret = krb5_krcc_unparse_cred_alloc(context, creds, &payload, &payloadlen);
    if (kret != KRB5_OK)
        goto errout;

    /* Add new key (credentials) into keyring */
    DEBUG_PRINT(("krb5_krcc_store: adding new key '%s' to keyring %d\n",
                 keyname, d->cache_id));
    kret = add_cred_key(keyname, payload, payloadlen, d->cache_id,
                        d->is_legacy_type, &cred_key);
    if (kret)
        goto errout;

    krb5_krcc_update_change_time(d);

    /* Set appropriate timeouts on cache keys. */
    kret = krb5_timeofday(context, &now);
    if (kret)
        goto errout;

    if (creds->times.endtime > now)
        (void)keyctl_set_timeout(cred_key, creds->times.endtime - now);

    update_keyring_expiration(context, id);

    kret = KRB5_OK;

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
    krb5_krcc_data *data = (krb5_krcc_data *) id->data;

    k5_cc_mutex_lock(context, &data->lock);
    *change_time = data->changetime;
    k5_cc_mutex_unlock(context, &data->lock);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_lock(krb5_context context, krb5_ccache id)
{
    krb5_krcc_data *data = (krb5_krcc_data *) id->data;

    k5_cc_mutex_lock(context, &data->lock);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_unlock(krb5_context context, krb5_ccache id)
{
    krb5_krcc_data *data = (krb5_krcc_data *) id->data;

    k5_cc_mutex_unlock(context, &data->lock);
    return 0;
}


static  krb5_error_code
krb5_krcc_save_principal(krb5_context context, krb5_ccache id,
                         krb5_principal princ)
{
    krb5_krcc_data *d;
    krb5_error_code kret;
    char *payload = NULL;
    key_serial_t newkey;
    unsigned int payloadsize;
    krb5_krcc_bc bc;

    k5_cc_mutex_assert_locked(context, &((krb5_krcc_data *) id->data)->lock);

    d = (krb5_krcc_data *) id->data;

    /* Do a dry run first to calculate the size. */
    bc.bpp = bc.endp = NULL;
    bc.size = 0;
    kret = krb5_krcc_unparse_principal(context, princ, &bc);
    CHECK_N_GO(kret, errout);

    /* Allocate a buffer and serialize for real. */
    payload = malloc(bc.size);
    if (payload == NULL)
        return KRB5_CC_NOMEM;
    bc.bpp = payload;
    bc.endp = payload + bc.size;
    kret = krb5_krcc_unparse_principal(context, princ, &bc);
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
                     KRCC_SPEC_PRINC_KEYNAME, d->cache_id,
                     rc ? "<unknown>" : princname));
        if (rc == 0)
            krb5_free_unparsed_name(context, princname);
    }
#endif
    newkey = add_key(KRCC_KEY_TYPE_USER, KRCC_SPEC_PRINC_KEYNAME, payload,
                     payloadsize, d->cache_id);
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

    k5_cc_mutex_lock(context, &d->lock);

    if (!d->cache_id || !d->princ_id) {
        princ = 0L;
        kret = KRB5_FCC_NOFILE;
        krb5_set_error_message(context, kret,
                               _("Credentials cache keyring '%s' not found"),
                               d->name);
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
    kret = krb5_krcc_parse_principal(context, princ, &bc);

errout:
    if (payload)
        free(payload);
    k5_cc_mutex_unlock(context, &d->lock);
    return kret;
}

static  krb5_error_code
krb5_krcc_save_time_offsets(krb5_context context, krb5_ccache id,
                            krb5_int32 time_offset, krb5_int32 usec_offset)
{
    krb5_krcc_data *d = (krb5_krcc_data *)id->data;
    krb5_error_code kret;
    key_serial_t newkey;
    void *payload = NULL;
    int psize;

    k5_cc_mutex_assert_locked(context, &d->lock);

    /* Prepare the payload. */
    kret = krb5_krcc_unparse_offsets(context, time_offset, usec_offset,
                                     &payload, &psize);
    CHECK_N_GO(kret, errout);

    /* Add new key into keyring. */
    newkey = add_key(KRCC_KEY_TYPE_USER, KRCC_TIME_OFFSETS, payload, psize,
                     d->cache_id);
    if (newkey == -1) {
        kret = errno;
        DEBUG_PRINT(("Error adding time offsets key: %s\n", strerror(kret)));
    } else {
        kret = KRB5_OK;
        krb5_krcc_update_change_time(d);
    }

errout:
    free(payload);
    return kret;
}

static krb5_error_code
krb5_krcc_get_time_offsets(krb5_context context, krb5_ccache id,
                           krb5_int32 *time_offset, krb5_int32 *usec_offset)
{
    krb5_krcc_data *d = (krb5_krcc_data *)id->data;
    krb5_error_code kret;
    key_serial_t key;
    krb5_int32 t, u;
    void *payload = NULL;
    int psize;

    k5_cc_mutex_lock(context, &d->lock);

    if (!d->cache_id) {
        kret = KRB5_FCC_NOFILE;
        goto errout;
    }

    key = keyctl_search(d->cache_id, KRCC_KEY_TYPE_USER, KRCC_TIME_OFFSETS, 0);
    if (key == -1) {
        kret = ENOENT;
        goto errout;
    }

    psize = keyctl_read_alloc(key, &payload);
    if (psize == -1) {
        DEBUG_PRINT(("Reading time offsets key %d: %s\n",
                     key, strerror(errno)));
        kret = KRB5_CC_IO;
        goto errout;
    }

    kret = krb5_krcc_parse_offsets(context, &t, &u, payload, psize);
    if (kret)
        goto errout;

    *time_offset = t;
    *usec_offset = u;

errout:
    free(payload);
    k5_cc_mutex_unlock(context, &d->lock);
    return kret;
}

struct krcc_ptcursor_data {
    key_serial_t collection_id;
    char *anchor_name;
    char *collection_name;
    char *subsidiary_name;
    char *primary_name;
    krb5_boolean first;
    long num_keys;
    long next_key;
    key_serial_t *keys;
};

static krb5_error_code KRB5_CALLCONV
krb5_krcc_ptcursor_new(krb5_context context, krb5_cc_ptcursor *cursor_out)
{
    struct krcc_ptcursor_data *data;
    krb5_cc_ptcursor cursor;
    krb5_error_code ret;
    long size;

    *cursor_out = NULL;

    cursor = k5alloc(sizeof(struct krb5_cc_ptcursor_s), &ret);
    if (cursor == NULL)
        return ENOMEM;
    data = k5alloc(sizeof(struct krcc_ptcursor_data), &ret);
    if (data == NULL)
        goto error;
    cursor->ops = &krb5_krcc_ops;
    cursor->data = data;
    data->first = TRUE;

    ret = get_default(context, &data->anchor_name, &data->collection_name,
                      &data->subsidiary_name);
    if (ret)
        goto error;

    /* If there is no default collection, return an empty cursor. */
    if (data->anchor_name == NULL) {
        *cursor_out = cursor;
        return 0;
    }

    ret = get_collection(data->anchor_name, data->collection_name,
                         &data->collection_id);
    if (ret)
        goto error;

    if (data->subsidiary_name == NULL) {
        ret = get_primary_name(context, data->anchor_name,
                               data->collection_name, data->collection_id,
                               &data->primary_name);
        if (ret)
            goto error;

        size = keyctl_read_alloc(data->collection_id, (void **)&data->keys);
        if (size == -1) {
            ret = errno;
            goto error;
        }
        data->num_keys = size / sizeof(key_serial_t);
    }

    *cursor_out = cursor;
    return 0;

error:
    krb5_krcc_ptcursor_free(context, &cursor);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_ptcursor_next(krb5_context context, krb5_cc_ptcursor cursor,
                        krb5_ccache *cache_out)
{
    krb5_error_code ret;
    struct krcc_ptcursor_data *data;
    key_serial_t key, cache_id = 0;
    const char *first_name, *keytype, *sep, *subsidiary_name;
    size_t keytypelen;
    char *description = NULL;

    *cache_out = NULL;

    data = cursor->data;

    /* No keyring available */
    if (data->collection_id == 0)
        return 0;

    if (data->first) {
        /* Look for the primary cache for a collection cursor, or the
         * subsidiary cache for a subsidiary cursor. */
        data->first = FALSE;
        first_name = (data->primary_name != NULL) ? data->primary_name :
            data->subsidiary_name;
        cache_id = keyctl_search(data->collection_id, KRCC_KEY_TYPE_KEYRING,
                                 first_name, 0);
        if (cache_id != -1) {
            return make_cache(data->collection_id, cache_id, data->anchor_name,
                              data->collection_name, first_name, cache_out);
        }
    }

    /* A subsidiary cursor yields at most the first cache. */
    if (data->subsidiary_name != NULL)
        return 0;

    keytype = KRCC_KEY_TYPE_KEYRING ";";
    keytypelen = strlen(keytype);

    for (; data->next_key < data->num_keys; data->next_key++) {
        /* Free any previously retrieved key description. */
        free(description);
        description = NULL;

        /*
         * Get the key description, which should have the form:
         *   typename;UID;GID;permissions;description
         */
        key = data->keys[data->next_key];
        if (keyctl_describe_alloc(key, &description) < 0)
            continue;
        sep = strrchr(description, ';');
        if (sep == NULL)
            continue;
        subsidiary_name = sep + 1;

        /* Skip this key if it isn't a keyring. */
        if (strncmp(description, keytype, keytypelen) != 0)
            continue;

        /* Don't repeat the primary cache. */
        if (strcmp(subsidiary_name, data->primary_name) == 0)
            continue;

        /* We found a valid key */
        data->next_key++;
        ret = make_cache(data->collection_id, key, data->anchor_name,
                         data->collection_name, subsidiary_name, cache_out);
        free(description);
        return ret;
    }

    free(description);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_ptcursor_free(krb5_context context, krb5_cc_ptcursor *cursor)
{
    struct krcc_ptcursor_data *data = (*cursor)->data;

    if (data != NULL) {
        free(data->anchor_name);
        free(data->collection_name);
        free(data->subsidiary_name);
        free(data->primary_name);
        free(data->keys);
        free(data);
    }
    free(*cursor);
    *cursor = NULL;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
krb5_krcc_switch_to(krb5_context context, krb5_ccache cache)
{
    krb5_krcc_data *data = cache->data;
    krb5_error_code ret;
    char *anchor_name = NULL, *collection_name = NULL, *subsidiary_name = NULL;
    key_serial_t collection_id;

    ret = parse_residual(data->name, &anchor_name, &collection_name,
                         &subsidiary_name);
    if (ret)
        goto cleanup;
    ret = get_collection(anchor_name, collection_name, &collection_id);
    if (ret)
        goto cleanup;
    ret = set_primary_name(context, collection_id, subsidiary_name);
cleanup:
    free(anchor_name);
    free(collection_name);
    free(subsidiary_name);
    return ret;
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
krb5_krcc_parse(krb5_context context, krb5_pointer buf, unsigned int len,
                krb5_krcc_bc * bc)
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
krb5_krcc_parse_cred(krb5_context context, krb5_creds * creds, char *payload,
                     int psize)
{
    krb5_error_code kret;
    krb5_octet octet;
    krb5_int32 int32;
    krb5_krcc_bc bc;

    /* Parse the pieces of the credential */
    bc.bpp = payload;
    bc.endp = bc.bpp + psize;
    kret = krb5_krcc_parse_principal(context, &creds->client, &bc);
    CHECK_N_GO(kret, out);

    kret = krb5_krcc_parse_principal(context, &creds->server, &bc);
    CHECK_N_GO(kret, cleanclient);

    kret = krb5_krcc_parse_keyblock(context, &creds->keyblock, &bc);
    CHECK_N_GO(kret, cleanserver);

    kret = krb5_krcc_parse_times(context, &creds->times, &bc);
    CHECK_N_GO(kret, cleanserver);

    kret = krb5_krcc_parse_octet(context, &octet, &bc);
    CHECK_N_GO(kret, cleanserver);
    creds->is_skey = octet;

    kret = krb5_krcc_parse_int32(context, &int32, &bc);
    CHECK_N_GO(kret, cleanserver);
    creds->ticket_flags = int32;

    kret = krb5_krcc_parse_addrs(context, &creds->addresses, &bc);
    CHECK_N_GO(kret, cleanblock);

    kret = krb5_krcc_parse_authdata(context, &creds->authdata, &bc);
    CHECK_N_GO(kret, cleanaddrs);

    kret = krb5_krcc_parse_krb5data(context, &creds->ticket, &bc);
    CHECK_N_GO(kret, cleanauthdata);

    kret = krb5_krcc_parse_krb5data(context, &creds->second_ticket, &bc);
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
krb5_krcc_parse_principal(krb5_context context, krb5_principal * princ,
                          krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    register krb5_principal tmpprinc;
    krb5_int32 length, type;
    int     i;

    /* Read principal type */
    kret = krb5_krcc_parse_int32(context, &type, bc);
    if (kret != KRB5_OK)
        return kret;

    /* Read the number of components */
    kret = krb5_krcc_parse_int32(context, &length, bc);
    if (kret != KRB5_OK)
        return kret;

    if (length < 0)
        return KRB5_CC_NOMEM;

    tmpprinc = (krb5_principal) malloc(sizeof(krb5_principal_data));
    if (tmpprinc == NULL)
        return KRB5_CC_NOMEM;
    if (length) {
        tmpprinc->data = calloc(length, sizeof(krb5_data));
        if (tmpprinc->data == 0) {
            free(tmpprinc);
            return KRB5_CC_NOMEM;
        }
    } else
        tmpprinc->data = 0;
    tmpprinc->magic = KV5M_PRINCIPAL;
    tmpprinc->length = length;
    tmpprinc->type = type;

    kret = krb5_krcc_parse_krb5data(context, &tmpprinc->realm, bc);
    i = 0;
    CHECK(kret);

    for (i = 0; i < length; i++) {
        kret = krb5_krcc_parse_krb5data(context, &tmpprinc->data[i], bc);
        CHECK(kret);
    }
    *princ = tmpprinc;
    return KRB5_OK;

errout:
    while (--i >= 0)
        free(tmpprinc->data[i].data);
    free(tmpprinc->realm.data);
    free(tmpprinc->data);
    free(tmpprinc);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_keyblock(krb5_context context, krb5_keyblock * keyblock,
                         krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_ui_2 ui2;
    krb5_int32 int32;

    keyblock->magic = KV5M_KEYBLOCK;
    keyblock->contents = 0;

    kret = krb5_krcc_parse_ui_2(context, &ui2, bc);
    CHECK(kret);
    keyblock->enctype = ui2;

    kret = krb5_krcc_parse_int32(context, &int32, bc);
    CHECK(kret);
    if (int32 < 0)
        return KRB5_CC_NOMEM;
    keyblock->length = int32;
    if (keyblock->length == 0)
        return KRB5_OK;
    keyblock->contents = malloc(keyblock->length);
    if (keyblock->contents == NULL)
        return KRB5_CC_NOMEM;

    kret = krb5_krcc_parse(context, keyblock->contents, keyblock->length, bc);
    CHECK(kret);

    return KRB5_OK;
errout:
    if (keyblock->contents)
        free(keyblock->contents);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_times(krb5_context context, krb5_ticket_times * t,
                      krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 i;

    kret = krb5_krcc_parse_int32(context, &i, bc);
    CHECK(kret);
    t->authtime = i;

    kret = krb5_krcc_parse_int32(context, &i, bc);
    CHECK(kret);
    t->starttime = i;

    kret = krb5_krcc_parse_int32(context, &i, bc);
    CHECK(kret);
    t->endtime = i;

    kret = krb5_krcc_parse_int32(context, &i, bc);
    CHECK(kret);
    t->renew_till = i;

    return 0;
errout:
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_krb5data(krb5_context context, krb5_data * data,
                         krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 len;

    data->magic = KV5M_DATA;
    data->data = 0;

    kret = krb5_krcc_parse_int32(context, &len, bc);
    CHECK(kret);
    if (len < 0)
        return KRB5_CC_NOMEM;
    data->length = len;
    if (data->length + 1 == 0)
        return KRB5_CC_NOMEM;

    if (data->length == 0) {
        data->data = 0;
        return KRB5_OK;
    }

    data->data = (char *) malloc(data->length + 1);
    if (data->data == NULL)
        return KRB5_CC_NOMEM;

    kret = krb5_krcc_parse(context, data->data, (unsigned) data->length, bc);
    CHECK(kret);

    data->data[data->length] = 0;       /* Null terminate, just in case.... */
    return KRB5_OK;
errout:
    if (data->data)
        free(data->data);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_int32(krb5_context context, krb5_int32 * i, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    unsigned char buf[4];

    kret = krb5_krcc_parse(context, buf, 4, bc);
    if (kret)
        return kret;
    *i = load_32_be(buf);
    return 0;
}

static  krb5_error_code
krb5_krcc_parse_octet(krb5_context context, krb5_octet * i, krb5_krcc_bc * bc)
{
    return krb5_krcc_parse(context, (krb5_pointer) i, 1, bc);
}

static  krb5_error_code
krb5_krcc_parse_addrs(krb5_context context, krb5_address *** addrs,
                      krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 length;
    size_t  msize;
    int     i;

    *addrs = 0;

    /* Read the number of components */
    kret = krb5_krcc_parse_int32(context, &length, bc);
    CHECK(kret);

    /*
     * Make *addrs able to hold length pointers to krb5_address structs
     * Add one extra for a null-terminated list
     */
    msize = (size_t)length + 1;
    if (msize == 0 || length < 0)
        return KRB5_CC_NOMEM;
    *addrs = calloc(msize, sizeof(krb5_address *));
    if (*addrs == NULL)
        return KRB5_CC_NOMEM;

    for (i = 0; i < length; i++) {
        (*addrs)[i] = (krb5_address *) malloc(sizeof(krb5_address));
        if ((*addrs)[i] == NULL) {
            krb5_free_addresses(context, *addrs);
            return KRB5_CC_NOMEM;
        }
        kret = krb5_krcc_parse_addr(context, (*addrs)[i], bc);
        CHECK(kret);
    }

    return KRB5_OK;
errout:
    if (*addrs)
        krb5_free_addresses(context, *addrs);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_addr(krb5_context context, krb5_address * addr,
                     krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_ui_2 ui2;
    krb5_int32 int32;

    addr->magic = KV5M_ADDRESS;
    addr->contents = 0;

    kret = krb5_krcc_parse_ui_2(context, &ui2, bc);
    CHECK(kret);
    addr->addrtype = ui2;

    kret = krb5_krcc_parse_int32(context, &int32, bc);
    CHECK(kret);
    if ((int32 & VALID_INT_BITS) != int32)      /* Overflow int??? */
        return KRB5_CC_NOMEM;
    addr->length = int32;
    if (addr->length == 0)
        return KRB5_OK;

    addr->contents = (krb5_octet *) malloc(addr->length);
    if (addr->contents == NULL)
        return KRB5_CC_NOMEM;

    kret = krb5_krcc_parse(context, addr->contents, addr->length, bc);
    CHECK(kret);

    return KRB5_OK;
errout:
    if (addr->contents)
        free(addr->contents);
    return kret;
}

static  krb5_error_code
krb5_krcc_parse_authdata(krb5_context context, krb5_authdata *** a,
                         krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 length;
    size_t  msize;
    int     i;

    *a = 0;

    /* Read the number of components */
    kret = krb5_krcc_parse_int32(context, &length, bc);
    CHECK(kret);

    if (length == 0)
        return KRB5_OK;

    /*
     * Make *a able to hold length pointers to krb5_authdata structs
     * Add one extra for a null-terminated list
     */
    msize = (size_t)length + 1;
    if (msize == 0 || length < 0)
        return KRB5_CC_NOMEM;
    *a = calloc(msize, sizeof(krb5_authdata *));
    if (*a == NULL)
        return KRB5_CC_NOMEM;

    for (i = 0; i < length; i++) {
        (*a)[i] = (krb5_authdata *) malloc(sizeof(krb5_authdata));
        if ((*a)[i] == NULL) {
            krb5_free_authdata(context, *a);
            *a = NULL;
            return KRB5_CC_NOMEM;
        }
        kret = krb5_krcc_parse_authdatum(context, (*a)[i], bc);
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
krb5_krcc_parse_authdatum(krb5_context context, krb5_authdata * a,
                          krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 int32;
    krb5_ui_2 ui2;

    a->magic = KV5M_AUTHDATA;
    a->contents = NULL;

    kret = krb5_krcc_parse_ui_2(context, &ui2, bc);
    CHECK(kret);
    a->ad_type = (krb5_authdatatype) ui2;
    kret = krb5_krcc_parse_int32(context, &int32, bc);
    CHECK(kret);
    if ((int32 & VALID_INT_BITS) != int32)      /* Overflow int??? */
        return KRB5_CC_NOMEM;
    a->length = int32;
    if (a->length == 0)
        return KRB5_OK;

    a->contents = (krb5_octet *) malloc(a->length);
    if (a->contents == NULL)
        return KRB5_CC_NOMEM;

    kret = krb5_krcc_parse(context, a->contents, a->length, bc);
    CHECK(kret);

    return KRB5_OK;
errout:
    if (a->contents)
        free(a->contents);
    return kret;

}

static  krb5_error_code
krb5_krcc_parse_ui_2(krb5_context context, krb5_ui_2 * i, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    unsigned char buf[2];

    kret = krb5_krcc_parse(context, buf, 2, bc);
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
krb5_krcc_unparse(krb5_context context, krb5_pointer buf, unsigned int len,
                  krb5_krcc_bc * bc)
{
    if (bc->bpp == NULL) {
        /* This is a dry run; just increase size and return. */
        bc->size += len;
        return KRB5_OK;
    }

    if (bc->bpp + len > bc->endp)
        return KRB5_CC_WRITE;

    memcpy(bc->bpp, buf, len);
    bc->bpp += len;

    return KRB5_OK;
}

static  krb5_error_code
krb5_krcc_unparse_principal(krb5_context context, krb5_principal princ,
                            krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_int32 i, length, tmp, type;

    type = princ->type;
    tmp = length = princ->length;

    kret = krb5_krcc_unparse_int32(context, type, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_int32(context, tmp, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_krb5data(context, &princ->realm, bc);
    CHECK_OUT(kret);

    for (i = 0; i < length; i++) {
        kret = krb5_krcc_unparse_krb5data(context, &princ->data[i], bc);
        CHECK_OUT(kret);
    }

    return KRB5_OK;
}

static  krb5_error_code
krb5_krcc_unparse_keyblock(krb5_context context, krb5_keyblock * keyblock,
                           krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_ui_2(context, keyblock->enctype, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_ui_4(context, keyblock->length, bc);
    CHECK_OUT(kret);
    return krb5_krcc_unparse(context, (char *) keyblock->contents,
                             keyblock->length, bc);
}

static  krb5_error_code
krb5_krcc_unparse_times(krb5_context context, krb5_ticket_times * t,
                        krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_int32(context, t->authtime, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_int32(context, t->starttime, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_int32(context, t->endtime, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_int32(context, t->renew_till, bc);
    CHECK_OUT(kret);
    return 0;
}

static  krb5_error_code
krb5_krcc_unparse_krb5data(krb5_context context, krb5_data * data,
                           krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_ui_4(context, data->length, bc);
    CHECK_OUT(kret);
    return krb5_krcc_unparse(context, data->data, data->length, bc);
}

static  krb5_error_code
krb5_krcc_unparse_int32(krb5_context context, krb5_int32 i, krb5_krcc_bc * bc)
{
    return krb5_krcc_unparse_ui_4(context, (krb5_ui_4) i, bc);
}

static  krb5_error_code
krb5_krcc_unparse_octet(krb5_context context, krb5_int32 i, krb5_krcc_bc * bc)
{
    krb5_octet ibuf;

    ibuf = (krb5_octet) i;
    return krb5_krcc_unparse(context, (char *) &ibuf, 1, bc);
}

static  krb5_error_code
krb5_krcc_unparse_addrs(krb5_context context, krb5_address ** addrs,
                        krb5_krcc_bc * bc)
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

    kret = krb5_krcc_unparse_int32(context, length, bc);
    CHECK_OUT(kret);
    for (i = 0; i < length; i++) {
        kret = krb5_krcc_unparse_addr(context, addrs[i], bc);
        CHECK_OUT(kret);
    }

    return KRB5_OK;
}

static  krb5_error_code
krb5_krcc_unparse_addr(krb5_context context, krb5_address * addr,
                       krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_ui_2(context, addr->addrtype, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_ui_4(context, addr->length, bc);
    CHECK_OUT(kret);
    return krb5_krcc_unparse(context, (char *) addr->contents,
                             addr->length, bc);
}

static  krb5_error_code
krb5_krcc_unparse_authdata(krb5_context context,
                           krb5_authdata ** a, krb5_krcc_bc * bc)
{
    krb5_error_code kret;
    krb5_authdata **temp;
    krb5_int32 i, length = 0;

    if (a != NULL) {
        for (temp = a; *temp; temp++)
            length++;
    }

    kret = krb5_krcc_unparse_int32(context, length, bc);
    CHECK_OUT(kret);
    for (i = 0; i < length; i++) {
        kret = krb5_krcc_unparse_authdatum(context, a[i], bc);
        CHECK_OUT(kret);
    }
    return KRB5_OK;
}

static  krb5_error_code
krb5_krcc_unparse_authdatum(krb5_context context, krb5_authdata * a,
                            krb5_krcc_bc * bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_ui_2(context, a->ad_type, bc);
    CHECK_OUT(kret);
    kret = krb5_krcc_unparse_ui_4(context, a->length, bc);
    CHECK_OUT(kret);
    return krb5_krcc_unparse(context, (krb5_pointer) a->contents,
                             a->length, bc);
}

static  krb5_error_code
krb5_krcc_unparse_ui_4(krb5_context context, krb5_ui_4 i, krb5_krcc_bc * bc)
{
    unsigned char buf[4];

    store_32_be(i, buf);
    return krb5_krcc_unparse(context, buf, 4, bc);
}

static  krb5_error_code
krb5_krcc_unparse_ui_2(krb5_context context, krb5_int32 i, krb5_krcc_bc * bc)
{
    unsigned char buf[2];

    store_16_be(i, buf);
    return krb5_krcc_unparse(context, buf, 2, bc);
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
krb5_krcc_unparse_cred(krb5_context context, krb5_creds * creds,
                       krb5_krcc_bc *bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_principal(context, creds->client, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_principal(context, creds->server, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_keyblock(context, &creds->keyblock, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_times(context, &creds->times, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_octet(context, (krb5_int32) creds->is_skey, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_int32(context, creds->ticket_flags, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_addrs(context, creds->addresses, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_authdata(context, creds->authdata, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_krb5data(context, &creds->ticket, bc);
    CHECK_OUT(kret);
    CHECK(kret);

    kret = krb5_krcc_unparse_krb5data(context, &creds->second_ticket, bc);
    CHECK_OUT(kret);

    /* Success! */
    kret = KRB5_OK;

errout:
    return kret;
}

static  krb5_error_code
krb5_krcc_unparse_cred_alloc(krb5_context context, krb5_creds * creds,
                             char **datapp, unsigned int *lenptr)
{
    krb5_error_code kret;
    char *buf = NULL;
    krb5_krcc_bc bc;

    if (!creds || !datapp || !lenptr)
        return EINVAL;

    *datapp = NULL;
    *lenptr = 0;

    /* Do a dry run first to calculate the size. */
    bc.bpp = bc.endp = NULL;
    bc.size = 0;
    kret = krb5_krcc_unparse_cred(context, creds, &bc);
    CHECK(kret);
    if (bc.size > MAX_CRED_SIZE)
        return KRB5_CC_WRITE;

    /* Allocate a buffer and unparse for real. */
    buf = malloc(bc.size);
    if (buf == NULL)
        return KRB5_CC_NOMEM;
    bc.bpp = buf;
    bc.endp = buf + bc.size;
    kret = krb5_krcc_unparse_cred(context, creds, &bc);
    CHECK(kret);

    /* Success! */
    *datapp = buf;
    *lenptr = bc.bpp - buf;
    buf = NULL;
    kret = KRB5_OK;

errout:
    free(buf);
    return kret;
}

static krb5_error_code
krb5_krcc_parse_index(krb5_context context, krb5_int32 *version,
                      char **primary, void *payload, int psize)
{
    krb5_error_code kret;
    krb5_krcc_bc bc;
    krb5_data data;

    bc.bpp = payload;
    bc.endp = bc.bpp + psize;

    kret = krb5_krcc_parse_int32(context, version, &bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_parse_krb5data(context, &data, &bc);
    CHECK_OUT(kret);

    *primary = (char *)data.data;
    return KRB5_OK;
}

static krb5_error_code
krb5_krcc_unparse_index_internal(krb5_context context, krb5_int32 version,
                                 const char *primary, krb5_krcc_bc *bc)
{
    krb5_error_code kret;
    krb5_data data;

    data.length = strlen(primary) + 1;
    data.data = (void *)primary;

    kret = krb5_krcc_unparse_int32(context, version, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_krb5data(context, &data, bc);
    CHECK_OUT(kret);

    return KRB5_OK;
}

static krb5_error_code
krb5_krcc_unparse_index(krb5_context context, krb5_int32 version,
                        const char *primary, void **datapp, int *lenptr)
{
    krb5_error_code kret;
    krb5_krcc_bc bc;
    char *buf;

    if (!primary || !datapp || !lenptr)
        return EINVAL;

    *datapp = NULL;
    *lenptr = 0;

    /* Do a dry run first to calculate the size. */
    bc.bpp = bc.endp = NULL;
    bc.size = 0;
    kret = krb5_krcc_unparse_index_internal(context, version, primary, &bc);
    CHECK_OUT(kret);

    buf = malloc(bc.size);
    if (buf == NULL)
        return ENOMEM;

    bc.bpp = buf;
    bc.endp = buf + bc.size;
    kret = krb5_krcc_unparse_index_internal(context, version, primary, &bc);
    CHECK(kret);

    /* Success! */
    *datapp = buf;
    *lenptr = bc.bpp - buf;
    kret = KRB5_OK;

errout:
    if (kret)
        free(buf);
    return kret;
}

static krb5_error_code
krb5_krcc_parse_offsets(krb5_context context, krb5_int32 *time_offset,
                        krb5_int32 *usec_offset, void *payload, int psize)
{
    krb5_error_code kret;
    krb5_krcc_bc bc;

    bc.bpp = payload;
    bc.endp = bc.bpp + psize;

    kret = krb5_krcc_parse_int32(context, time_offset, &bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_parse_int32(context, usec_offset, &bc);
    CHECK_OUT(kret);

    return KRB5_OK;
}

static krb5_error_code
krb5_krcc_unparse_offsets_internal(krb5_context context,
                                   krb5_int32 time_offset,
                                   krb5_int32 usec_offset,
                                   krb5_krcc_bc *bc)
{
    krb5_error_code kret;

    kret = krb5_krcc_unparse_int32(context, time_offset, bc);
    CHECK_OUT(kret);

    kret = krb5_krcc_unparse_int32(context, usec_offset, bc);
    CHECK_OUT(kret);

    return KRB5_OK;
}

static krb5_error_code
krb5_krcc_unparse_offsets(krb5_context context, krb5_int32 time_offset,
                          krb5_int32 usec_offset, void **datapp, int *lenptr)
{
    krb5_error_code kret;
    krb5_krcc_bc bc;
    char *buf;

    if (!datapp || !lenptr)
        return EINVAL;

    *datapp = NULL;
    *lenptr = 0;

    /* Do a dry run first to calculate the size. */
    bc.bpp = bc.endp = NULL;
    bc.size = 0;
    kret = krb5_krcc_unparse_offsets_internal(context, time_offset,
                                              usec_offset, &bc);
    CHECK_OUT(kret);

    buf = malloc(bc.size);
    if (buf == NULL)
        return ENOMEM;

    bc.bpp = buf;
    bc.endp = buf + bc.size;
    kret = krb5_krcc_unparse_offsets_internal(context, time_offset,
                                              usec_offset, &bc);
    CHECK(kret);

    /* Success! */
    *datapp = buf;
    *lenptr = bc.bpp - buf;
    kret = KRB5_OK;

errout:
    if (kret)
        free(buf);
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
    krb5_krcc_ptcursor_new,
    krb5_krcc_ptcursor_next,
    krb5_krcc_ptcursor_free,
    NULL, /* move */
    krb5_krcc_last_change_time, /* lastchange */
    NULL, /* wasdefault */
    krb5_krcc_lock,
    krb5_krcc_unlock,
    krb5_krcc_switch_to,
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
    NULL,
};
#endif  /* USE_KEYRING_CCACHE */
