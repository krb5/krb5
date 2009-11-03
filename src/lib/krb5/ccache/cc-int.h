/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/ccache/file/cc-int.h
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * This file contains constant and function declarations used in the
 * file-based credential cache routines.
 */

#ifndef __KRB5_CCACHE_H__
#define __KRB5_CCACHE_H__

#include "k5-int.h"

krb5_boolean
krb5int_cc_creds_match_request(krb5_context, krb5_flags whichfields, krb5_creds *mcreds, krb5_creds *creds);

int
krb5int_cc_initialize(void);

void
krb5int_cc_finalize(void);

krb5_error_code krb5int_random_string (krb5_context, char *, unsigned int);

/*
 * Cursor for iterating over ccache types
 */
struct krb5_cc_typecursor;
typedef struct krb5_cc_typecursor *krb5_cc_typecursor;

krb5_error_code
krb5int_cc_typecursor_new(krb5_context context, krb5_cc_typecursor *cursor);

krb5_error_code
krb5int_cc_typecursor_next(
    krb5_context context,
    krb5_cc_typecursor cursor,
    const struct _krb5_cc_ops **ops);

krb5_error_code
krb5int_cc_typecursor_free(
    krb5_context context,
    krb5_cc_typecursor *cursor);

/* reentrant mutex used by krb5_cc_* functions */
typedef struct _k5_cc_mutex {
    k5_mutex_t lock;
    krb5_context owner;
    krb5_int32 refcount;
} k5_cc_mutex;

#define K5_CC_MUTEX_PARTIAL_INITIALIZER         \
    { K5_MUTEX_PARTIAL_INITIALIZER, NULL, 0 }

krb5_error_code
k5_cc_mutex_init(k5_cc_mutex *m);

krb5_error_code
k5_cc_mutex_finish_init(k5_cc_mutex *m);

#define k5_cc_mutex_destroy(M)                  \
    k5_mutex_destroy(&(M)->lock);

void
k5_cc_mutex_assert_locked(krb5_context context, k5_cc_mutex *m);

void
k5_cc_mutex_assert_unlocked(krb5_context context, k5_cc_mutex *m);

krb5_error_code
k5_cc_mutex_lock(krb5_context context, k5_cc_mutex *m);

krb5_error_code
k5_cc_mutex_unlock(krb5_context context, k5_cc_mutex *m);

extern k5_cc_mutex krb5int_mcc_mutex;
extern k5_cc_mutex krb5int_krcc_mutex;
extern k5_cc_mutex krb5int_cc_file_mutex;

#ifdef USE_CCAPI_V3
extern krb5_error_code KRB5_CALLCONV krb5_stdccv3_context_lock
(krb5_context context);

extern krb5_error_code KRB5_CALLCONV krb5_stdccv3_context_unlock
(krb5_context context);
#endif

krb5_error_code
k5_cc_mutex_force_unlock(k5_cc_mutex *m);

krb5_error_code
k5_cccol_force_unlock(void);

#endif /* __KRB5_CCACHE_H__ */
