/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * prng_yarrow.c
 *
 * Copyright (C) 2001, 2002, 2004, 2007, 2008, 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
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
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "prng.h"
#include "enc_provider.h"
#include <assert.h>
#include "k5-thread.h"

#include "yarrow.h"
static Yarrow_CTX y_ctx;
#define yarrow_lock krb5int_yarrow_lock
k5_mutex_t yarrow_lock = K5_MUTEX_PARTIAL_INITIALIZER;

/* Helper function to estimate entropy based on sample length
 * and where it comes from.
 */

static size_t
entropy_estimate(unsigned int randsource, size_t length)
{
    switch (randsource) {
    case KRB5_C_RANDSOURCE_OLDAPI:
        return 4 * length;
    case KRB5_C_RANDSOURCE_OSRAND:
        return 8 * length;
    case KRB5_C_RANDSOURCE_TRUSTEDPARTY:
        return 4 * length;
    case KRB5_C_RANDSOURCE_TIMING:
        return 2;
    case KRB5_C_RANDSOURCE_EXTERNAL_PROTOCOL:
        return 0;
    default:
        abort();
    }
    return 0;
}

static int
yarrow_init(void)
{
    unsigned i, source_id;
    int yerr;

    yerr = k5_mutex_finish_init(&yarrow_lock);
    if (yerr)
        return yerr;

    yerr = krb5int_yarrow_init (&y_ctx, NULL);
    if (yerr != YARROW_OK && yerr != YARROW_NOT_SEEDED)
        return KRB5_CRYPTO_INTERNAL;

    for (i=0; i < KRB5_C_RANDSOURCE_MAX; i++ ) {
        if (krb5int_yarrow_new_source(&y_ctx, &source_id) != YARROW_OK)
            return KRB5_CRYPTO_INTERNAL;
        assert (source_id == i);
    }

    return 0;
}

static krb5_error_code
yarrow_add_entropy(krb5_context context, unsigned int randsource,
                          const krb5_data *data)
{
    int yerr;
    /* Make sure the mutex got initialized.  */
    yerr = krb5int_crypto_init();
    if (yerr)
        return yerr;
    /* Now, finally, feed in the data.  */
    yerr = krb5int_yarrow_input(&y_ctx, randsource,
                                data->data, data->length,
                                entropy_estimate(randsource, data->length));
    if (yerr != YARROW_OK)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}
/*
static krb5_error_code
yarrow_seed(krb5_context context, krb5_data *data)
{
    return yarrow_add_entropy(context, KRB5_C_RANDSOURCE_OLDAPI, data);
}
*/
static krb5_error_code
yarrow_make_octets(krb5_context context, krb5_data *data)
{
    int yerr;
    yerr = krb5int_yarrow_output(&y_ctx, data->data, data->length);
    if (yerr == YARROW_NOT_SEEDED) {
        yerr = krb5int_yarrow_reseed(&y_ctx, YARROW_SLOW_POOL);
        if (yerr == YARROW_OK)
            yerr = krb5int_yarrow_output(&y_ctx, data->data, data->length);
    }
    if (yerr != YARROW_OK)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

static void
yarrow_cleanup (void)
{
    krb5int_yarrow_final (&y_ctx);
    k5_mutex_destroy(&yarrow_lock);
}

const struct krb5_prng_provider krb5int_prng_yarrow = {
    "yarrow",
    yarrow_make_octets,
    yarrow_add_entropy,
    yarrow_init,
    yarrow_cleanup
};
