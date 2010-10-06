/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * prng_nss.c
 *
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
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
#include <assert.h>
#include "k5-thread.h"

#ifdef CRYPTO_IMPL_NSS

/*
 * Using Yarrow with NSS is a bit problematic because the MD5 contexts it holds
 * open for the entropy pools would be invalidated by a fork(), causing us to
 * lose the entropy contained therein.
 *
 * Therefore, use the NSS PRNG if NSS is the crypto implementation.
 */

#include "../nss/nss_gen.h"
#include <pk11pub.h>

static int
nss_init(void)
{
    return 0;
}

static krb5_error_code
nss_add_entropy(krb5_context context, unsigned int randsource,
                          const krb5_data *data)
{
    krb5_error_code ret;

    ret = k5_nss_init();
    if (ret)
        return ret;
    if (PK11_RandomUpdate(data->data, data->length) != SECSuccess)
        return k5_nss_map_last_error();
    return 0;
}

static krb5_error_code
nss_make_octets(krb5_context context, krb5_data *data)
{
    krb5_error_code ret;

    ret = k5_nss_init();
    if (ret)
        return ret;
    if (PK11_GenerateRandom((unsigned char *)data->data,
                            data->length) != SECSuccess)
        return k5_nss_map_last_error();
    return 0;
}

static void
nss_cleanup (void)
{
}

const struct krb5_prng_provider krb5int_prng_nss = {
    "nss",
    nss_make_octets,
    nss_add_entropy,
    nss_init,
    nss_cleanup
};
#endif
