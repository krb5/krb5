/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/prng.c - NSS prng functions */
/*
 * Copyright (C) 2011 by the Massachusetts Institute of Technology.
 * All rights reserved.
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

#include "crypto_int.h"
#include "nss_gen.h"
#include "nss_prng.h"
#include <pk11pub.h>

krb5_error_code
k5_nss_prng_add_entropy(krb5_context context, const krb5_data *indata)
{
    krb5_error_code ret;

    ret = k5_nss_init();
    if (ret)
        return ret;
    if (PK11_RandomUpdate(indata->data, indata->length) != SECSuccess)
        return k5_nss_map_last_error();
    return 0;
}

krb5_error_code
k5_nss_prng_make_octets(krb5_context context, krb5_data *outdata)
{
    krb5_error_code ret;

    ret = k5_nss_init();
    if (ret)
        return ret;
    if (PK11_GenerateRandom((unsigned char *)outdata->data,
                            outdata->length) != SECSuccess)
        return k5_nss_map_last_error();
    return 0;
}
