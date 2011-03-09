/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/krb/prng_nss.c */
/*
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

#include "crypto_int.h"
#include "nss_prng.h"

/*
 * This PRNG module should be used whenever the NSS crypto implementation is
 * used.  The Fortuna module does not work with NSS because it needs to hold
 * AES-256 and SHA-256 contexts across forks.
 */

int
k5_prng_init(void)
{
    return 0;
}

void
k5_prng_cleanup(void)
{
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_add_entropy(krb5_context context, unsigned int randsource,
                          const krb5_data *indata)
{
    return k5_nss_prng_add_entropy(context, indata);
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_make_octets(krb5_context context, krb5_data *outdata)
{
    return k5_nss_prng_make_octets(context, outdata);
}
