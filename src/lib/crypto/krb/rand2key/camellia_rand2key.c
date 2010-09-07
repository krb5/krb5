/*
 * lib/crypto/krb/rand2key/camellia_rand2key.c
 *
 * Copyright (c) 2009
 * NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.
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


#include "rand2key.h"

krb5_error_code
krb5int_camellia_make_key(const krb5_data *randombits, krb5_keyblock *key)
{
    if (key->length != 16 && key->length != 32)
        return(KRB5_BAD_KEYSIZE);
    if (randombits->length != key->length)
        return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;

    memcpy(key->contents, randombits->data, randombits->length);

    return(0);
}
