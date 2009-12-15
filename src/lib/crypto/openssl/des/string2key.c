/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/openssl/des/string2key.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
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

#include "des_int.h"
#include <openssl/des.h>


krb5_error_code
mit_des_string_to_key_int (krb5_keyblock *key,
                           const krb5_data *pw, const krb5_data *salt)
{
    DES_cblock outkey;
    DES_string_to_key(pw->data, &outkey);
    if ( key->length <  sizeof(outkey))
        return KRB5_CRYPTO_INTERNAL;
    key->length = sizeof(outkey);
    memcpy(key->contents, outkey, key->length);
    return 0;
}
