/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/krb/rand2key/des_rand2key.c
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


#include "rand2key.h"
#include "des_int.h"

krb5_error_code
krb5int_des_make_key(const krb5_data *randombits, krb5_keyblock *key)
{
    if (key->length != KRB5_MIT_DES_KEYSIZE)
        return(KRB5_BAD_KEYSIZE);
    if (randombits->length != 7)
        return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;

    /* take the seven bytes, move them around into the top 7 bits of the
       8 key bytes, then compute the parity bits */

    memcpy(key->contents, randombits->data, randombits->length);
    key->contents[7] = (((key->contents[0]&1)<<1) | ((key->contents[1]&1)<<2) |
                        ((key->contents[2]&1)<<3) | ((key->contents[3]&1)<<4) |
                        ((key->contents[4]&1)<<5) | ((key->contents[5]&1)<<6) |
                        ((key->contents[6]&1)<<7));

    mit_des_fixup_key_parity(key->contents);

    return(0);
}
