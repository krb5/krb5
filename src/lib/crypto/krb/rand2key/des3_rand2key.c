/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/krb/rand2key/des3_rand2key.c
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

/* RFC 3961 */
krb5_error_code
krb5int_des3_make_key(const krb5_data *randombits, krb5_keyblock *key)
{
    int i;
    if (key->length != KRB5_MIT_DES3_KEYSIZE)
        return(KRB5_BAD_KEYSIZE);
    if (randombits->length != KRB5_MIT_DES3_KEY_BYTES)
        return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;

    /* take the seven bytes, move them around into the top 7 bits of the
       8 key bytes, then compute the parity bits.  Do this three times. */

    for (i=0; i<3; i++) {
        memcpy(key->contents+i*8, randombits->data+i*7, 7);
        key->contents[i*8+7] = (((key->contents[i*8]&1)<<1) |
                                ((key->contents[i*8+1]&1)<<2) |
                                ((key->contents[i*8+2]&1)<<3) |
                                ((key->contents[i*8+3]&1)<<4) |
                                ((key->contents[i*8+4]&1)<<5) |
                                ((key->contents[i*8+5]&1)<<6) |
                                ((key->contents[i*8+6]&1)<<7));

        mit_des_fixup_key_parity(key->contents+i*8);
    }
    return(0);
}
