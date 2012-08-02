/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/hash_provider/hash_md4.c
 *
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
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
#include <cyassl/ctaocrypt/md4.h>

/*
 * k5_md4_hash: Hash data buffer using MD4.
 * 
 * @data     Input data structure
 * @num_data Number of blocks
 * @output   Output data structure
 *
 * Returns 0 on success, krb5_error_code on error
 */
static krb5_error_code
k5_md4_hash(const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    Md4 md4;
    unsigned int i;
   
    if (output->length != MD4_DIGEST_SIZE)
        return(KRB5_CRYPTO_INTERNAL);

    InitMd4(&md4);
    for (i = 0; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];

        if (SIGN_IOV(iov)) {
            Md4Update(&md4, (unsigned char *) iov->data.data, 
                      iov->data.length);
        }
    }
    Md4Final(&md4, (unsigned char *) output->data);

    return(0);
}

const struct krb5_hash_provider krb5int_hash_md4 = {
    "MD4",
    MD4_DIGEST_SIZE,
    MD4_BLOCK_SIZE,
    k5_md4_hash
};
