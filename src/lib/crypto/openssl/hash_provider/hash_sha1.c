/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/openssl/hash_provider/hash_sha1.c */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
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
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "crypto_int.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

static krb5_error_code
k5_sha1_hash(const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    EVP_MD_CTX ctx;
    unsigned int i;

    if (output->length != SHA_DIGEST_LENGTH)
        return KRB5_CRYPTO_INTERNAL;

    EVP_MD_CTX_init(&ctx);
    EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL);
    for (i = 0; i < num_data; i++) {
        const krb5_data *d = &data[i].data;
        if (SIGN_IOV(&data[i]))
            EVP_DigestUpdate(&ctx, (unsigned char *)d->data, d->length);
    }
    EVP_DigestFinal_ex(&ctx, (unsigned char *)output->data, NULL);
    EVP_MD_CTX_cleanup(&ctx);
    return 0;
}

const struct krb5_hash_provider krb5int_hash_sha1 = {
    "SHA1",
    SHA_DIGEST_LENGTH,
    64,
    k5_sha1_hash
};
