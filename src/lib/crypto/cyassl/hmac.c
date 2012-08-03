/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/hmac.c */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "crypto_int.h"

#include <cyassl/ctaocrypt/hmac.h>
#include <cyassl/ctaocrypt/md4.h>
#include <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/sha256.h>

/* Used to verify hash function is compatible with CyaSSL,
 * and return the valid hash function type, or return -1
 * otherwise.
 */
static int
check_digest(const struct krb5_hash_provider *hash)
{
    if (!strncmp(hash->hash_name, "SHA1",4))
        return SHA;
    else if (!strncmp(hash->hash_name, "SHA256", 6))
        return SHA256;
    else if (!strncmp(hash->hash_name, "MD5", 3))
        return MD5;
    else
        return -1;
}

/*
 * krb5int_hmac_keyblock: Calculate HMAC of input buffer using desired
 *                        hash function (MD5, SHA1, SHA256).
 *
 * @hash     Type of hash function to use 
 * @keyblock Hash key
 * @data     Input data structure
 * @num_data Number of blocks
 * @output   Output data structure
 *
 * Returns 0 on success, krb5_error_code on error
 */
krb5_error_code
krb5int_hmac_keyblock(const struct krb5_hash_provider *hash,
                      const krb5_keyblock *keyblock,
                      const krb5_crypto_iov *data, size_t num_data,
                      krb5_data *output)
{
    Hmac hmac;
    unsigned int i = 0;
    size_t hashsize, blocksize;

    hashsize = hash->hashsize;
    blocksize = hash->blocksize;

    if (keyblock->length > blocksize) {
        return(KRB5_CRYPTO_INTERNAL);
    }

    if (output->length < hashsize) {
        return(KRB5_BAD_MSIZE);
    }

    /* Check if algorithm is supported */
    if (check_digest(hash) == -1) {
        return(KRB5_CRYPTO_INTERNAL);
    }

    HmacSetKey(&hmac, check_digest(hash), keyblock->contents, 
               keyblock->length);

    for (i = 0; i < num_data; i++) { 
        const krb5_crypto_iov *iov = &data[i]; 
        if (SIGN_IOV(iov)) {
            HmacUpdate(&hmac, (unsigned char*) iov->data.data, 
                       iov->data.length);
        }
    }
    output->length = hashsize;
    HmacFinal(&hmac, (unsigned char *)output->data);
    
    return 0;
}

krb5_error_code
krb5int_hmac(const struct krb5_hash_provider *hash, krb5_key key,
             const krb5_crypto_iov *data, size_t num_data,
             krb5_data *output)
{
    return krb5int_hmac_keyblock(hash, &key->keyblock, data, num_data, 
                                 output);
}

