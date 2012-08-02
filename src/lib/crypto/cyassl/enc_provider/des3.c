/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/enc_provider/des3.c */
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
#include <cyassl/ctaocrypt/des3.h>

static krb5_error_code
validate(krb5_key key, const krb5_data *ivec, const krb5_crypto_iov *data,
         size_t num_data, krb5_boolean *empty)
{
    size_t i, input_length;

    for (i = 0, input_length = 0; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];

        if (ENCRYPT_IOV(iov))
            input_length += iov->data.length;
    }

    /* Is our key the correct length? */
    if (key->keyblock.length != KRB5_MIT_DES3_KEYSIZE)
        return(KRB5_BAD_KEYSIZE);

    /* Is our input a multiple of the block size, and
       the IV the correct length? */
    if ((input_length%DES_BLOCK_SIZE) != 0 
        || (ivec != NULL && ivec->length != DES_BLOCK_SIZE))
        return(KRB5_BAD_MSIZE);

    *empty = (input_length == 0);
    return 0;
}

/*
 * k5_des3_encrypt: Encrypt data buffer using 3DES.  
 *  
 * @key      DES key (with odd parity)
 * @ivec     Initialization Vector
 * @data     Input/Output buffer (in-place encryption, block-by-block)
 * @num_data Number of blocks
 *
 * Returns 0 on success, krb5_error_code on error
 */
static krb5_error_code
k5_des3_encrypt(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
                size_t num_data)
{
    int ret;
    Des3 des3;
    unsigned char iv[DES_BLOCK_SIZE];
    unsigned char iblock[DES_BLOCK_SIZE];
    unsigned char oblock[DES_BLOCK_SIZE];
    struct iov_block_state input_pos, output_pos;
    krb5_boolean empty;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    ret = validate(key, ivec, data, num_data, &empty);
    if (ret != 0 || empty)
        return ret;

    memset(iv, 0, sizeof(iv));
    
    /* Check if IV exists and is the correct size */
    if (ivec && ivec->data) {
        if (ivec->length != sizeof(iv))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv, ivec->data, ivec->length);
    }

    Des3_SetKey(&des3, key->keyblock.contents, iv, DES_ENCRYPTION);

    for (;;) {

        if (!krb5int_c_iov_get_block(iblock, DES_BLOCK_SIZE,
                                     data, num_data, &input_pos))
            break;

        Des3_CbcEncrypt(&des3, oblock, iblock, DES_BLOCK_SIZE);

        krb5int_c_iov_put_block(data, num_data,
                                oblock, DES_BLOCK_SIZE, &output_pos);
    }

    if (ivec != NULL)
        memcpy(ivec->data, oblock, DES_BLOCK_SIZE);

    zap(iv, sizeof(iv));
    zap(iblock, sizeof(iblock));
    zap(oblock, sizeof(oblock));

    return 0;
}

/*
 * k5_des3_decrypt: Decrypt data buffer using 3DES.  
 *  
 * @key      DES key (with odd parity)
 * @ivec     Initialization Vector
 * @data     Input/Output buffer (in-place decryption, block-by-block)
 * @num_data Number of blocks
 *
 * Returns 0 on success, krb5_error_code on error
 */
static krb5_error_code
k5_des3_decrypt(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
                size_t num_data)
{
    int ret;
    Des3 des3;
    unsigned char iv[DES_BLOCK_SIZE];
    unsigned char iblock[DES_BLOCK_SIZE];
    unsigned char oblock[DES_BLOCK_SIZE];
    struct iov_block_state input_pos, output_pos;
    krb5_boolean empty;
    
    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    ret = validate(key, ivec, data, num_data, &empty);
    if (ret != 0 || empty)
        return ret;

    memset(iv, 0, sizeof(iv));
    
    /* Check if IV exists and is the correct size */
    if (ivec && ivec->data) {
        if (ivec->length != sizeof(iv))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv, ivec->data, ivec->length);
    }

    Des3_SetKey(&des3, key->keyblock.contents, iv, DES_DECRYPTION);

    for (;;) {

        if (!krb5int_c_iov_get_block(iblock, DES_BLOCK_SIZE,
                                     data, num_data, &input_pos))
            break;

        Des3_CbcDecrypt(&des3, oblock, iblock, DES_BLOCK_SIZE);

        krb5int_c_iov_put_block(data, num_data, oblock, DES_BLOCK_SIZE,
                                &output_pos);
    }

    if (ivec != NULL)
        memcpy(ivec->data, iblock, DES_BLOCK_SIZE);

    zap(iv, sizeof(iv));
    zap(iblock, sizeof(iblock));
    zap(oblock, sizeof(oblock));

    return 0;
}

const struct krb5_enc_provider krb5int_enc_des3 = {
    DES_BLOCK_SIZE,
    KRB5_MIT_DES3_KEY_BYTES, KRB5_MIT_DES3_KEYSIZE,
    k5_des3_encrypt,
    k5_des3_decrypt,
    NULL,
    krb5int_des_init_state,
    krb5int_default_free_state
};
