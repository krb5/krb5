/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/enc_provider/aes.c */
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
#include <cyassl/ctaocrypt/aes.h>

static inline void
xor_words(word* first, const word* second, word32 len) 
{
    word32 i;

    for (i = 0; i < len; i++) {
        first[i] ^= second[i];
    }    
}

static inline void
xor_buf(byte* buffer, const byte* m, word32 len)
{
    if ( ((word)buffer | (word)m | len) & (WORD_SIZE == 0) ) {
        xor_words( (word*)buffer, (const word*)m, len / WORD_SIZE);
    } else {
        word32 i;
        for (i = 0; i < len; i++) {
            buffer[i] ^= m[i];
        }
    }
}

/*
 * krb5int_aes_encrypt: Encrypt data buffer using AES CBC-CTS. With
 *                      CyaSSL, this requires a bit of trickery to
 *                      Emulate CTS since only CBC is currently
 *                      implemented in CTaoCrypt.
 * @key      AES key
 * @ivec     Initialization Vector
 * @data     Input/Output buffer (in-place encryption, block-by-block)
 * @num_data Number of blocks
 *
 * Returns 0 on success, krb5_error_code on error
 */
krb5_error_code
krb5int_aes_encrypt(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data)
{
    Aes aes; 
    int ret = 0;
    size_t nblocks = 0, i = 0;
    int N1_length;
    size_t  input_length;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char iblock[AES_BLOCK_SIZE];
    unsigned char oblock[AES_BLOCK_SIZE];
    unsigned char blockN1[AES_BLOCK_SIZE];   /* Last block (N-1) */
    unsigned char blockN2[AES_BLOCK_SIZE];   /* Second to last block (N-2) */
    
    struct iov_block_state input_pos, output_pos;

    /* Find the length of total data to encrypt */
    for (i = 0, input_length = 0; i < num_data; i++) {
        krb5_crypto_iov *iov = &data[i];

        if (ENCRYPT_IOV(iov))
            input_length += iov->data.length;
    }

    /* Check if IV exists and is the correct size */
    if (ivec && ivec->data) {
        if (ivec->length != sizeof(iv))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv, ivec->data,ivec->length);
    } else {
        memset(iv, 0, sizeof(iv));
    }

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    nblocks = (input_length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
   
    /* Set up CTaoCrypt Aes structure with key */
    ret = AesSetKey(&aes, key->keyblock.contents, key->keyblock.length,
                    iv, AES_ENCRYPTION);
    if(ret != 0)
        return KRB5_CRYPTO_INTERNAL;

    /* If we only have 1 block, use regular AES-CBC mode */
    if (nblocks == 1) {
        if (input_length != AES_BLOCK_SIZE)
            return KRB5_BAD_MSIZE;
        krb5int_c_iov_get_block(iblock, AES_BLOCK_SIZE, data, num_data, 
                                &input_pos);
        AesCbcEncrypt(&aes, oblock, iblock, AES_BLOCK_SIZE);
        krb5int_c_iov_put_block(data, num_data, oblock, AES_BLOCK_SIZE, 
                                &output_pos);
    } 
    /* If we have > 1 block, use AES CBC-CTS mode */
    else if (nblocks > 1) {
        for (i = 0; i < nblocks - 2; i++) {
            krb5int_c_iov_get_block(iblock, AES_BLOCK_SIZE, data, 
                                    num_data, &input_pos);
            AesCbcEncrypt(&aes, oblock, iblock, AES_BLOCK_SIZE);
            krb5int_c_iov_put_block(data, num_data, oblock, AES_BLOCK_SIZE,
                                    &output_pos); 
        }

        /* Pad last block with 0's */
        memset(blockN1, 0, AES_BLOCK_SIZE);
        N1_length = input_length % AES_BLOCK_SIZE;

        /* Get and encrypt last 2 blocks */
        krb5int_c_iov_get_block(blockN2, AES_BLOCK_SIZE, data, num_data, 
                                &input_pos);
        krb5int_c_iov_get_block(blockN1, AES_BLOCK_SIZE, data, num_data, 
                                &input_pos);

        /* Encrypt second-to-last block */
        AesCbcEncrypt(&aes, blockN2, blockN2, AES_BLOCK_SIZE);
        /* Encrypt last block */
        AesCbcEncrypt(&aes, blockN1, blockN1, AES_BLOCK_SIZE);

        /* Put last 2 blocks back in data buffer in reverse order */
        krb5int_c_iov_put_block(data, num_data, blockN1, AES_BLOCK_SIZE, 
                                &output_pos);
        krb5int_c_iov_put_block(data, num_data, blockN2, AES_BLOCK_SIZE, 
                                &output_pos);
    }
   
    if(ivec && ivec->data)
        memcpy(ivec->data, iv, sizeof(iv));

    zap(iv, AES_BLOCK_SIZE);
    zap(iblock, AES_BLOCK_SIZE);
    zap(oblock, AES_BLOCK_SIZE);
    zap(blockN1, AES_BLOCK_SIZE);
    zap(blockN2, AES_BLOCK_SIZE);

    return 0;
}

/*
 * krb5int_aes_decrypt: Decrypt data buffer using AES CBC-CTS. With
 *                      CyaSSL, this requires a bit of trickery to
 *                      Emulate CTS since only CBC is currently
 *                      implemented in CTaoCrypt.
 * @key      AES key
 * @ivec     Initialization Vector
 * @data     Input/Output buffer (in-place decryption, block-by-block)
 * @num_data Number of blocks
 *
 * Returns 0 on success, krb5_error_code on error
 */
krb5_error_code
krb5int_aes_decrypt(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data)
{
    Aes aes;
    int ret = 0;
    unsigned int nblocks = 0, i = 0;
    int N1_length;
    size_t input_length;
    unsigned char iv[AES_BLOCK_SIZE];

    unsigned char iblock[AES_BLOCK_SIZE];
    unsigned char oblock[AES_BLOCK_SIZE];
    
    unsigned char blockN1[AES_BLOCK_SIZE];   /* Last block (N-1) */
    unsigned char blockN2[AES_BLOCK_SIZE];   /* Second to last block (N-2) */
   
    unsigned char plainN1[AES_BLOCK_SIZE];   /* To hold decrypted blockN1 */
    unsigned char plainN2[AES_BLOCK_SIZE];   /* To hold decrypted blockN2 */
  
    unsigned char lastCBlock[AES_BLOCK_SIZE];   /* Storage for CTS hack */

    struct iov_block_state input_pos, output_pos;
   
    /* Find the length of total data to encrypt */
    for (i = 0, input_length = 0; i < num_data; i++) {
        krb5_crypto_iov *iov = &data[i];

        if (ENCRYPT_IOV(iov))
            input_length += iov->data.length; 
    }

    /* Check if IV exists and is the correct size */
    memset(iv,0,sizeof(iv));
    if (ivec && ivec->data) {
        if (ivec->length != sizeof(iv))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv, ivec->data,ivec->length);
    }

    /* Copy IV to lastCBlock for CTS hack, if nblocks > 2,
       store last cipher block in lastCBlock (below). */
    memcpy(lastCBlock, iv, AES_BLOCK_SIZE);

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    nblocks = (input_length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    /* Set up CTaoCrypt Aes structure with key */
    ret = AesSetKey(&aes, key->keyblock.contents, key->keyblock.length,
                    iv, AES_DECRYPTION);
    if(ret != 0)
        return KRB5_CRYPTO_INTERNAL;

    /* If we have 1 block, decrypt using AES CBC mode */
    if (nblocks == 1) {
        if (input_length != AES_BLOCK_SIZE)
            return KRB5_BAD_MSIZE;
        krb5int_c_iov_get_block(iblock, AES_BLOCK_SIZE, data, num_data, 
                                &input_pos);
        AesCbcDecrypt(&aes, oblock, iblock, AES_BLOCK_SIZE);
        krb5int_c_iov_put_block(data, num_data, oblock, AES_BLOCK_SIZE, 
                                &output_pos);
    } 
    else if (nblocks > 1) {
        /* Decrypt data up to last 2 blocks */
        for (i = 0; i < nblocks - 2; i++) {
            krb5int_c_iov_get_block(iblock, AES_BLOCK_SIZE, data, num_data,
                                    &input_pos);
            AesCbcDecrypt(&aes, oblock, iblock, AES_BLOCK_SIZE);
            krb5int_c_iov_put_block(data, num_data, oblock, AES_BLOCK_SIZE,
                                    &output_pos);

            /* Save last ciphertext block in case we need it for CTS hack */
            memcpy(lastCBlock, iblock, AES_BLOCK_SIZE);
        }

        /* Pad last block with 0's */
        memset(blockN1, 0, AES_BLOCK_SIZE);

        krb5int_c_iov_get_block(blockN2, AES_BLOCK_SIZE, data, num_data, 
                                &input_pos);
        krb5int_c_iov_get_block(blockN1, AES_BLOCK_SIZE, data, num_data, 
                                &input_pos);

        /* Decrypt second to last block (N-2) into plainN2 */
        AesCbcDecrypt(&aes, plainN2, blockN2, AES_BLOCK_SIZE);
        xor_buf(plainN2, lastCBlock, AES_BLOCK_SIZE);

        /* Pad last block (C:N-1) with the last B-M bits of decrypted 
           second-to-last block (plainN2)
           B = AES_BLOCK_SIZE
           M = length of last block */
        N1_length = input_length % AES_BLOCK_SIZE;
        if (N1_length > 0) {
            memcpy(blockN1 + N1_length, plainN2 + N1_length, 
                   AES_BLOCK_SIZE - N1_length);
        }

        /* Redo correct xor between decrypted C:N-2 and C:N-1 for 
           correct AES-CBC */
        xor_buf(plainN2, blockN1, AES_BLOCK_SIZE);

        /* Decrypt last block (N-1) into plainN1 */
        AesCbcDecrypt(&aes, plainN1, blockN1, AES_BLOCK_SIZE);
        xor_buf(plainN1, blockN2, AES_BLOCK_SIZE);   /* undo incorrect XOR */
        xor_buf(plainN1, lastCBlock, AES_BLOCK_SIZE);   /* do correct XOR */
       
        /* Put last 2 blocks back in data buffer in reverse order */
        krb5int_c_iov_put_block(data, num_data, plainN1, AES_BLOCK_SIZE, 
                                &output_pos);
        krb5int_c_iov_put_block(data, num_data, plainN2, AES_BLOCK_SIZE, 
                                &output_pos); 
    }

    zap(iv, AES_BLOCK_SIZE);    
    zap(iblock, AES_BLOCK_SIZE);
    zap(oblock, AES_BLOCK_SIZE);
    zap(blockN1, AES_BLOCK_SIZE);
    zap(blockN2, AES_BLOCK_SIZE);
    zap(plainN1, AES_BLOCK_SIZE);
    zap(plainN2, AES_BLOCK_SIZE);

    return 0;
}

static krb5_error_code
krb5int_aes_init_state (const krb5_keyblock *key, krb5_keyusage usage,
                        krb5_data *state)
{
    state->length = 16;
    state->data = (void *) malloc(16);
    if (state->data == NULL)
        return ENOMEM;
    memset(state->data, 0, state->length);
    return 0;
}

const struct krb5_enc_provider krb5int_enc_aes128 = {
    16,
    16, 16,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    NULL,
    krb5int_aes_init_state,
    krb5int_default_free_state
};

const struct krb5_enc_provider krb5int_enc_aes256 = {
    16,
    32, 32,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    NULL,
    krb5int_aes_init_state,
    krb5int_default_free_state
};
