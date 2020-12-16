/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/openssl/enc_provider/aes.c */
/*
 * Copyright (C) 2003, 2007, 2008, 2009 by the Massachusetts Institute of Technology.
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
#include <openssl/evp.h>
#include <openssl/aes.h>
//#include <openssl/modes.h>

/* proto's */
static krb5_error_code
cbc_enc(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
        size_t num_data);
static krb5_error_code
cbc_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data);
static krb5_error_code
cts_encr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data, size_t dlen);
static krb5_error_code
cts_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data, size_t dlen);

#define BLOCK_SIZE 16
#define NUM_BITS 8
#define IV_CTS_BUF_SIZE 16 /* 16 - hardcoded in CRYPTO_cts128_en/decrypt */

static const EVP_CIPHER *
map_mode(unsigned int len)
{
    if (len==16)
        return EVP_aes_128_cbc();
    if (len==32)
        return EVP_aes_256_cbc();
    else
        return NULL;
}

/* Encrypt one block using CBC. */
static krb5_error_code
cbc_enc(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
        size_t num_data)
{
    int             ret, olen = BLOCK_SIZE;
    unsigned char   iblock[BLOCK_SIZE], oblock[BLOCK_SIZE];
    EVP_CIPHER_CTX  *ctx;
    struct iov_cursor cursor;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return ENOMEM;

    ret = EVP_EncryptInit_ex(ctx, map_mode(key->keyblock.length),
                             NULL, key->keyblock.contents, (ivec) ? (unsigned char*)ivec->data : NULL);
    if (ret == 0) {
        EVP_CIPHER_CTX_free(ctx);
        return KRB5_CRYPTO_INTERNAL;
    }

    k5_iov_cursor_init(&cursor, data, num_data, BLOCK_SIZE, FALSE);
    k5_iov_cursor_get(&cursor, iblock);
    EVP_CIPHER_CTX_set_padding(ctx,0);
    ret = EVP_EncryptUpdate(ctx, oblock, &olen, iblock, BLOCK_SIZE);
    if (ret == 1)
        k5_iov_cursor_put(&cursor, oblock);
    EVP_CIPHER_CTX_free(ctx);

    zap(iblock, BLOCK_SIZE);
    zap(oblock, BLOCK_SIZE);
    return (ret == 1) ? 0 : KRB5_CRYPTO_INTERNAL;
}

/* Decrypt one block using CBC. */
static krb5_error_code
cbc_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data)
{
    int              ret = 0, olen = BLOCK_SIZE;
    unsigned char    iblock[BLOCK_SIZE], oblock[BLOCK_SIZE];
    EVP_CIPHER_CTX   *ctx;
    struct iov_cursor cursor;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return ENOMEM;

    ret = EVP_DecryptInit_ex(ctx, map_mode(key->keyblock.length),
                             NULL, key->keyblock.contents, (ivec) ? (unsigned char*)ivec->data : NULL);
    if (ret == 0) {
        EVP_CIPHER_CTX_free(ctx);
        return KRB5_CRYPTO_INTERNAL;
    }

    k5_iov_cursor_init(&cursor, data, num_data, BLOCK_SIZE, FALSE);
    k5_iov_cursor_get(&cursor, iblock);
    EVP_CIPHER_CTX_set_padding(ctx,0);
    ret = EVP_DecryptUpdate(ctx, oblock, &olen, iblock, BLOCK_SIZE);
    if (ret == 1)
        k5_iov_cursor_put(&cursor, oblock);
    EVP_CIPHER_CTX_free(ctx);

    zap(iblock, BLOCK_SIZE);
    zap(oblock, BLOCK_SIZE);
    return (ret == 1) ? 0 : KRB5_CRYPTO_INTERNAL;
}


/** The CTS mode is not implemented in BoringSSL.
  * So, copy the implementation from OpenSSL here.
  */

/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

typedef void (*block128_f)(const uint8_t in[16], uint8_t out[16],
                           const AES_KEY *key);

typedef void (*cbc128_f)(const uint8_t *in, uint8_t *out, size_t len,
                         const AES_KEY *key, uint8_t ivec[16], int enc);

static size_t CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out,
                             size_t len, const void *key,
                             unsigned char ivec[16], cbc128_f cbc)
{
    size_t residue;
    union {
        size_t align;
        unsigned char c[16];
    } tmp;

    if (len <= 16)
        return 0;

    if ((residue = len % 16) == 0)
        residue = 16;

    len -= residue;

    (*cbc) (in, out, len, key, ivec, 1);

    in += len;
    out += len;

#if defined(CBC_HANDLES_TRUNCATED_IO)
    memcpy(tmp.c, out - 16, 16);
    (*cbc) (in, out - 16, residue, key, ivec, 1);
    memcpy(out, tmp.c, residue);
#else
    memset(tmp.c, 0, sizeof(tmp));
    memcpy(tmp.c, in, residue);
    memcpy(out, out - 16, residue);
    (*cbc) (tmp.c, out - 16, 16, key, ivec, 1);
#endif
    return len + residue;
}

static size_t CRYPTO_cts128_encrypt_block(const unsigned char *in,
                                   unsigned char *out, size_t len,
                                   const void *key, unsigned char ivec[16],
                                   block128_f block)
{
    size_t residue, n;

    if (len <= 16)
        return 0;

    if ((residue = len % 16) == 0)
        residue = 16;

    len -= residue;

    CRYPTO_cbc128_encrypt(in, out, len, key, ivec, block);

    in += len;
    out += len;

    for (n = 0; n < residue; ++n)
        ivec[n] ^= in[n];
    (*block) (ivec, ivec, key);
    memcpy(out, out - 16, residue);
    memcpy(out - 16, ivec, 16);

    return len + residue;
}

static size_t CRYPTO_cts128_decrypt(const unsigned char *in, unsigned char *out,
                             size_t len, const void *key,
                             unsigned char ivec[16], cbc128_f cbc)
{
    size_t residue;
    union {
        size_t align;
        unsigned char c[32];
    } tmp;

    if (len <= 16)
        return 0;

    if ((residue = len % 16) == 0)
        residue = 16;

    len -= 16 + residue;

    if (len) {
        (*cbc) (in, out, len, key, ivec, 0);
        in += len;
        out += len;
    }

    memset(tmp.c, 0, sizeof(tmp));
    /*
     * this places in[16] at &tmp.c[16] and decrypted block at &tmp.c[0]
     */
    (*cbc) (in, tmp.c, 16, key, tmp.c + 16, 0);

    memcpy(tmp.c, in + 16, residue);
#if defined(CBC_HANDLES_TRUNCATED_IO)
    (*cbc) (tmp.c, out, 16 + residue, key, ivec, 0);
#else
    (*cbc) (tmp.c, tmp.c, 32, key, ivec, 0);
    memcpy(out, tmp.c, 16 + residue);
#endif
    return 16 + len + residue;
}

size_t CRYPTO_cts128_decrypt_block(const unsigned char *in,
                                   unsigned char *out, size_t len,
                                   const void *key, unsigned char ivec[16],
                                   block128_f block)
{
    size_t residue, n;
    union {
        size_t align;
        unsigned char c[32];
    } tmp;

    if (len <= 16)
        return 0;

    if ((residue = len % 16) == 0)
        residue = 16;

    len -= 16 + residue;

    if (len) {
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec, block);
        in += len;
        out += len;
    }

    (*block) (in, tmp.c + 16, key);

    memcpy(tmp.c, tmp.c + 16, 16);
    memcpy(tmp.c, in + 16, residue);
    (*block) (tmp.c, tmp.c, key);

    for (n = 0; n < 16; ++n) {
        unsigned char c = in[n];
        out[n] = tmp.c[n] ^ ivec[n];
        ivec[n] = c;
    }
    for (residue += 16; n < residue; ++n)
        out[n] = tmp.c[n] ^ in[n];

    return 16 + len + residue;
}


static krb5_error_code
cts_encr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data, size_t dlen)
{
    int                    ret = 0;
    size_t                 size = 0;
    unsigned char         *oblock = NULL, *dbuf = NULL;
    unsigned char          iv_cts[IV_CTS_BUF_SIZE];
    struct iov_cursor      cursor;
    AES_KEY                enck;

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data){
        if (ivec->length != sizeof(iv_cts))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv_cts, ivec->data,ivec->length);
    }

    oblock = OPENSSL_malloc(dlen);
    if (!oblock){
        return ENOMEM;
    }
    dbuf = OPENSSL_malloc(dlen);
    if (!dbuf){
        OPENSSL_free(oblock);
        return ENOMEM;
    }

    k5_iov_cursor_init(&cursor, data, num_data, dlen, FALSE);
    k5_iov_cursor_get(&cursor, dbuf);

    AES_set_encrypt_key(key->keyblock.contents,
                        NUM_BITS * key->keyblock.length, &enck);

    size = CRYPTO_cts128_encrypt((unsigned char *)dbuf, oblock, dlen, &enck,
                                 iv_cts, (cbc128_f)AES_cbc_encrypt);
    if (size <= 0)
        ret = KRB5_CRYPTO_INTERNAL;
    else
        k5_iov_cursor_put(&cursor, oblock);

    if (!ret && ivec && ivec->data)
        memcpy(ivec->data, iv_cts, sizeof(iv_cts));

    zap(oblock, dlen);
    zap(dbuf, dlen);
    OPENSSL_free(oblock);
    OPENSSL_free(dbuf);

    return ret;
}

static krb5_error_code
cts_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data, size_t dlen)
{
    int                    ret = 0;
    size_t                 size = 0;
    unsigned char         *oblock = NULL;
    unsigned char         *dbuf = NULL;
    unsigned char          iv_cts[IV_CTS_BUF_SIZE];
    struct iov_cursor      cursor;
    AES_KEY                deck;

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data){
        if (ivec->length != sizeof(iv_cts))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv_cts, ivec->data,ivec->length);
    }

    oblock = OPENSSL_malloc(dlen);
    if (!oblock)
        return ENOMEM;
    dbuf = OPENSSL_malloc(dlen);
    if (!dbuf){
        OPENSSL_free(oblock);
        return ENOMEM;
    }

    AES_set_decrypt_key(key->keyblock.contents,
                        NUM_BITS * key->keyblock.length, &deck);

    k5_iov_cursor_init(&cursor, data, num_data, dlen, FALSE);
    k5_iov_cursor_get(&cursor, dbuf);

    size = CRYPTO_cts128_decrypt((unsigned char *)dbuf, oblock,
                                 dlen, &deck,
                                 iv_cts, (cbc128_f)AES_cbc_encrypt);
    if (size <= 0)
        ret = KRB5_CRYPTO_INTERNAL;
    else
        k5_iov_cursor_put(&cursor, oblock);

    if (!ret && ivec && ivec->data)
        memcpy(ivec->data, iv_cts, sizeof(iv_cts));

    zap(oblock, dlen);
    zap(dbuf, dlen);
    OPENSSL_free(oblock);
    OPENSSL_free(dbuf);

    return ret;
}

krb5_error_code
krb5int_aes_encrypt(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data)
{
    int    ret = 0;
    size_t input_length, nblocks;

    input_length = iov_total_length(data, num_data, FALSE);
    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (nblocks == 1) {
        if (input_length != BLOCK_SIZE)
            return KRB5_BAD_MSIZE;
        ret = cbc_enc(key, ivec, data, num_data);
    } else if (nblocks > 1) {
        ret = cts_encr(key, ivec, data, num_data, input_length);
    }

    return ret;
}

krb5_error_code
krb5int_aes_decrypt(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data)
{
    int    ret = 0;
    size_t input_length, nblocks;

    input_length = iov_total_length(data, num_data, FALSE);
    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (nblocks == 1) {
        if (input_length != BLOCK_SIZE)
            return KRB5_BAD_MSIZE;
        ret = cbc_decr(key, ivec, data, num_data);
    } else if (nblocks > 1) {
        ret = cts_decr(key, ivec, data, num_data, input_length);
    }

    return ret;
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
