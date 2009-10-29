/*
 * lib/crypto/openssl/enc_provider/aes.c
 *
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

#include "k5-int.h"
#include "enc_provider.h"
#include "rand2key.h"
#include "aead.h"
#include "hash_provider/hash_provider.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

/* proto's */
static krb5_error_code
cts_enc(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output);
static krb5_error_code
cbc_enc(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output);
static krb5_error_code
cts_decr(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output);
static krb5_error_code
cbc_decr(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output);
static krb5_error_code
cts_encr_iov(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data, size_t dlen);
static krb5_error_code
cts_decr_iov(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data, size_t dlen);

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

static krb5_error_code
cbc_enc(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    int             ret = 0, tmp_len = 0;
    unsigned char  *tmp_buf = NULL;
    EVP_CIPHER_CTX  ciph_ctx;

    tmp_len = input->length;
    tmp_buf = OPENSSL_malloc(input->length);
    if (!tmp_buf){
        return ENOMEM;
    }

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_EncryptInit_ex(&ciph_ctx, map_mode(key->keyblock.length),
                  NULL, key->keyblock.contents, (ivec) ? (unsigned char*)ivec->data : NULL);

    if (ret == 1){
        EVP_CIPHER_CTX_set_padding(&ciph_ctx,0); 
        ret = EVP_EncryptUpdate(&ciph_ctx, tmp_buf, &tmp_len,
                           (unsigned char *)input->data, input->length);
        output->length = tmp_len;
        if(ret)
            ret = EVP_EncryptFinal_ex(&ciph_ctx,tmp_buf+tmp_len,&tmp_len);
    }

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (ret == 1){
        memcpy(output->data, tmp_buf, output->length);
        ret = 0;
    } else {
        ret = KRB5_CRYPTO_INTERNAL;
    }

    memset(tmp_buf, 0, input->length);
    OPENSSL_free(tmp_buf);

    return ret;
}

static krb5_error_code
cbc_decr(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    int              ret = 0, tmp_len = 0;
    unsigned char   *tmp_buf = NULL;
    EVP_CIPHER_CTX   ciph_ctx;

    tmp_len = input->length;
    tmp_buf = OPENSSL_malloc(input->length);
    if (!tmp_buf){
        return ENOMEM;
    }

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_DecryptInit_ex(&ciph_ctx, map_mode(key->keyblock.length),
                  NULL, key->keyblock.contents, (ivec) ? (unsigned char*)ivec->data : NULL);
    if (ret == 1) {
        EVP_CIPHER_CTX_set_padding(&ciph_ctx,0); 
        ret = EVP_EncryptUpdate(&ciph_ctx, tmp_buf, &tmp_len,
                           (unsigned char *)input->data, input->length);
        output->length = tmp_len;
        if (ret == 1)
            ret = EVP_DecryptFinal_ex(&ciph_ctx,tmp_buf+tmp_len,&tmp_len);
    }

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (ret == 1) {
        output->length += tmp_len;
        memcpy(output->data, tmp_buf, output->length);
        ret = 0;
    } else {
        ret = KRB5_CRYPTO_INTERNAL;
    }

    memset(tmp_buf, 0, input->length);
    OPENSSL_free(tmp_buf);

    return ret;
}

static krb5_error_code
cts_enc(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    int             ret = 0, tmp_len = 0;
    size_t          size = 0;
    unsigned char   iv_cts[IV_CTS_BUF_SIZE];
    unsigned char  *tmp_buf = NULL;
    AES_KEY         enck;

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data){
        if (ivec->length != sizeof(iv_cts))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv_cts, ivec->data,ivec->length);
    }

    tmp_buf = OPENSSL_malloc(input->length);
    if (!tmp_buf)
        return ENOMEM;
    tmp_len = input->length;

    AES_set_encrypt_key(key->keyblock.contents,
			NUM_BITS * key->keyblock.length, &enck);

    size = CRYPTO_cts128_encrypt((unsigned char *)input->data, tmp_buf,
                                 input->length, &enck,
                                 iv_cts, (cbc128_f)AES_cbc_encrypt);
    if (size <= 0 || output->length < size) {
        ret = KRB5_CRYPTO_INTERNAL;
    } else {
        output->length = size;
        memcpy(output->data, tmp_buf, output->length);
        ret = 0;
    }

    if (!ret && ivec && ivec->data)
        memcpy(ivec->data, iv_cts, sizeof(iv_cts));

    memset(tmp_buf, 0, input->length);
    OPENSSL_free(tmp_buf);

    return ret;
}

static krb5_error_code
cts_decr(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    int    ret = 0, tmp_len = 0;
    size_t size = 0;
    unsigned char   iv_cts[IV_CTS_BUF_SIZE];
    unsigned char  *tmp_buf = NULL;
    AES_KEY         deck;

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data){
        if (ivec->length != sizeof(iv_cts))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv_cts, ivec->data,ivec->length);
    }

    tmp_buf = OPENSSL_malloc(input->length);
    if (!tmp_buf)
        return ENOMEM;
    tmp_len = input->length;

    AES_set_decrypt_key(key->keyblock.contents,
			NUM_BITS * key->keyblock.length, &deck);

    size = CRYPTO_cts128_decrypt((unsigned char *)input->data, tmp_buf,
                                 input->length, &deck,
                                 iv_cts, (cbc128_f)AES_cbc_encrypt);
    if (size <= 0 || output->length < size) {
        ret = KRB5_CRYPTO_INTERNAL;
    } else {
        output->length = size + 16;
        memcpy(output->data, tmp_buf, output->length);
        ret = 0;
    }

    if (!ret && ivec && ivec->data)
        memcpy(ivec->data, iv_cts, sizeof(iv_cts));

    memset(tmp_buf, 0, input->length);
    OPENSSL_free(tmp_buf);

    return ret;
}

static krb5_error_code
cts_encr_iov(krb5_key key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data, size_t dlen)
{
    int                    ret = 0;
    int                    oblock_len = BLOCK_SIZE * num_data;
    size_t                 size = 0, tlen = 0;
    unsigned char         *oblock = NULL, *dbuf = NULL;
    unsigned char          iv_cts[IV_CTS_BUF_SIZE];
    unsigned char          iblock[BLOCK_SIZE];
    struct iov_block_state input_pos, output_pos;
    AES_KEY                enck;

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data){
        if (ivec->length != sizeof(iv_cts))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv_cts, ivec->data,ivec->length);
    }

    oblock = OPENSSL_malloc(oblock_len);
    if (!oblock){
        return ENOMEM;
    }
    dbuf = OPENSSL_malloc(dlen);
    if (!dbuf){
        OPENSSL_free(oblock);
        return ENOMEM;
    }

    memset(oblock, 0, oblock_len);
    memset(dbuf, 0, dlen);

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    tlen = 0;
    for (;;) {
        if (krb5int_c_iov_get_block(iblock, BLOCK_SIZE,
                                     data, num_data, &input_pos)){
            memcpy(dbuf+tlen,iblock, BLOCK_SIZE);

            tlen += BLOCK_SIZE;
       } else {
            memcpy(dbuf+tlen,iblock, dlen - tlen);
            break;
       }

        if (tlen > dlen) break;
    }

    AES_set_encrypt_key(key->keyblock.contents,
			NUM_BITS * key->keyblock.length, &enck);

    size = CRYPTO_cts128_encrypt((unsigned char *)dbuf, oblock, dlen, &enck,
                                 iv_cts, (cbc128_f)AES_cbc_encrypt);
    if (size <= 0) {
        ret = KRB5_CRYPTO_INTERNAL;
    } else {
        krb5int_c_iov_put_block(data, num_data,
                                oblock, dlen, &output_pos);
    }

    if (!ret && ivec && ivec->data)
        memcpy(ivec->data, iv_cts, sizeof(iv_cts));

    memset(oblock,0,oblock_len);
    memset(dbuf,0,dlen);
    OPENSSL_free(oblock);
    OPENSSL_free(dbuf);

    return ret;
}

static krb5_error_code
cts_decr_iov(krb5_key key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data, size_t dlen)
{
    int                    ret = 0;
    int                    oblock_len = BLOCK_SIZE*num_data;
    size_t                 size = 0, tlen = 0;
    unsigned char         *oblock = NULL;
    unsigned char         *dbuf = NULL;
    unsigned char          iblock[BLOCK_SIZE];
    unsigned char          iv_cts[IV_CTS_BUF_SIZE];
    struct iov_block_state input_pos, output_pos;
    AES_KEY                deck;

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data){
        if (ivec->length <= sizeof(iv_cts))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv_cts, ivec->data,ivec->length);
    }

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    oblock = OPENSSL_malloc(oblock_len);
    if (!oblock)
        return ENOMEM;
    dbuf = OPENSSL_malloc(dlen);
    if (!dbuf){
        OPENSSL_free(oblock);
        return ENOMEM;
    }

    memset(oblock, 0, oblock_len);
    memset(dbuf, 0, dlen);

    AES_set_decrypt_key(key->keyblock.contents,
			NUM_BITS * key->keyblock.length, &deck);

    tlen = 0;
    for (;;) {
        if (krb5int_c_iov_get_block(iblock, BLOCK_SIZE,
                                     data, num_data, &input_pos)){
            memcpy(dbuf+tlen,iblock, BLOCK_SIZE);

            tlen += BLOCK_SIZE;
       } else {
            memcpy(dbuf+tlen,iblock, dlen - tlen);
            break;
       }

        if (tlen > dlen) break;
    }

    size = CRYPTO_cts128_decrypt((unsigned char *)dbuf, oblock,
                                 dlen, &deck,
                                 iv_cts, (cbc128_f)AES_cbc_encrypt);
    if (size <= 0)
        ret = KRB5_CRYPTO_INTERNAL;
    else {
        krb5int_c_iov_put_block(data, num_data, oblock, dlen, &output_pos);
    }

    if (!ret && ivec && ivec->data)
        memcpy(ivec->data, iv_cts, sizeof(iv_cts));

    memset(oblock,0,oblock_len);
    memset(dbuf,0,dlen);
    OPENSSL_free(oblock);
    OPENSSL_free(dbuf);

    return ret;
}

krb5_error_code
krb5int_aes_encrypt(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    int  ret = 0;

    if (input->length <= BLOCK_SIZE){
        ret = cbc_enc(key, ivec, input, output);
    } else {
        ret = cts_enc(key, ivec, input, output);
    }

    return ret;
}

krb5_error_code
krb5int_aes_decrypt(krb5_key key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    int ret = 0;
    int nblocks = 0;

    if (input->length < BLOCK_SIZE)
        abort();

    if (input->length == BLOCK_SIZE){
        ret = cbc_decr(key, ivec, input, output);
    } else {
        ret = cts_decr(key, ivec, input, output);
    }

    return ret;
}

static krb5_error_code
krb5int_aes_encrypt_iov(krb5_key key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data)
{
    int    ret = 0;
    int    nblocks = 0;
    size_t input_length, i;

    for (i = 0, input_length = 0; i < num_data; i++){
        krb5_crypto_iov *iov = &data[i];

        if (ENCRYPT_IOV(iov))
            input_length += iov->data.length;
    }

    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    assert(nblocks > 1);

    ret = cts_encr_iov(key, ivec, data, num_data, input_length);

    return ret;
}

static krb5_error_code
krb5int_aes_decrypt_iov(krb5_key key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data)
{
    int    ret = 0;
    int    nblocks = 0;
    size_t input_length, i;

    for (i = 0, input_length = 0; i < num_data; i++) {
        krb5_crypto_iov *iov = &data[i];

        if (ENCRYPT_IOV(iov))
            input_length += iov->data.length;
    }

    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;

    assert(nblocks > 1);

    ret = cts_decr_iov(key, ivec, data, num_data, input_length);

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
    krb5int_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state,
    krb5int_aes_encrypt_iov,
    krb5int_aes_decrypt_iov
};

const struct krb5_enc_provider krb5int_enc_aes256 = {
    16,
    32, 32,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    krb5int_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state,
    krb5int_aes_encrypt_iov,
    krb5int_aes_decrypt_iov
};

