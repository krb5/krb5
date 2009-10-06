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
#include "aes.h"
#include <aead.h>
#include <hash_provider/hash_provider.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <rand2key.h>

/* proto's */
static krb5_error_code
cts_enc(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output);
static krb5_error_code
cbc_enc(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output);
static krb5_error_code
cts_decr(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output);
static krb5_error_code
cbc_decr(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output);
static krb5_error_code
cts_enc_iov(const krb5_keyblock *key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data);
static krb5_error_code
cts_decr_iov(const krb5_keyblock *key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data);

static const EVP_CIPHER *
map_mode( unsigned int len)
{
    if (len==16)
        return EVP_aes_128_cbc();
    if (len==32)
        return EVP_aes_256_cbc();
    else
        return NULL;
}

static inline void enc(char *out, const char *in, aes_ctx *ctx)
{
    if (aes_enc_blk((const unsigned char *)in, (unsigned char *)out, ctx)
	!= aes_good)
	abort();
}
static inline void dec(char *out, const char *in, aes_ctx *ctx)
{
    if (aes_dec_blk((const unsigned char *)in, (unsigned char *)out, ctx)
	!= aes_good)
	abort();
}
static void xorblock(char *out, const char *in)
{
    int z;
    for (z = 0; z < BLOCK_SIZE; z++)
	out[z] ^= in[z];
}


static krb5_error_code
cbc_enc(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    EVP_CIPHER_CTX  ciph_ctx;
    unsigned char   *key_buf = NULL;
    unsigned char  *tmp_buf = NULL;
    int  ret = 0, tmp_len = 0;

    key_buf = OPENSSL_malloc(key->length);
    if (!key_buf)
        return ENOMEM;
    tmp_len = input->length;
    tmp_buf = OPENSSL_malloc(input->length);
    if (!tmp_buf){
        OPENSSL_free(key_buf);
        return ENOMEM;
    }
    memcpy(key_buf, key->contents, key->length);

    EVP_CIPHER_CTX_init(&ciph_ctx);

    if (ivec && ivec->data && (ivec->length <= EVP_MAX_IV_LENGTH)){
        ret = EVP_EncryptInit_ex(&ciph_ctx, map_mode(key->length),
                                 NULL, key_buf, (unsigned char*)ivec->data);
    } else {
        ret = EVP_EncryptInit_ex(&ciph_ctx, map_mode(key->length),
                                 NULL, key_buf, NULL);
    }

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

    OPENSSL_free(key_buf);
    OPENSSL_free(tmp_buf);

    return ret;
}

static krb5_error_code
cbc_decr(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    int ret = 0;
    int tmp_len = 0;
    unsigned char   *key_buf = NULL;
    unsigned char   *tmp_buf = NULL;
    EVP_CIPHER_CTX  ciph_ctx;


    key_buf = OPENSSL_malloc(key->length);
    if (!key_buf)
        return ENOMEM;
    tmp_len = input->length;
    tmp_buf = OPENSSL_malloc(input->length);
    if (!tmp_buf){
        OPENSSL_free(key_buf);
        return ENOMEM;
    }
    memcpy(key_buf, key->contents, key->length);

    EVP_CIPHER_CTX_init(&ciph_ctx);

    if (ivec && ivec->data && (ivec->length <= EVP_MAX_IV_LENGTH)) {
        ret = EVP_DecryptInit_ex(&ciph_ctx, map_mode(key->length),
                                 NULL, key_buf, (unsigned char*)ivec->data);
    } else
        ret = EVP_DecryptInit_ex(&ciph_ctx, map_mode(key->length),
                                 NULL, key_buf, NULL);

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

    OPENSSL_free(key_buf);
    OPENSSL_free(tmp_buf);

    return ret;
}

static krb5_error_code
cts_enc(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    size_t          size = 0;
    int             ret = 0, tmp_len = 0;
    unsigned char   iv_cts[EVP_MAX_IV_LENGTH*4];
    unsigned char  *tmp_buf = NULL;
    AES_KEY         enck;

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data && (ivec->length <= sizeof(iv_cts)))  
        memcpy(iv_cts, ivec->data,ivec->length);

    tmp_buf = OPENSSL_malloc(input->length);
    if (!tmp_buf)
        return ENOMEM;
    tmp_len = input->length;

    AES_set_encrypt_key(key->contents, 8*key->length, &enck);

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

    OPENSSL_free(tmp_buf);

    return ret;
}

static krb5_error_code
cts_decr(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    size_t size = 0;
    int    ret = 0, tmp_len = 0;
    unsigned char   iv_cts[EVP_MAX_IV_LENGTH*4];
    unsigned char  *tmp_buf = NULL;
    AES_KEY         deck;

    memset(iv_cts,0,EVP_MAX_IV_LENGTH*4);
    if (ivec && ivec->data && (ivec->length <= EVP_MAX_IV_LENGTH))
        memcpy(iv_cts, ivec->data,ivec->length);

    tmp_buf = OPENSSL_malloc(input->length);
    if (!tmp_buf)
        return ENOMEM;
    tmp_len = input->length;

    AES_set_decrypt_key(key->contents, 8*key->length, &deck);

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

    OPENSSL_free(tmp_buf);

    return ret;
}

static krb5_error_code
cts_enc_iov(const krb5_keyblock *key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data)
{
    int                    ret = 0;
    int                    oblock_len = BLOCK_SIZE*num_data;
    size_t                 size = 0;
    AES_KEY                enck;
    unsigned char         *oblock = NULL;
    unsigned char          iblock_buf[BLOCK_SIZE*2];
    unsigned char          iblockN1[BLOCK_SIZE];
    unsigned char          iblockN2[BLOCK_SIZE];
    unsigned char          iv_cts[EVP_MAX_IV_LENGTH*4];
    struct iov_block_state input_pos, output_pos;

    oblock = OPENSSL_malloc(oblock_len);
    if (!oblock){
        return ENOMEM;
    }
    memset(oblock, 0, oblock_len);

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data && (ivec->length <= sizeof(iv_cts)))
        memcpy(iv_cts, ivec->data,ivec->length);

    AES_set_encrypt_key(key->contents, 8*key->length, &enck);

    for (;;) {

        if (!krb5int_c_iov_get_block(iblockN1, BLOCK_SIZE,
                                     data, num_data, &input_pos))
            break;
        if (!krb5int_c_iov_get_block(iblockN2, BLOCK_SIZE,
                                     data, num_data, &input_pos))
            break;

        if (input_pos.iov_pos == num_data)
            break;

        memcpy(iblock_buf,iblockN1,input_pos.data_pos);
        memcpy(iblock_buf+input_pos.data_pos,iblockN2,input_pos.data_pos);

        size = CRYPTO_cts128_encrypt((unsigned char *)iblock_buf, oblock,
                        2*BLOCK_SIZE, &enck,
                        iv_cts, (cbc128_f)AES_cbc_encrypt);
        if (size <= 0) {
            ret = KRB5_CRYPTO_INTERNAL;
            break;
        }
        krb5int_c_iov_put_block(data, num_data,
                                oblock, 2*BLOCK_SIZE, &output_pos);
    }

    memset(oblock,0,sizeof(oblock));
    OPENSSL_free(oblock);

    return ret;
}

static krb5_error_code
cts_decr_iov(const krb5_keyblock *key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data)
{
    int                    ret = 0;
    int                    oblock_len = BLOCK_SIZE*num_data;
    size_t                 size = 0;
    AES_KEY                deck;
    unsigned char         *oblock = NULL;
    unsigned char          iblock_buf[BLOCK_SIZE*2];
    unsigned char          iblockN1[BLOCK_SIZE];
    unsigned char          iblockN2[BLOCK_SIZE];
    unsigned char          iv_cts[EVP_MAX_IV_LENGTH*4];
    struct iov_block_state input_pos, output_pos;

    oblock = OPENSSL_malloc(oblock_len);
    if (!oblock){
        return ENOMEM;
    }
    memset(oblock, 0, oblock_len);

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data && (ivec->length <= sizeof(iv_cts)))
        memcpy(iv_cts, ivec->data,ivec->length);

    AES_set_decrypt_key(key->contents, 8*key->length, &deck);

    for (;;) {

        if (!krb5int_c_iov_get_block(iblockN1, BLOCK_SIZE,
                                     data, num_data, &input_pos))
            break;
        if (!krb5int_c_iov_get_block(iblockN2, BLOCK_SIZE,
                                     data, num_data, &input_pos))
            break;

        if (input_pos.iov_pos == num_data)
            break;
        memset(iblock_buf, 0, 32);
        memcpy(iblock_buf,iblockN1,input_pos.data_pos);
        memcpy(iblock_buf+input_pos.data_pos,iblockN2,input_pos.data_pos);

        size = CRYPTO_cts128_decrypt((unsigned char *)iblock_buf, oblock,
                                     2*BLOCK_SIZE, &deck,
                                     iv_cts, (cbc128_f)AES_cbc_encrypt);
        if (size <= 0) {
            ret = KRB5_CRYPTO_INTERNAL;
            break;
        }
        krb5int_c_iov_put_block(data, num_data,
                                oblock, 2*BLOCK_SIZE, &output_pos);
    }

    memset(oblock,0,sizeof(oblock));
    OPENSSL_free(oblock);

    return ret;
}

krb5_error_code
krb5int_aes_encrypt(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    int  ret = 0;

    if ( input->length < BLOCK_SIZE * 2) {

        ret = cbc_enc(key, ivec, input, output);

    } else {

        ret = cts_enc(key, ivec, input, output);
    }

    return ret;
}

krb5_error_code
krb5int_aes_decrypt(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    int ret = 0;

    if ( input->length < BLOCK_SIZE*2) {

        ret = cbc_decr(key, ivec, input, output);

    } else {

        ret = cts_decr(key, ivec, input, output);

    }

    return ret;
}

static krb5_error_code
krb5int_aes_encrypt_iov(const krb5_keyblock *key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data)
{
    int ret = 0;

    ret = cts_enc_iov(key, ivec, data, num_data);
    return ret;
}

static krb5_error_code
krb5int_aes_decrypt_iov(const krb5_keyblock *key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data)
{
    int ret = 0;

    ret = cts_decr_iov(key, ivec, data, num_data);
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

