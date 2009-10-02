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
    aes_ctx ctx;
    char tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE];
    int nblocks = 0, blockno;
    size_t input_length, i;

    if (aes_enc_key(key->contents, key->length, &ctx) != aes_good)
	abort();

    if (ivec != NULL)
	memcpy(tmp, ivec->data, BLOCK_SIZE);
    else
	memset(tmp, 0, BLOCK_SIZE);

    for (i = 0, input_length = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	if (ENCRYPT_IOV(iov))
	    input_length += iov->data.length;
    }

    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;

    assert(nblocks > 1);

    {
	char blockN2[BLOCK_SIZE];   /* second last */
	char blockN1[BLOCK_SIZE];   /* last block */
	struct iov_block_state input_pos, output_pos;

	IOV_BLOCK_STATE_INIT(&input_pos);
	IOV_BLOCK_STATE_INIT(&output_pos);

	for (blockno = 0; blockno < nblocks - 2; blockno++) {
	    char blockN[BLOCK_SIZE];

	    krb5int_c_iov_get_block((unsigned char *)blockN, BLOCK_SIZE, data, num_data, &input_pos);
	    xorblock(tmp, blockN);
	    enc(tmp2, tmp, &ctx);
	    krb5int_c_iov_put_block(data, num_data, (unsigned char *)tmp2, BLOCK_SIZE, &output_pos);

	    /* Set up for next block.  */
	    memcpy(tmp, tmp2, BLOCK_SIZE);
	}

	/* Do final CTS step for last two blocks (the second of which
	   may or may not be incomplete).  */

	/* First, get the last two blocks */
	memset(blockN1, 0, sizeof(blockN1)); /* pad last block with zeros */
	krb5int_c_iov_get_block((unsigned char *)blockN2, BLOCK_SIZE, data, num_data, &input_pos);
	krb5int_c_iov_get_block((unsigned char *)blockN1, BLOCK_SIZE, data, num_data, &input_pos);

	/* Encrypt second last block */
	xorblock(tmp, blockN2);
	enc(tmp2, tmp, &ctx);
	memcpy(blockN2, tmp2, BLOCK_SIZE); /* blockN2 now contains first block */
	memcpy(tmp, tmp2, BLOCK_SIZE);

	/* Encrypt last block */
	xorblock(tmp, blockN1);
	enc(tmp2, tmp, &ctx);
	memcpy(blockN1, tmp2, BLOCK_SIZE);

	/* Put the last two blocks back into the iovec (reverse order) */
	krb5int_c_iov_put_block(data, num_data, (unsigned char *)blockN1, BLOCK_SIZE, &output_pos);
	krb5int_c_iov_put_block(data, num_data, (unsigned char *)blockN2, BLOCK_SIZE, &output_pos);

	if (ivec != NULL)
	    memcpy(ivec->data, blockN1, BLOCK_SIZE);
    }

    return 0;
}

static krb5_error_code
krb5int_aes_decrypt_iov(const krb5_keyblock *key,
		        const krb5_data *ivec,
		        krb5_crypto_iov *data,
		        size_t num_data)
{
    aes_ctx ctx;
    char tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE], tmp3[BLOCK_SIZE];
    int nblocks = 0, blockno;
    unsigned int i;
    size_t input_length;

    if (aes_dec_key(key->contents, key->length, &ctx) != aes_good)
	abort();

    if (ivec != NULL)
	memcpy(tmp, ivec->data, BLOCK_SIZE);
    else
	memset(tmp, 0, BLOCK_SIZE);

    for (i = 0, input_length = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	if (ENCRYPT_IOV(iov))
	    input_length += iov->data.length;
    }

    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;

    assert(nblocks > 1);

    {
	char blockN2[BLOCK_SIZE];   /* second last */
	char blockN1[BLOCK_SIZE];   /* last block */
	struct iov_block_state input_pos, output_pos;

	IOV_BLOCK_STATE_INIT(&input_pos);
	IOV_BLOCK_STATE_INIT(&output_pos);

	for (blockno = 0; blockno < nblocks - 2; blockno++) {
	    char blockN[BLOCK_SIZE];

	    krb5int_c_iov_get_block((unsigned char *)blockN, BLOCK_SIZE, data, num_data, &input_pos);
	    dec(tmp2, blockN, &ctx);
	    xorblock(tmp2, tmp);
	    krb5int_c_iov_put_block(data, num_data, (unsigned char *)tmp2, BLOCK_SIZE, &output_pos);
	    memcpy(tmp, blockN, BLOCK_SIZE);
	}

	/* Do last two blocks, the second of which (next-to-last block
	   of plaintext) may be incomplete.  */

	/* First, get the last two encrypted blocks */
	memset(blockN1, 0, sizeof(blockN1)); /* pad last block with zeros */
	krb5int_c_iov_get_block((unsigned char *)blockN2, BLOCK_SIZE, data, num_data, &input_pos);
	krb5int_c_iov_get_block((unsigned char *)blockN1, BLOCK_SIZE, data, num_data, &input_pos);

	/* Decrypt second last block */
	dec(tmp2, blockN2, &ctx);
	/* Set tmp2 to last (possibly partial) plaintext block, and
	   save it.  */
	xorblock(tmp2, blockN1);
	memcpy(blockN2, tmp2, BLOCK_SIZE);

	/* Maybe keep the trailing part, and copy in the last
	   ciphertext block.  */
	input_length %= BLOCK_SIZE;
	memcpy(tmp2, blockN1, input_length ? input_length : BLOCK_SIZE);
	dec(tmp3, tmp2, &ctx);
	xorblock(tmp3, tmp);
	/* Copy out ivec first before we clobber blockN1 with plaintext */
	if (ivec != NULL)
	    memcpy(ivec->data, blockN1, BLOCK_SIZE);
	memcpy(blockN1, tmp3, BLOCK_SIZE);

	/* Put the last two blocks back into the iovec */
	krb5int_c_iov_put_block(data, num_data, (unsigned char *)blockN1, BLOCK_SIZE, &output_pos);
	krb5int_c_iov_put_block(data, num_data, (unsigned char *)blockN2, BLOCK_SIZE, &output_pos);
    }

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

