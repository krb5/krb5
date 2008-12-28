/*
 * lib/crypto/enc_provider/aes_ctr.c
 *
 * Copyright (C) 2003, 2007, 2008 by the Massachusetts Institute of Technology.
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
#include "../aead.h"

#define CCM_FLAG_MASK_Q		0x07

#define CCM_COUNTER_LENGTH	3

static inline void xorblock(unsigned char *out, const unsigned char *in)
{
    int z;
    for (z = 0; z < BLOCK_SIZE; z++)
	out[z] ^= in[z];
}

/* Get the current counter block number from the IV */
static inline void getctrblockno(krb5_ui_8 *pblockno,
				 const unsigned char ctr[BLOCK_SIZE])
{
    register krb5_octet q, i;
    krb5_ui_8 blockno;

    q = ctr[0] + 1;

    assert(q >= 2 && q <= 8);

    for (i = 0, blockno = 0; i < q; i++) {
	register int s = (q - i - 1) * 8;

	blockno |= ctr[16 - q + i] << s;
    }

    *pblockno = blockno;
}

/* Store the current counter block number in the IV */
static inline void putctrblockno(krb5_ui_8 blockno,
				 unsigned char ctr[BLOCK_SIZE])
{
    register krb5_octet q, i;

    q = ctr[0] + 1;

    for (i = 0; i < q; i++) {
	register int s = (q - i - 1) * 8;

	ctr[16 - q + i] = (blockno >> s) & 0xFF;
    }
}

/*
 * ivec must be a correctly formatted counter block per SP800-38C A.3
 */
static krb5_error_code
krb5int_aes_encrypt_ctr_iov(const krb5_keyblock *key,
		            const krb5_data *ivec,
			    krb5_crypto_iov *data,
			    size_t num_data)
{
    aes_ctx ctx;
    unsigned char ctr[BLOCK_SIZE];
    krb5_ui_8 blockno;
    struct iov_block_state input_pos, output_pos;

    if (aes_enc_key(key->contents, key->length, &ctx) != aes_good)
	abort();

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /* Don't encrypt the header (B0), and use zero instead of IOV padding */
    input_pos.ignore_header = output_pos.ignore_header = 1;
    input_pos.pad_to_boundary = output_pos.pad_to_boundary = 1;

    if (ivec != NULL) {
	if (ivec->length != BLOCK_SIZE || (ivec->data[0] & ~(CCM_FLAG_MASK_Q)))
	    return KRB5_BAD_MSIZE;

	memcpy(ctr, ivec->data, BLOCK_SIZE);
    } else {
	memset(ctr, 0, BLOCK_SIZE);
	ctr[0] = CCM_COUNTER_LENGTH - 1; /* default q=3 from RFC 5116 5.3 */
    }

    getctrblockno(&blockno, ctr);

    for (;;) {
	unsigned char plain[BLOCK_SIZE];
	unsigned char ectr[BLOCK_SIZE];

	if (!krb5int_c_iov_get_block((unsigned char *)plain, BLOCK_SIZE, data, num_data, &input_pos))
	    break;

	if (aes_enc_blk(ctr, ectr, &ctx) != aes_good)
	    abort();

	xorblock(plain, ectr);
	krb5int_c_iov_put_block(data, num_data, (unsigned char *)plain, BLOCK_SIZE, &output_pos);

	putctrblockno(++blockno, ctr);
    }

    if (ivec != NULL)
	memcpy(ivec->data, ctr, sizeof(ctr));

    return 0;
}

static krb5_error_code
krb5int_aes_decrypt_ctr_iov(const krb5_keyblock *key,
			    const krb5_data *ivec,
			    krb5_crypto_iov *data,
			    size_t num_data)
{
    aes_ctx ctx;
    unsigned char ctr[BLOCK_SIZE];
    krb5_ui_8 blockno;
    struct iov_block_state input_pos, output_pos;

    if (aes_enc_key(key->contents, key->length, &ctx) != aes_good)
	abort();

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /* Don't encrypt the header (B0), and use zero instead of IOV padding */
    input_pos.ignore_header = output_pos.ignore_header = 1;
    input_pos.pad_to_boundary = output_pos.pad_to_boundary = 1;

    if (ivec != NULL) {
	if (ivec->length != BLOCK_SIZE || (ivec->data[0] & ~(CCM_FLAG_MASK_Q)))
	    return KRB5_BAD_MSIZE;

	memcpy(ctr, ivec->data, BLOCK_SIZE);
    } else {
	memset(ctr, 0, BLOCK_SIZE);
	ctr[0] = CCM_COUNTER_LENGTH - 1; /* default q=3 from RFC 5116 5.3 */
    }

    getctrblockno(&blockno, ctr);

    for (;;) {
	unsigned char ectr[BLOCK_SIZE];
	unsigned char cipher[BLOCK_SIZE];

	if (!krb5int_c_iov_get_block((unsigned char *)cipher, BLOCK_SIZE, data, num_data, &input_pos))
	    break;

	if (aes_enc_blk(ctr, ectr, &ctx) != aes_good)
	    abort();

	xorblock(cipher, ectr);
	krb5int_c_iov_put_block(data, num_data, (unsigned char *)cipher, BLOCK_SIZE, &output_pos);

	putctrblockno(++blockno, ctr);
    }

    if (ivec != NULL)
	memcpy(ivec->data, ctr, sizeof(ctr));

    return 0;
}

static krb5_error_code
krb5int_aes_encrypt_ctr(const krb5_keyblock *key, const krb5_data *ivec,
		        const krb5_data *input, krb5_data *output)
{
    krb5_crypto_iov iov[1];
    krb5_error_code ret;

    assert(output->data != NULL);

    memcpy(output->data, input->data, input->length);
    output->length = input->length;

    iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[0].data = *output;

    ret = krb5int_aes_encrypt_ctr_iov(key, ivec, iov, sizeof(iov)/sizeof(iov[0]));
    if (ret != 0) {
	zap(output->data, output->length);
    }

    return ret;
}

static krb5_error_code
krb5int_aes_decrypt_ctr(const krb5_keyblock *key, const krb5_data *ivec,
		        const krb5_data *input, krb5_data *output)
{
    krb5_crypto_iov iov[1];
    krb5_error_code ret;

    assert(output->data != NULL);

    memcpy(output->data, input->data, input->length);
    output->length = input->length;

    iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[0].data = *output;

    ret = krb5int_aes_decrypt_ctr_iov(key, ivec, iov, sizeof(iov)/sizeof(iov[0]));
    if (ret != 0) {
	zap(output->data, output->length);
    }

    return ret;
}

static krb5_error_code
k5_aes_make_key(const krb5_data *randombits, krb5_keyblock *key)
{
    if (key->length != 16 && key->length != 32)
	return(KRB5_BAD_KEYSIZE);
    if (randombits->length != key->length)
	return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;

    memcpy(key->contents, randombits->data, randombits->length);
    return(0);
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

const struct krb5_enc_provider krb5int_enc_aes128_ctr = {
    16,
    16, 16,
    krb5int_aes_encrypt_ctr,
    krb5int_aes_decrypt_ctr,
    k5_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state,
    krb5int_aes_encrypt_ctr_iov,
    krb5int_aes_decrypt_ctr_iov
};

const struct krb5_enc_provider krb5int_enc_aes256_ctr = {
    16,
    32, 32,
    krb5int_aes_encrypt_ctr,
    krb5int_aes_decrypt_ctr,
    k5_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state,
    krb5int_aes_encrypt_ctr_iov,
    krb5int_aes_decrypt_ctr_iov
};

