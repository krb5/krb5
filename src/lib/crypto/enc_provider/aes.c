/*
 * lib/crypto/enc_provider/aes.c
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

#if 0
aes_rval aes_blk_len(unsigned int blen, aes_ctx cx[1]);
aes_rval aes_enc_key(const unsigned char in_key[], unsigned int klen, aes_ctx cx[1]);
aes_rval aes_enc_blk(const unsigned char in_blk[], unsigned char out_blk[], const aes_ctx cx[1]);
aes_rval aes_dec_key(const unsigned char in_key[], unsigned int klen, aes_ctx cx[1]);
aes_rval aes_dec_blk(const unsigned char in_blk[], unsigned char out_blk[], const aes_ctx cx[1]);
#endif

#define CHECK_SIZES 0

#if 0
static void printd (const char *descr, krb5_data *d) {
    int i, j;
    const int r = 16;

    printf("%s:", descr);

    for (i = 0; i < d->length; i += r) {
	printf("\n  %04x: ", i);
	for (j = i; j < i + r && j < d->length; j++)
	    printf(" %02x", 0xff & d->data[j]);
#ifdef SHOW_TEXT
	for (; j < i + r; j++)
	    printf("   ");
	printf("   ");
	for (j = i; j < i + r && j < d->length; j++) {
	    int c = 0xff & d->data[j];
	    printf("%c", isprint(c) ? c : '.');
	}
#endif
    }
    printf("\n");
}
#endif

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

krb5_error_code
krb5int_aes_encrypt(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    aes_ctx ctx;
    char tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE], tmp3[BLOCK_SIZE];
    int nblocks = 0, blockno;

/*    CHECK_SIZES; */

    if (aes_enc_key(key->contents, key->length, &ctx) != aes_good)
	abort();

    if (ivec)
	memcpy(tmp, ivec->data, BLOCK_SIZE);
    else
	memset(tmp, 0, BLOCK_SIZE);

    nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;

    if (nblocks == 1) {
	/* Used when deriving keys. */
	if (input->length < BLOCK_SIZE)
	    return KRB5_BAD_MSIZE;
	enc(output->data, input->data, &ctx);
    } else if (nblocks > 1) {
	unsigned int nleft;

	for (blockno = 0; blockno < nblocks - 2; blockno++) {
	    xorblock(tmp, input->data + blockno * BLOCK_SIZE);
	    enc(tmp2, tmp, &ctx);
	    memcpy(output->data + blockno * BLOCK_SIZE, tmp2, BLOCK_SIZE);

	    /* Set up for next block.  */
	    memcpy(tmp, tmp2, BLOCK_SIZE);
	}
	/* Do final CTS step for last two blocks (the second of which
	   may or may not be incomplete).  */
	xorblock(tmp, input->data + (nblocks - 2) * BLOCK_SIZE);
	enc(tmp2, tmp, &ctx);
	nleft = input->length - (nblocks - 1) * BLOCK_SIZE;
	memcpy(output->data + (nblocks - 1) * BLOCK_SIZE, tmp2, nleft);
	memcpy(tmp, tmp2, BLOCK_SIZE);

	memset(tmp3, 0, sizeof(tmp3));
	memcpy(tmp3, input->data + (nblocks - 1) * BLOCK_SIZE, nleft);
	xorblock(tmp, tmp3);
	enc(tmp2, tmp, &ctx);
	memcpy(output->data + (nblocks - 2) * BLOCK_SIZE, tmp2, BLOCK_SIZE);
	if (ivec)
	    memcpy(ivec->data, tmp2, BLOCK_SIZE);
    }

    return 0;
}

krb5_error_code
krb5int_aes_decrypt(const krb5_keyblock *key, const krb5_data *ivec,
		    const krb5_data *input, krb5_data *output)
{
    aes_ctx ctx;
    char tmp[BLOCK_SIZE], tmp2[BLOCK_SIZE], tmp3[BLOCK_SIZE];
    int nblocks = 0, blockno;

    CHECK_SIZES;

    if (aes_dec_key(key->contents, key->length, &ctx) != aes_good)
	abort();

    if (ivec)
	memcpy(tmp, ivec->data, BLOCK_SIZE);
    else
	memset(tmp, 0, BLOCK_SIZE);

    nblocks = (input->length + BLOCK_SIZE - 1) / BLOCK_SIZE;

    if (nblocks == 1) {
	if (input->length < BLOCK_SIZE)
	    return KRB5_BAD_MSIZE;
	dec(output->data, input->data, &ctx);
    } else if (nblocks > 1) {

	for (blockno = 0; blockno < nblocks - 2; blockno++) {
	    dec(tmp2, input->data + blockno * BLOCK_SIZE, &ctx);
	    xorblock(tmp2, tmp);
	    memcpy(output->data + blockno * BLOCK_SIZE, tmp2, BLOCK_SIZE);
	    memcpy(tmp, input->data + blockno * BLOCK_SIZE, BLOCK_SIZE);
	}
	/* Do last two blocks, the second of which (next-to-last block
	   of plaintext) may be incomplete.  */
	dec(tmp2, input->data + (nblocks - 2) * BLOCK_SIZE, &ctx);
	/* Set tmp3 to last ciphertext block, padded.  */
	memset(tmp3, 0, sizeof(tmp3));
	memcpy(tmp3, input->data + (nblocks - 1) * BLOCK_SIZE,
	       input->length - (nblocks - 1) * BLOCK_SIZE);
	/* Set tmp2 to last (possibly partial) plaintext block, and
	   save it.  */
	xorblock(tmp2, tmp3);
	memcpy(output->data + (nblocks - 1) * BLOCK_SIZE, tmp2,
	       input->length - (nblocks - 1) * BLOCK_SIZE);
	/* Maybe keep the trailing part, and copy in the last
	   ciphertext block.  */
	memcpy(tmp2, tmp3, input->length - (nblocks - 1) * BLOCK_SIZE);
	/* Decrypt, to get next to last plaintext block xor previous
	   ciphertext.  */
	dec(tmp3, tmp2, &ctx);
	xorblock(tmp3, tmp);
	memcpy(output->data + (nblocks - 2) * BLOCK_SIZE, tmp3, BLOCK_SIZE);
	if (ivec)
	    memcpy(ivec->data, input->data + (nblocks - 2) * BLOCK_SIZE,
		   BLOCK_SIZE);
    }

    return 0;
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
    struct iov_block_state input_pos, output_pos;

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

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (nblocks == 1) {
	krb5int_c_iov_get_block((unsigned char *)tmp, BLOCK_SIZE,
				data, num_data, &input_pos);
	enc(tmp2, tmp, &ctx);
	krb5int_c_iov_put_block(data, num_data, (unsigned char *)tmp2,
				BLOCK_SIZE, &output_pos);
    } else if (nblocks > 1) {
	char blockN2[BLOCK_SIZE];   /* second last */
	char blockN1[BLOCK_SIZE];   /* last block */

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
    int nblocks = 0, blockno, i;
    size_t input_length;
    struct iov_block_state input_pos, output_pos;

    CHECK_SIZES;

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

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (nblocks == 1) {
	krb5int_c_iov_get_block((unsigned char *)tmp, BLOCK_SIZE,
				data, num_data, &input_pos);
	dec(tmp2, tmp, &ctx);
	krb5int_c_iov_put_block(data, num_data, (unsigned char *)tmp2,
				BLOCK_SIZE, &output_pos);
    } else if (nblocks > 1) {
	char blockN2[BLOCK_SIZE];   /* second last */
	char blockN1[BLOCK_SIZE];   /* last block */

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

const struct krb5_enc_provider krb5int_enc_aes128 = {
    16,
    16, 16,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    k5_aes_make_key,
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
    k5_aes_make_key,
    krb5int_aes_init_state,
    krb5int_default_free_state,
    krb5int_aes_encrypt_iov,
    krb5int_aes_decrypt_iov
};

