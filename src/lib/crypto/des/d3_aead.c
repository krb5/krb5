/*
 * Copyright (C) 2008 by the Massachusetts Institute of Technology.
 * Copyright 1995 by Richard P. Basch.  All Rights Reserved.
 * Copyright 1995 by Lehman Brothers, Inc.  All Rights Reserved.
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
 * the name of Richard P. Basch, Lehman Brothers and M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  Richard P. Basch,
 * Lehman Brothers and M.I.T. make no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

#include "des_int.h"
#include "f_tables.h"
#include "../aead.h"

struct iov_block_state {
    size_t iov_pos;
    size_t data_pos;
    krb5_boolean got_header;
};

#define IOV_BLOCK_STATE_INIT(_state)	((_state)->iov_pos = (_state)->data_pos = (_state)->got_header = 0)

static void
iov_get_block(unsigned char block[MIT_DES_BLOCK_LENGTH],
	      const krb5_crypto_iov *data,
              size_t num_data,
	      struct iov_block_state *iov_state)
{
    size_t i, j = 0;

    for (i = iov_state->iov_pos; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];
	size_t nbytes;

	if (iov_state->got_header ?
	    !ENCRYPT_DATA_IOV(iov) :
	    !ENCRYPT_CONF_IOV(iov))
	    continue;

	nbytes = iov->data.length - iov_state->data_pos;
	if (nbytes > MIT_DES_BLOCK_LENGTH - j)
	    nbytes = MIT_DES_BLOCK_LENGTH - j;

	memcpy(block + j, iov->data.data + iov_state->data_pos, nbytes);

	iov_state->data_pos += nbytes;
	j += nbytes;

	assert(j <= MIT_DES_BLOCK_LENGTH);

	if (j == MIT_DES_BLOCK_LENGTH)
	    break;

	assert(iov_state->data_pos == iov->data.length);

	iov_state->data_pos = 0;
    }

    if (iov_state->got_header == 0 &&
	data[i].data.length == iov_state->data_pos) {
	/* Once we have consumed the header, return to start */
	iov_state->iov_pos = 0;
	iov_state->data_pos = 0;
	iov_state->got_header = 1;
    }

    if (j != MIT_DES_BLOCK_LENGTH)
	memset(block + j, 0, MIT_DES_BLOCK_LENGTH - j);

    iov_state->iov_pos = i;
}

static void
iov_put_block(const krb5_crypto_iov *data,
	      size_t num_data,
	      unsigned char block[MIT_DES_BLOCK_LENGTH],
	      struct iov_block_state *iov_state)
{
    size_t i, j = 0;

    for (i = iov_state->iov_pos; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];
	size_t nbytes;

	if (iov_state->got_header ?
	    !ENCRYPT_DATA_IOV(iov) :
	    !ENCRYPT_CONF_IOV(iov))
	    continue;

	nbytes = iov->data.length - iov_state->data_pos;
	if (nbytes > MIT_DES_BLOCK_LENGTH - j)
	    nbytes = MIT_DES_BLOCK_LENGTH - j;

	memcpy(iov->data.data + iov_state->data_pos, block + j, nbytes);

	iov_state->data_pos += nbytes;
	j += nbytes;

	assert(j <= MIT_DES_BLOCK_LENGTH);

	if (j == MIT_DES_BLOCK_LENGTH)
	    break;

	assert(iov_state->data_pos == iov->data.length);

	iov_state->data_pos = 0;
    }

    if (iov_state->got_header == 0 &&
	data[i].data.length == iov_state->data_pos) {
	/* Once we have consumed the header, return to start */
	iov_state->iov_pos = 0;
	iov_state->data_pos = 0;
	iov_state->got_header = 1;
    }

    iov_state->iov_pos = i;
}
void
krb5int_des3_cbc_encrypt_iov(krb5_crypto_iov *data,
			     unsigned long num_data,
			     const mit_des_key_schedule ks1,
			     const mit_des_key_schedule ks2,
			     const mit_des_key_schedule ks3,
			     mit_des_cblock ivec)
{
    unsigned DES_INT32 left, right;
    const unsigned DES_INT32 *kp1, *kp2, *kp3;
    const unsigned char *ip;
    unsigned char *op;
    struct iov_block_state input_pos, output_pos;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /*
     * Get key pointer here.  This won't need to be reinitialized
     */
    kp1 = (const unsigned DES_INT32 *)ks1;
    kp2 = (const unsigned DES_INT32 *)ks2;
    kp3 = (const unsigned DES_INT32 *)ks3;

    /*
     * Initialize left and right with the contents of the initial
     * vector.
     */
    ip = ivec;
    GET_HALF_BLOCK(left, ip);
    GET_HALF_BLOCK(right, ip);

    /*
     * Suitably initialized, now work the length down 8 bytes
     * at a time.
     */
    do {
	unsigned DES_INT32 temp;
	unsigned char iblock[MIT_DES_BLOCK_LENGTH];
	unsigned char oblock[MIT_DES_BLOCK_LENGTH];

	ip = iblock;
	op = oblock;

	iov_get_block(iblock, data, num_data, &input_pos);

	GET_HALF_BLOCK(temp, ip);
	left  ^= temp;
	GET_HALF_BLOCK(temp, ip);
	right ^= temp;

	/*
	 * Encrypt what we have
	 */
	DES_DO_ENCRYPT(left, right, kp1);
	DES_DO_DECRYPT(left, right, kp2);
	DES_DO_ENCRYPT(left, right, kp3);

	/*
	 * Copy the results out
	 */
	PUT_HALF_BLOCK(left, op);
	PUT_HALF_BLOCK(right, op);

	iov_put_block(data, num_data, oblock, &output_pos);

	if (input_pos.iov_pos == num_data && ivec != NULL)
	    memcpy(ivec, oblock, MIT_DES_BLOCK_LENGTH);
    } while (input_pos.iov_pos != num_data);
}

void
krb5int_des3_cbc_decrypt_iov(krb5_crypto_iov *data,
			     unsigned long num_data,
			     const mit_des_key_schedule ks1,
			     const mit_des_key_schedule ks2,
			     const mit_des_key_schedule ks3,
			     mit_des_cblock ivec)
{
    unsigned DES_INT32 left, right;
    const unsigned DES_INT32 *kp1, *kp2, *kp3;
    const unsigned char *ip;
    unsigned DES_INT32 ocipherl, ocipherr;
    unsigned DES_INT32 cipherl, cipherr;
    unsigned char *op;
    struct iov_block_state input_pos, output_pos;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /*
     * Get key pointer here.  This won't need to be reinitialized
     */
    kp1 = (const unsigned DES_INT32 *)ks1;
    kp2 = (const unsigned DES_INT32 *)ks2;
    kp3 = (const unsigned DES_INT32 *)ks3;

    /*
     * Decrypting is harder than encrypting because of
     * the necessity of remembering a lot more things.
     * Should think about this a little more...
     */

    if (num_data == 0)
	return;

    /*
     * Prime the old cipher with ivec.
     */
    ip = ivec;
    GET_HALF_BLOCK(ocipherl, ip);
    GET_HALF_BLOCK(ocipherr, ip);

    /*
     * Now do this in earnest until we run out of length.
     */
    do {
	/*
	 * Read a block from the input into left and
	 * right.  Save this cipher block for later.
	 */
	unsigned char iblock[MIT_DES_BLOCK_LENGTH];
	unsigned char oblock[MIT_DES_BLOCK_LENGTH];

	iov_get_block(iblock, data, num_data, &input_pos);

	ip = iblock;
	op = oblock;

	GET_HALF_BLOCK(left, ip);
	GET_HALF_BLOCK(right, ip);
	cipherl = left;
	cipherr = right;

	/*
	 * Decrypt this.
	 */
	DES_DO_DECRYPT(left, right, kp3);
	DES_DO_ENCRYPT(left, right, kp2);
	DES_DO_DECRYPT(left, right, kp1);

	/*
	 * Xor with the old cipher to get plain
	 * text.  Output 8 or less bytes of this.
	 */
	left ^= ocipherl;
	right ^= ocipherr;

	PUT_HALF_BLOCK(left, op);
	PUT_HALF_BLOCK(right, op);

	/*
	 * Save current cipher block here
	 */
	ocipherl = cipherl;
	ocipherr = cipherr;

	iov_put_block(data, num_data, oblock, &output_pos);

	if (input_pos.iov_pos == num_data && ivec != NULL)
	    memcpy(ivec, oblock, MIT_DES_BLOCK_LENGTH);
    } while (input_pos.iov_pos != num_data);
}
