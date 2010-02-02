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

void
krb5int_des_cbc_encrypt_iov(krb5_crypto_iov *data,
			    unsigned long num_data,
			    const mit_des_key_schedule schedule,
			    mit_des_cblock ivec)
{
    unsigned DES_INT32 left, right;
    const unsigned DES_INT32 *kp;
    const unsigned char *ip;
    unsigned char *op;
    struct iov_block_state input_pos, output_pos;
    unsigned char iblock[MIT_DES_BLOCK_LENGTH];
    unsigned char oblock[MIT_DES_BLOCK_LENGTH];

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /*
     * Get key pointer here.  This won't need to be reinitialized
     */
    kp = (const unsigned DES_INT32 *)schedule;

    /*
     * Initialize left and right with the contents of the initial
     * vector.
     */
    if (ivec != NULL)
	ip = ivec;
    else
	ip = mit_des_zeroblock;
    GET_HALF_BLOCK(left, ip);
    GET_HALF_BLOCK(right, ip);

    /*
     * Suitably initialized, now work the length down 8 bytes
     * at a time.
     */
    for (;;) {
	unsigned DES_INT32 temp;

	ip = iblock;
	op = oblock;

	if (!krb5int_c_iov_get_block(iblock, MIT_DES_BLOCK_LENGTH, data, num_data, &input_pos))
	    break;

	if (input_pos.iov_pos == num_data)
	    break;

	GET_HALF_BLOCK(temp, ip);
	left  ^= temp;
	GET_HALF_BLOCK(temp, ip);
	right ^= temp;

	/*
	 * Encrypt what we have
	 */
	DES_DO_ENCRYPT(left, right, kp);

	/*
	 * Copy the results out
	 */
	PUT_HALF_BLOCK(left, op);
	PUT_HALF_BLOCK(right, op);

	krb5int_c_iov_put_block(data, num_data, oblock, MIT_DES_BLOCK_LENGTH, &output_pos);
    }

    if (ivec != NULL)
	memcpy(ivec, oblock, MIT_DES_BLOCK_LENGTH);
}

void
krb5int_des_cbc_decrypt_iov(krb5_crypto_iov *data,
			    unsigned long num_data,
			    const mit_des_key_schedule schedule,
			    mit_des_cblock ivec)
{
    unsigned DES_INT32 left, right;
    const unsigned DES_INT32 *kp;
    const unsigned char *ip;
    unsigned DES_INT32 ocipherl, ocipherr;
    unsigned DES_INT32 cipherl, cipherr;
    unsigned char *op;
    struct iov_block_state input_pos, output_pos;
    unsigned char iblock[MIT_DES_BLOCK_LENGTH];
    unsigned char oblock[MIT_DES_BLOCK_LENGTH];

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    /*
     * Get key pointer here.  This won't need to be reinitialized
     */
    kp = (const unsigned DES_INT32 *)schedule;

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
    if (ivec != NULL)
	ip = ivec;
    else
	ip = mit_des_zeroblock;
    GET_HALF_BLOCK(ocipherl, ip);
    GET_HALF_BLOCK(ocipherr, ip);

    /*
     * Now do this in earnest until we run out of length.
     */
    for (;;) {
	/*
	 * Read a block from the input into left and
	 * right.  Save this cipher block for later.
	 */

	if (!krb5int_c_iov_get_block(iblock, MIT_DES_BLOCK_LENGTH, data, num_data, &input_pos))
	    break;

	if (input_pos.iov_pos == num_data)
	    break;

	ip = iblock;
	op = oblock;

	GET_HALF_BLOCK(left, ip);
	GET_HALF_BLOCK(right, ip);
	cipherl = left;
	cipherr = right;

	/*
	 * Decrypt this.
	 */
	DES_DO_DECRYPT(left, right, kp);

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

	krb5int_c_iov_put_block(data, num_data, oblock, MIT_DES_BLOCK_LENGTH, &output_pos);
    }

    if (ivec != NULL) {
	op = ivec;
	PUT_HALF_BLOCK(ocipherl, op);
	PUT_HALF_BLOCK(ocipherr, op);
    }
}
