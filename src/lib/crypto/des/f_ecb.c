/*
 * Copyright (c) 1990 Dennis Ferguson.  All rights reserved.
 *
 * Commercial use is permitted only if products which are derived from
 * or include this software are made available for purchase and/or use
 * in Canada.  Otherwise, redistribution and use in source and binary
 * forms are permitted.
 */

/*
 * des_ecb_encrypt.c - do an encryption in ECB mode
 */
#include "des_int.h"
#include "f_tables.h"

/*
 * des_ecb_encrypt - {en,de}crypt a block in ECB mode
 */
int
mit_des_ecb_encrypt(in, out, schedule, encrypt)
	const mit_des_cblock *in;
	mit_des_cblock *out;
	mit_des_key_schedule schedule;
	int encrypt;
{
	register unsigned DES_INT32 left, right;
	register unsigned DES_INT32 temp;
	register int i;

	{
		/*
		 * Need a temporary for copying the data in
		 */
		register unsigned char *datap;

		/*
		 * Copy the input block into the registers
		 */
		datap = (unsigned char *)in;
		GET_HALF_BLOCK(left, datap);
		GET_HALF_BLOCK(right, datap);
	}

	/*
	 * Do the initial permutation.
	 */
	DES_INITIAL_PERM(left, right, temp);

	/*
	 * Now the rounds.  Use different code depending on whether it
	 * is an encryption or a decryption (gross, should keep both
	 * sets of keys in the key schedule instead).
	 */
	if (encrypt) {
		register unsigned DES_INT32 *kp;

		kp = (unsigned DES_INT32 *)schedule;
		for (i = 0; i < 8; i++) {
			DES_SP_ENCRYPT_ROUND(left, right, temp, kp);
			DES_SP_ENCRYPT_ROUND(right, left, temp, kp);
		}
	} else {
		register unsigned DES_INT32 *kp;

		/*
		 * Point kp past end of schedule
		 */
		kp = ((unsigned DES_INT32 *)schedule) + (2 * 16);;
		for (i = 0; i < 8; i++) {
			DES_SP_DECRYPT_ROUND(left, right, temp, kp);
			DES_SP_DECRYPT_ROUND(right, left, temp, kp);
		}
	}

	/*
	 * Do the final permutation
	 */
	DES_FINAL_PERM(left, right, temp);

	/*
	 * Finally, copy the result out a byte at a time
	 */
	{
		register unsigned char *datap;

		datap = (unsigned char *)out;
		PUT_HALF_BLOCK(left, datap);
		PUT_HALF_BLOCK(right, datap);
	}

	/*
	 * return nothing
	 */
	return (0);
}
