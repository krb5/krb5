/*
 * Copyright (c) 1990 Dennis Ferguson.  All rights reserved.
 *
 * Commercial use is permitted only if products which are derived from
 * or include this software are made available for purchase and/or use
 * in Canada.  Otherwise, redistribution and use in source and binary
 * forms are permitted.
 */

/*
 * des_cbc_encrypt.c - an implementation of the DES cipher function in cbc mode
 */
#include "des_int.h"
#include "f_tables.h"

/*
 * des_cbc_encrypt - {en,de}crypt a stream in CBC mode
 */

/*
 * This routine performs DES cipher-block-chaining operation, either
 * encrypting from cleartext to ciphertext, if encrypt != 0 or
 * decrypting from ciphertext to cleartext, if encrypt == 0.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext.  The cleartext and ciphertext should be in host order.
 *
 * NOTE-- the output is ALWAYS an multiple of 8 bytes long.  If not
 * enough space was provided, your program will get trashed.
 *
 * For encryption, the cleartext string is null padded, at the end, to
 * an integral multiple of eight bytes.
 *
 * For decryption, the ciphertext will be used in integral multiples
 * of 8 bytes, but only the first "length" bytes returned into the
 * cleartext.
 */

int
mit_des_cbc_encrypt(in, out, length, schedule, ivec, enc)
	const mit_des_cblock *in;
	mit_des_cblock *out;
	unsigned long length;
	const mit_des_key_schedule schedule;
	const mit_des_cblock ivec;
	int enc;
{
	register unsigned DES_INT32 left, right;
	register unsigned DES_INT32 temp;
	const unsigned DES_INT32 *kp;
	const unsigned char *ip;
	unsigned char *op;

	/*
	 * Get key pointer here.  This won't need to be reinitialized
	 */
	kp = (const unsigned DES_INT32 *)schedule;

	/*
	 * Deal with encryption and decryption separately.
	 */
	if (enc) {
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
		ip = *in;
		op = *out;
		while (length > 0) {
			/*
			 * Get more input, xor it in.  If the length is
			 * greater than or equal to 8 this is straight
			 * forward.  Otherwise we have to fart around.
			 */
			if (length >= 8) {
				left  ^= ((*ip++) & FF_UINT32) << 24;
				left  ^= ((*ip++) & FF_UINT32) << 16;
				left  ^= ((*ip++) & FF_UINT32) <<  8;
				left  ^=  (*ip++) & FF_UINT32;
				right ^= ((*ip++) & FF_UINT32) << 24;
				right ^= ((*ip++) & FF_UINT32) << 16;
				right ^= ((*ip++) & FF_UINT32) <<  8;
				right ^=  (*ip++) & FF_UINT32;
				length -= 8;
			} else {
				/*
				 * Oh, shoot.  We need to pad the
				 * end with zeroes.  Work backwards
				 * to do this.
				 */
				ip += (int) length;
				switch(length) {
				case 7:
					right ^= (*(--ip) & FF_UINT32) <<  8;
				case 6:
					right ^= (*(--ip) & FF_UINT32) << 16;
				case 5:
					right ^= (*(--ip) & FF_UINT32) << 24;
				case 4:
					left  ^=  *(--ip) & FF_UINT32;
				case 3:
					left  ^= (*(--ip) & FF_UINT32) <<  8;
				case 2:
					left  ^= (*(--ip) & FF_UINT32) << 16;
				case 1:
					left  ^= (*(--ip) & FF_UINT32) << 24;
					break;
				}
				length = 0;
			}

			/*
			 * Encrypt what we have
			 */
			DES_DO_ENCRYPT(left, right, temp, kp);

			/*
			 * Copy the results out
			 */
			PUT_HALF_BLOCK(left, op);
			PUT_HALF_BLOCK(right, op);
		}
	} else {
		/*
		 * Decrypting is harder than encrypting because of
		 * the necessity of remembering a lot more things.
		 * Should think about this a little more...
		 */
		unsigned DES_INT32 ocipherl, ocipherr;
		unsigned DES_INT32 cipherl, cipherr;

		if (length <= 0)
			return 0;

		/*
		 * Prime the old cipher with ivec.
		 */
		ip = ivec;
		GET_HALF_BLOCK(ocipherl, ip);
		GET_HALF_BLOCK(ocipherr, ip);

		/*
		 * Now do this in earnest until we run out of length.
		 */
		ip = *in;
		op = *out;
		for (;;) {		/* check done inside loop */
			/*
			 * Read a block from the input into left and
			 * right.  Save this cipher block for later.
			 */
			GET_HALF_BLOCK(left, ip);
			GET_HALF_BLOCK(right, ip);
			cipherl = left;
			cipherr = right;

			/*
			 * Decrypt this.
			 */
			DES_DO_DECRYPT(left, right, temp, kp);

			/*
			 * Xor with the old cipher to get plain
			 * text.  Output 8 or less bytes of this.
			 */
			left ^= ocipherl;
			right ^= ocipherr;
			if (length > 8) {
				length -= 8;
				PUT_HALF_BLOCK(left, op);
				PUT_HALF_BLOCK(right, op);
				/*
				 * Save current cipher block here
				 */
				ocipherl = cipherl;
				ocipherr = cipherr;
			} else {
				/*
				 * Trouble here.  Start at end of output,
				 * work backwards.
				 */
				op += (int) length;
				switch(length) {
				case 8:
					*(--op) = (unsigned char) (right & 0xff);
				case 7:
					*(--op) = (unsigned char) ((right >> 8) & 0xff);
				case 6:
					*(--op) = (unsigned char) ((right >> 16) & 0xff);
				case 5:
					*(--op) = (unsigned char) ((right >> 24) & 0xff);
				case 4:
					*(--op) = (unsigned char) (left & 0xff);
				case 3:
					*(--op) = (unsigned char) ((left >> 8) & 0xff);
				case 2:
					*(--op) = (unsigned char) ((left >> 16) & 0xff);
				case 1:
					*(--op) = (unsigned char) ((left >> 24) & 0xff);
					break;
				}
				break;		/* we're done */
			}
		}
	}

	/*
	 * Done, return nothing.
	 */
	return 0;
}
