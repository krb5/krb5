/*
 * Copyright (c) 1990 Dennis Ferguson.  All rights reserved.
 *
 * Commercial use is permitted only if products which are derived from
 * or include this software are made available for purchase and/or use
 * in Canada.  Otherwise, redistribution and use in source and binary
 * forms are permitted.
 */

/*
 * des_cbc_cksum.c - compute an 8 byte checksum using DES in CBC mode
 */
#include "des_int.h"
#include "f_tables.h"

/*
 * This routine performs DES cipher-block-chaining checksum operation,
 * a.k.a.  Message Authentication Code.  It ALWAYS encrypts from input
 * to a single 64 bit output MAC checksum.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext. The cleartext and ciphertext should be in host order.
 *
 * NOTE-- the output is ALWAYS 8 bytes long.  If not enough space was
 * provided, your program will get trashed.
 *
 * The input is null padded, at the end (highest addr), to an integral
 * multiple of eight bytes.
 */

unsigned long
mit_des_cbc_cksum(in, out, length, schedule, ivec)
	const krb5_octet *in;
	krb5_octet *out;
	unsigned long length;
	const mit_des_key_schedule schedule;
	const krb5_octet *ivec;
{
	register unsigned DES_INT32 left, right;
	register unsigned DES_INT32 temp;
	const unsigned DES_INT32 *kp;
	const unsigned char *ip;
	unsigned char *op;
	register DES_INT32 len;

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
	ip = in;
	len = length;
	while (len > 0) {
		/*
		 * Get more input, xor it in.  If the length is
		 * greater than or equal to 8 this is straight
		 * forward.  Otherwise we have to fart around.
		 */
		if (len >= 8) {
			left  ^= ((*ip++) & FF_UINT32) << 24;
			left  ^= ((*ip++) & FF_UINT32) << 16;
			left  ^= ((*ip++) & FF_UINT32) <<  8;
			left  ^=  (*ip++) & FF_UINT32;
			right ^= ((*ip++) & FF_UINT32) << 24;
			right ^= ((*ip++) & FF_UINT32) << 16;
			right ^= ((*ip++) & FF_UINT32) <<  8;
			right ^=  (*ip++) & FF_UINT32;
			len -= 8;
		} else {
			/*
			 * Oh, shoot.  We need to pad the
			 * end with zeroes.  Work backwards
			 * to do this.
			 */
			ip += (int) len;
			switch(len) {
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
			len = 0;
		}

		/*
		 * Encrypt what we have
		 */
		kp = (const unsigned DES_INT32 *)schedule;
		DES_DO_ENCRYPT(left, right, temp, kp);
	}

	/*
	 * Done.  Left and right have the checksum.  Put it into
	 * the output.
	 */
	op = out;
	PUT_HALF_BLOCK(left, op);
	PUT_HALF_BLOCK(right, op);

	/*
	 * Return right.  I'll bet the MIT code returns this
	 * inconsistantly (with the low order byte of the checksum
	 * not always in the low order byte of the DES_INT32).  We won't.
	 */
	return right & 0xFFFFFFFFUL;
}
