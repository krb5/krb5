/*
 * Copyright (c) 1990 Dennis Ferguson.  All rights reserved.
 *
 * Commercial use is permitted only if products which are derived from
 * or include this software are made available for purchase and/or use
 * in Canada.  Otherwise, redistribution and use in source and binary
 * forms are permitted.
 */

/*
 * des_tables.h - declarations to import the DES tables, used internally
 *		  by some of the library routines.
 */
#ifndef	__DES_TABLES_H__
#define	__DES_TABLES_H__	/* nothing */

#ifndef const
#ifndef __STDC__
#define const /* nothing */
#endif
#endif

/*
 * These may be declared const if you wish.  Be sure to change the
 * declarations in des_tables.c as well.
 */
extern const unsigned KRB_INT32 des_IP_table[256];
extern const unsigned KRB_INT32 des_FP_table[256];
extern const unsigned KRB_INT32 des_SP_table[8][64];

/*
 * Use standard shortforms to reference these to save typing
 */
#define	IP	des_IP_table
#define	FP	des_FP_table
#define	SP	des_SP_table

/*
 * Code to do a DES round using the tables.  Note that the E expansion
 * is easy to compute algorithmically, especially if done out-of-order.
 * Take a look at its form and compare it to everything involving temp
 * below.  Since SP[0-7] don't have any bits in common set it is okay
 * to do the successive xor's.
 *
 * Note too that the SP table has been reordered to match the order of
 * the keys (if the original order of SP was 12345678, the reordered
 * table is 71354682).  This is unnecessary, but was done since some
 * compilers seem to like you going through the matrix from beginning
 * to end.
 *
 * There is a difference in the best way to do this depending on whether
 * one is encrypting or decrypting.  If encrypting we move forward through
 * the keys and hence should move forward through the table.  If decrypting
 * we go back.  Part of the need for this comes from trying to emulate
 * existing software which generates a single key schedule and uses it
 * both for encrypting and decrypting.  Generating separate encryption
 * and decryption key schedules would allow one to use the same code
 * for both.
 *
 * left, right and temp should be unsigned KRB_INT32 values.  left and right
 * should be the high and low order parts of the cipher block at the
 * current stage of processing (this makes sense if you read the spec).
 * kp should be an unsigned KRB_INT32 pointer which points at the current
 * set of subkeys in the key schedule.  It is advanced to the next set
 * (i.e. by 8 bytes) when this is done.
 *
 * This occurs in the innermost loop of the DES function.  The four
 * variables should really be in registers.
 *
 * When using this, the inner loop of the DES function might look like:
 *
 *	for (i = 0; i < 8; i++) {
 *		DES_SP_{EN,DE}CRYPT_ROUND(left, right, temp, kp);
 *		DES_SP_{EN,DE}CRYPT_ROUND(right, left, temp, kp);
 *	}
 *
 * Note the trick above.  You are supposed to do 16 rounds, swapping
 * left and right at the end of each round.  By doing two rounds at
 * a time and swapping left and right in the code we can avoid the
 * swaps altogether.
 */
#define	DES_SP_ENCRYPT_ROUND(left, right, temp, kp) \
	(temp) = (((right) >> 11) | ((right) << 21)) ^ *(kp)++; \
	(left) ^= SP[0][((temp) >> 24) & 0x3f] \
		| SP[1][((temp) >> 16) & 0x3f] \
		| SP[2][((temp) >>  8) & 0x3f] \
		| SP[3][((temp)      ) & 0x3f]; \
	(temp) = (((right) >> 23) | ((right) << 9)) ^ *(kp)++; \
	(left) ^= SP[4][((temp) >> 24) & 0x3f] \
		| SP[5][((temp) >> 16) & 0x3f] \
		| SP[6][((temp) >>  8) & 0x3f] \
		| SP[7][((temp)      ) & 0x3f]

#define	DES_SP_DECRYPT_ROUND(left, right, temp, kp) \
	(temp) = (((right) >> 23) | ((right) << 9)) ^ *(--(kp)); \
	(left) ^= SP[7][((temp)      ) & 0x3f] \
		| SP[6][((temp) >>  8) & 0x3f] \
		| SP[5][((temp) >> 16) & 0x3f] \
		| SP[4][((temp) >> 24) & 0x3f]; \
	(temp) = (((right) >> 11) | ((right) << 21)) ^ *(--(kp)); \
	(left) ^= SP[3][((temp)      ) & 0x3f] \
		| SP[2][((temp) >>  8) & 0x3f] \
		| SP[1][((temp) >> 16) & 0x3f] \
		| SP[0][((temp) >> 24) & 0x3f]

/*
 * Macros to help deal with the initial permutation table.  Note
 * the IP table only deals with 32 bits at a time, allowing us to
 * collect the bits we need to deal with each half into an unsigned
 * KRB_INT32.  By carefully selecting how the bits are ordered we also
 * take advantages of symmetries in the table so that we can use a
 * single table to compute the permutation of all bytes.  This sounds
 * complicated, but if you go through the process of designing the
 * table you'll find the symmetries fall right out.
 *
 * The follow macros compute the set of bits used to index the
 * table for produce the left and right permuted result.
 */
#define	DES_IP_LEFT_BITS(left, right) \
	((((left) & 0x55555555) << 1) | ((right) & 0x55555555))
#define	DES_IP_RIGHT_BITS(left, right) \
	(((left) & 0xaaaaaaaa) | (((right) & 0xaaaaaaaa) >> 1))

/*
 * The following macro does an in-place initial permutation given
 * the current left and right parts of the block and a single
 * temporary.  Use this more as a guide for rolling your own, though.
 * The best way to do the IP depends on the form of the data you
 * are dealing with.  If you use this, though, try to make left,
 * right and temp register unsigned KRB_INT32s.
 */
#define	DES_INITIAL_PERM(left, right, temp) \
	(temp) = DES_IP_RIGHT_BITS((left), (right)); \
	(right) = DES_IP_LEFT_BITS((left), (right)); \
	(left) = IP[((right) >> 24) & 0xff] \
	       | (IP[((right) >> 16) & 0xff] << 1) \
	       | (IP[((right) >>  8) & 0xff] << 2) \
	       | (IP[(right) & 0xff] << 3); \
	(right) = IP[((temp) >> 24) & 0xff] \
		| (IP[((temp) >> 16) & 0xff] << 1) \
		| (IP[((temp) >>  8) & 0xff] << 2) \
		| (IP[(temp) & 0xff] << 3)


/*
 * Now the final permutation stuff.  The same comments apply to
 * this as to the initial permutation, except that we use different
 * bits and shifts.
 */
#define DES_FP_LEFT_BITS(left, right) \
	((((left) & 0x0f0f0f0f) << 4) | ((right) & 0x0f0f0f0f))
#define	DES_FP_RIGHT_BITS(left, right) \
	(((left) & 0xf0f0f0f0) | (((right) & 0xf0f0f0f0) >> 4))


/*
 * Here is a sample final permutation.  Note that there is a trick
 * here.  DES requires swapping the left and right parts after the
 * last cipher round but before the final permutation.  We do this
 * swapping internally, which is why left and right are confused
 * at the beginning.
 */
#define DES_FINAL_PERM(left, right, temp) \
	(temp) = DES_FP_RIGHT_BITS((right), (left)); \
	(right) = DES_FP_LEFT_BITS((right), (left)); \
	(left) = (FP[((right) >> 24) & 0xff] << 6) \
	       | (FP[((right) >> 16) & 0xff] << 4) \
	       | (FP[((right) >>  8) & 0xff] << 2) \
	       |  FP[(right) & 0xff]; \
	(right) = (FP[((temp) >> 24) & 0xff] << 6) \
		| (FP[((temp) >> 16) & 0xff] << 4) \
		| (FP[((temp) >>  8) & 0xff] << 2) \
		|  FP[temp & 0xff]


/*
 * Finally, as a sample of how all this might be held together, the
 * following two macros do in-place encryptions and decryptions.  left
 * and right are two unsigned KRB_INT32 variables which at the beginning
 * are expected to hold the clear (encrypted) block in host byte order
 * (left the high order four bytes, right the low order).  At the end
 * they will contain the encrypted (clear) block.  temp is an unsigned KRB_INT32
 * used as a temporary.  kp is an unsigned KRB_INT32 pointer pointing at
 * the start of the key schedule.  All these should be in registers.
 *
 * You can probably do better than these by rewriting for particular
 * situations.  These aren't bad, though.
 */
#define	DES_DO_ENCRYPT(left, right, temp, kp) \
	do { \
		register int i; \
		DES_INITIAL_PERM((left), (right), (temp)); \
		for (i = 0; i < 8; i++) { \
			DES_SP_ENCRYPT_ROUND((left), (right), (temp), (kp)); \
			DES_SP_ENCRYPT_ROUND((right), (left), (temp), (kp)); \
		} \
		DES_FINAL_PERM((left), (right), (temp)); \
		(kp) -= (2 * 16); \
	} while (0)

#define	DES_DO_DECRYPT(left, right, temp, kp) \
	do { \
		register int i; \
		DES_INITIAL_PERM((left), (right), (temp)); \
		(kp) += (2 * 16); \
		for (i = 0; i < 8; i++) { \
			DES_SP_DECRYPT_ROUND((left), (right), (temp), (kp)); \
			DES_SP_DECRYPT_ROUND((right), (left), (temp), (kp)); \
		} \
		DES_FINAL_PERM((left), (right), (temp)); \
	} while (0)

/*
 * These are handy dandy utility thingies for straightening out bytes.
 * Included here because they're used a couple of places.
 */
#define	GET_HALF_BLOCK(lr, ip) \
	(lr) = ((unsigned KRB_INT32)(*(ip)++)) << 24; \
	(lr) |= ((unsigned KRB_INT32)(*(ip)++)) << 16; \
	(lr) |= ((unsigned KRB_INT32)(*(ip)++)) << 8; \
	(lr) |= (unsigned KRB_INT32)(*(ip)++)

#define	PUT_HALF_BLOCK(lr, op) \
	*(op)++ = ((lr) >> 24) & 0xff; \
	*(op)++ = ((lr) >> 16) & 0xff; \
	*(op)++ = ((lr) >> 8) & 0xff; \
	*(op)++ = (lr) & 0xff

#endif	/* __DES_TABLES_H__ */
