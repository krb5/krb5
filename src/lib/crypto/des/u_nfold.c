/*
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
 *
 *
 * N-folding algorithm
 *    Described in "A Better Key Schedule for DES-like Ciphers"
 *    by Uri Blumenthal and Steven M. Bellovin
 *    based on the work done by Lars Knudsen.
 *
 * To n-fold a number X, replicate the input value X to a length that is
 * the least common multiple of n and the length of X.  Before each
 * repetition, the input value is rotated to the right by 13 bit positions.
 * The successive n-bit chunks are added together using 1's complement
 * addition (addition with end-around carry) to yield a n-bit result.
 *
 * The algorithm here assumes that the input and output are padded to
 * octet boundaries (8-bit multiple).
 */

#include "k5-int.h"

#define ROTATE_VALUE 13

krb5_error_code
mit_des_n_fold(inbuf, inlen, outbuf, outlen)
    krb5_octet *inbuf;
    size_t inlen;
    krb5_octet *outbuf;
    size_t outlen;
{
    register int bytes;
    register krb5_octet *tempbuf;
    
    if (inbuf == (krb5_octet *)NULL)
	return EINVAL;
    if (outbuf == (krb5_octet *)NULL)
	return EINVAL;

    tempbuf = (krb5_octet *)malloc(inlen);
    if (tempbuf == (krb5_octet *)NULL)
	return ENOMEM;

    memset(outbuf, 0, outlen);
    bytes = 0;

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

    do {
	int i, j;
	register unsigned int k;

	if ((bytes % inlen) == 0) {
	    /* Rotate input */
	    k = ((bytes/inlen) * ROTATE_VALUE) % (inlen*8);
	    
	    for (j = (k+7)/8; j < inlen + (k/7)/8; j++)
		tempbuf[j % inlen] =
		    (inbuf[((8*j-k)/8)%inlen] & (((1<<(8-(k&7)))-1) <<(k&7))) +
		    (inbuf[((8*j-k)/8 + 1)%inlen] >> (8-(k&7)));
	}


	i = min(outlen - (bytes % outlen), inlen - (bytes % inlen));

	j = i;
	k = 0;
	while (j--) {
	    k = outbuf[(bytes+j) % outlen] + tempbuf[(bytes+j) % inlen] + k;
	    outbuf[(bytes+j) % outlen] = k & 0xff;
	    k >>= 8;
	}

	j = outlen-1;
	while (k) {
	    k += outbuf[j];
	    outbuf[j--] = k & 0xff;
	    k >>= 8;
	}
	
	bytes += i;
    } while (((bytes % inlen) == 0) && ((bytes % outlen) == 0));
    
    return 0;
}
