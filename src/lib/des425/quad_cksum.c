/*
 * lib/des425/quad_cksum.c
 *
 * Copyright 1985, 1986, 1987, 1988,1990 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Quadratic Congruential Manipulation Dectection Code
 *
 * ref: "Message Authentication"
 *		R.R. Jueneman, S. M. Matyas, C.H. Meyer
 *		IEEE Communications Magazine,
 *		Sept 1985 Vol 23 No 9 p 29-40
 *
 * This routine, part of the Athena DES library built for the Kerberos
 * authentication system, calculates a manipulation detection code for
 * a message.  It is a much faster alternative to the DES-checksum
 * method. No guarantees are offered for its security.	Refer to the
 * paper noted above for more information
 *
 * Implementation for 4.2bsd
 * by S.P. Miller	Project Athena/MIT
 */

/*
 * Algorithm (per paper):
 *		define:
 *		message to be composed of n m-bit blocks X1,...,Xn
 *		optional secret seed S in block X1
 *		MDC in block Xn+1
 *		prime modulus N
 *		accumulator Z
 *		initial (secret) value of accumulator C
 *		N, C, and S are known at both ends
 *		C and , optionally, S, are hidden from the end users
 *		then
 *			(read array references as subscripts over time)
 *			Z[0] = c;
 *			for i = 1...n
 *				Z[i] = (Z[i+1] + X[i])**2 modulo N
 *			X[n+1] = Z[n] = MDC
 *
 *		Then pick
 *			N = 2**31 -1
 *			m = 16
 *			iterate 4 times over plaintext, also use Zn
 *			from iteration j as seed for iteration j+1,
 *			total MDC is then a 128 bit array of the four
 *			Zn;
 *
 *			return the last Zn and optionally, all
 *			four as output args.
 *
 * Modifications:
 *	To inhibit brute force searches of the seed space, this
 *	implementation is modified to have
 *	Z	= 64 bit accumulator
 *	C	= 64 bit C seed
 *	N	= 2**63 - 1
 *  S	= S seed is not implemented here
 *	arithmetic is not quite real double integer precision, since we
 *	cant get at the carry or high order results from multiply,
 *	but nontheless is 64 bit arithmetic.
 */


/* System include files */
#include <stdio.h>
#include <errno.h>

#include "des.h"

/* Definitions for byte swapping */

/* vax byte order is LSB first. This is not performance critical, and
   is far more readable this way. */
#define four_bytes_vax_to_nets(x) ((((((x[3]<<8)|x[2])<<8)|x[1])<<8)|x[0])
#define vaxtohl(x) four_bytes_vax_to_nets(((unsigned char *)(x)))
#define two_bytes_vax_to_nets(x) ((x[1]<<8)|x[0])
#define vaxtohs(x) two_bytes_vax_to_nets(((unsigned char *)(x)))

/* Externals */
extern char *errmsg();
#ifndef HAVE_ERRNO
extern int errno;
#endif
extern int des_debug;

/*** Routines ***************************************************** */

KRB5_DLLIMP unsigned long KRB5_CALLCONV
des_quad_cksum(in,out,length,out_count,c_seed)
    mit_des_cblock FAR *c_seed;		/* secret seed, 8 bytes */
    unsigned char FAR *in;		/* input block */
    unsigned DES_INT32 FAR *out;	/* optional longer output */
    int out_count;			/* number of iterations */
    long length;			/* original length in bytes */
{

    /*
     * this routine both returns the low order of the final (last in
     * time) 32bits of the checksum, and if "out" is not a null
     * pointer, a longer version, up to entire 32 bytes of the
     * checksum is written unto the address pointed to.
     */

    register unsigned DES_INT32 z;
    register unsigned DES_INT32 z2;
    register unsigned DES_INT32 x;
    register unsigned DES_INT32 x2;
    register unsigned char *p;
    register DES_INT32 len;
    register int i;

    /* use all 8 bytes of seed */

    z = vaxtohl(c_seed);
    z2 = vaxtohl((char *)c_seed+4);
    if (out == NULL)
	out_count = 1;		/* default */

    /* This is repeated n times!! */
    for (i = 1; i <=4 && i<= out_count; i++) {
	len = length;
	p = in;
	while (len) {
	    if (len > 1) {
		x = (z + vaxtohs(p));
		p += 2;
		len -= 2;
	    }
	    else {
		x = (z + *(unsigned char *)p++);
		len = 0;
	    }
	    x2 = z2;
	    z  = ((x * x) + (x2 * x2)) % 0x7fffffff;
	    z2 = (x * (x2+83653421))   % 0x7fffffff; /* modulo */
#ifdef DEBUG
	    if (des_debug & 8)
		printf("%d %d\n",z,z2);
#endif
	}

	if (out != NULL) {
	    *out++ = z;
	    *out++ = z2;
	}
    }
    /* return final z value as 32 bit version of checksum */
    return z;
}
