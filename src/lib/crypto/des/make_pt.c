/*
 * lib/crypto/des/make_pt.c
 *
 * Copyright 1985, 1988, 1990 by the Massachusetts Institute of Technology.
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
 */


#include <krb5/krb5.h>
#include <stdio.h>
#include "des_int.h"
#include "tables.h"

static unsigned char P_temp[32];
static unsigned long P_prime[4][256];

void gen(stream)
    FILE *stream;
{
    register i,j,k,m;
    /* P permutes 32 bit input R1 into 32 bit output R2 */

#ifdef BIG
    /* flip p into p_temp */
    for (i = 0; i<32; i++)
	P_temp[P[rev_swap_bit_pos_0(i)]] = rev_swap_bit_pos_0(i);

    /*
     * now for each byte of input, figure out all possible combinations
     */
    for (i = 0; i <4 ; i ++) {	/* each input byte */
	for (j = 0; j<256; j++) { /* each possible byte value */
	    /* flip bit order */
	    k = j;
	    /* swap_byte_bits(j); */
	    for (m = 0; m < 8; m++) { /* each bit */
		if (k & (1 << m)) {
		    /* set output values */
		    P_prime[i][j] |= 1 << P_temp[(i*8)+m];
		}
	    }
	}
    }

    fprintf(stream,
	    "\n\tstatic unsigned long const P_prime[4][256] = {\n\t");
    for (i = 0; i < 4; i++) {
	fprintf(stream,"\n");
	for (j = 0; j < 64; j++) {
	    fprintf(stream,"\n");
	    for (k = 0; k < 4; k++) {
		fprintf(stream,"0x%08X",P_prime[i][j*4+k]);
		if ((i == 3) && (j == 63) && (k == 3))
		    fprintf(stream,"\n};");
		else
		    fprintf(stream,", ");
	    }
	}
    }

#endif
    fprintf(stream,"\n");
}
