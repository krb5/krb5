/*
 * lib/crypto/des/make_p.c
 *
 * Copyright 1985, 1988,1990 by the Massachusetts Institute of Technology.
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
 * This routine generates the P permutation code for the DES.
 */


#include <krb5/krb5.h>
#include <stdio.h>
#include "des_int.h"
#include "tables.h"

void gen(stream)
    FILE *stream;
{
    /* P permutes 32 bit input R1 into 32 bit output R2 */	

    /* clear the output */
    fprintf(stream,"    L2 = 0;\n");
#ifndef	BIG
    fprintf(stream,"    R2 = 0;\n");
    fprintf(stream,
	    "/* P operations */\n/* from right to right */\n");
    /* first list mapping from left to left */
    for (i = 0; i <=31; i++)
	if (P[i] < 32)
	    fprintf(stream,
		    "    if (R1 & (1<<%d)) R2 |= 1<<%d;\n",P[i],i);
#else /* BIG */
    /* flip p into p_temp */
    fprintf(stream,"    P_temp = R1;\n");
    fprintf(stream,"    P_temp_p = (unsigned char *) &P_temp;\n");
 
#ifdef	LSBFIRST
    fprintf(stream,"    R2 = P_prime[0][*P_temp_p++];\n");
    fprintf(stream,"    R2 |= P_prime[1][*P_temp_p++];\n");
    fprintf(stream,"    R2 |= P_prime[2][*P_temp_p++];\n");
    fprintf(stream,"    R2 |= P_prime[3][*P_temp_p];\n");
#else /* MSBFIRST */
    fprintf(stream,"    R2 = P_prime[3][*P_temp_p++];\n");
    fprintf(stream,"    R2 |= P_prime[2][*P_temp_p++];\n");
    fprintf(stream,"    R2 |= P_prime[1][*P_temp_p++];\n");
    fprintf(stream,"    R2 |= P_prime[0][*P_temp_p];\n");
#endif /* MSBFIRST */
#endif /* BIG */
}
