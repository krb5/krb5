/*
 * lib/crypto/des/make_s.c
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
 */



#include <krb5/krb5.h>
#include <stdio.h>
#include "des_int.h"
#include "s_table.h"

void gen(stream)
    FILE *stream;
{
    /* clear the output */
    fprintf(stream,"\n\tL2 = 0; R2 = 0;");

#ifdef notdef
    /* P permutes 32 bit input R1 into 32 bit output R2 */

    fprintf(stream,"\n/* P operations */\n/* first left to left */\n");
    /* first list mapping from left to left */
    for (i = 0; i <=31; i++)
	if (S[i] < 32)
	    fprintf(stream,
		    "\n\tif (R1 & (1<<%d)) R2 |= 1<<%d;",S[i],i);
#endif
    fprintf(stream,"\n");
}
