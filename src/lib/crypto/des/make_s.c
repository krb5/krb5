/*
 * $Source$
 * $Author$
 *
 * Copyright 1985, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please
 * see the file <mit-copyright.h>.
 */

#include <mit-copyright.h>
#include <stdio.h>
#include "des_internal.h"
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
