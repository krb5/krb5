/*
 * $Source$
 * $Author$
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information,
 * please see the file <mit-copyright.h>.
 *
 * This routine generates source code that implements the "E"
 * operations of the DES.
 */

#include <stdio.h>
#include "des_internal.h"
#include "tables.h"

void gen(stream)
    FILE *stream;
{
    register i;

    /* clear the output */
    fprintf(stream, "    L2 = 0; R2 = 0;\n");

    /* only take bits from R1, put into either L2 or R2 */
    /* first setup E */
    fprintf(stream, "/* E operations */\n/* right to left */\n");
    /* first list mapping from left to left */

    for (i = 0; i <= 31; i++)
	if (E[i] < 32)
	    fprintf(stream,
		    "    if (R1 & (1<<%2d)) L2 |= 1<<%2d;\n", E[i], i);

    fprintf(stream, "\n/* now from right to right */\n");
    /*  list mapping from left to right */
    for (i = 32; i <= 47; i++)
	if (E[i] <32)
	    fprintf(stream, "    if (R1 & (1<<%2d)) R2 |= 1<<%2d;\n",
		    E[i], i-32);
}
