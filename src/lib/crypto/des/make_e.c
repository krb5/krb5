/*
 * $Source$
 * $Author$
 *
 * Copyright 1987, 1988, 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * This routine generates source code that implements the "E"
 * operations of the DES.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_make_e_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <stdio.h>
#include "des_int.h"
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
