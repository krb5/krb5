/*
 * $Source$
 * $Author$
 *
 * Copyright 1987, 1988,1990 by the Massachusetts Institute of Technology.
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
 * This routine generates source code implementing the initial
 * permutation of the DES.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_make_ip_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <stdio.h>
#include "des_int.h"
#include "tables.h"


#define SWAP(x) swap_long_bytes_bit_number(swap_bit_pos_0_to_ansi(x))

void gen(stream)
    FILE *stream;
{
    register i;

    /* clear the output */
    fprintf(stream,"    L2 = 0; R2 = 0;\n");

    /* first setup IP */
    fprintf(stream,"/* IP operations */\n/* first left to left */\n");

    /* first list mapping from left to left */
    for (i = 0; i <= 31; i++)
        if (IP[i] < 32)
            test_set(stream, "L1", SWAP(IP[i]), "L2", i);

    /* now mapping from right to left */
    fprintf(stream,"\n/* now from right to left */\n");
    for (i = 0; i <= 31; i++)
        if (IP[i] >= 32)
            test_set(stream, "R1", SWAP(IP[i]-32), "L2", i);

    fprintf(stream,"\n/* now from left to right */\n");
    /*  list mapping from left to right */
    for (i = 32; i <= 63; i++)
        if (IP[i] <32)
            test_set(stream, "L1", SWAP(IP[i]), "R2", i-32);

    /* now mapping from right to right */
    fprintf(stream,"\n/* last from right to right */\n");
    for (i = 32; i <= 63; i++)
        if (IP[i] >= 32)
            test_set(stream, "R1", SWAP(IP[i]-32), "R2", i-32);
    exit(0);
}
