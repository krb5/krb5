/*
 * lib/crypto/des/make_odd.c
 *
 * Copyright 1988,1990 by the Massachusetts Institute of Technology.
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
 * This routine generates an odd-parity table for use in key generation.
 */


#include <stdio.h>

void gen(stream)
    FILE *stream;
{
    /*
     * map a byte into its equivalent with odd parity, where odd
     * parity is in the least significant bit
     */
    register i, j, k, odd;

    fprintf(stream,
            "static unsigned char const odd_parity[256] = {\n");

    for (i = 0; i < 256; i++) {
        odd = 0;
        /* shift out the lsb parity bit */
        k = i >> 1;
        /* then count the other bits */
        for (j = 0; j < 7; j++) {
            odd ^= (k&1);
            k = k >> 1;
        }
        k = i&~1;
        if (!odd)
            k |= 1;
        fprintf(stream, "%3d", k);
        if (i < 255)
            fprintf(stream, ", ");
        if (i%8 == 0)
            fprintf(stream, "\n");
    }
    fprintf(stream, "};\n");
}
