/*
 * lib/crypto/des/make_st.c
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
#include "tables.h"

char temp[8][64];
int mit_des_debug;

void gen(stream)
    FILE *stream;
{
    register unsigned long i,j,k,l,m,n;

    /* rearrange the S table entries, and adjust for host bit order */

    fprintf(stream, "static unsigned char const S_adj[8][64] = {");
    fprintf(stream, "    /* adjusted */\n");

    for (i = 0; i<=7 ; i++) {
        for (j = 0; j <= 63; j++) {
            /*
             * figure out which one to put in the new S[i][j]
             *
             * start by assuming the value of the input bits is "j" in
             * host order, then figure out what it means in standard
             * form.
             */
            k = swap_six_bits_to_ansi(j);
            /* figure out the index for k */
            l = (((k >> 5) & 01) << 5)
                + ((k & 01) <<4) + ((k >> 1) & 0xf);
            m = S[i][l];
            /* restore in host order */
            n = swap_four_bits_to_ansi(m);
            if (mit_des_debug)
                fprintf(stderr,
                "i = %d, j = %d, k = %d, l = %d, m = %d, n = %d\n",
                        i,j,k,l,m,n);
            temp[i][j] = n;
        }
    }

    for (i = 0; i<=7; i++) {
        fprintf(stream,"\n");
        k =0;
        for (j = 0; j<= 3; j++) {
            fprintf(stream,"\n");
            for (m = 0; m <= 15; m++) {
                fprintf(stream,"%2d",temp[i][k]);
                if ((k++ != 63) || (i !=7)) {
                    fprintf(stream,", ");
                }
            }
        }
    }

    fprintf(stream,"\n};\n");
}
