/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/t_prf.c
 *
 * Copyright (C) 2004 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * This file contains tests for the PRF code in Kerberos.  IT reads an
 * input file, and writes an output file.  It is assumed that the
 * output file will be diffed against expected output to see whether
 * regression tests pass.  The input file is a very primitive format.
 * It includes an enctype and password to be string2keyed followed by
 * a number of bytes of input length, followed by that many bytes of
 * input.  The program outputs krb5_c_prf of that input and key as a
 * hex string.
 */

#include "k5-int.h"
#include <assert.h>

int main () {
    krb5_data input, output;
    krb5_keyblock *key = NULL;
    unsigned int in_length;
    unsigned int i;
    size_t prfsz;

    while (1) {
        krb5_enctype enctype;
        char s[1025];

        if (scanf( "%d", &enctype) == EOF)
            break;
        if (scanf("%1024s", &s[0]) == EOF)
            break;
        assert (krb5_init_keyblock(0, enctype, 0, &key) == 0);
        input.data = &s[0];
        input.length = strlen(s);
        assert(krb5_c_string_to_key (0, enctype, &input, &input, key) == 0);

        if (scanf("%u", &in_length) == EOF)
            break;

        if (in_length ) {
            unsigned int lc;
            assert ((input.data = malloc(in_length)) != NULL);
            for (lc = in_length; lc > 0; lc--) {
                scanf ("%2x",  &i);
                input.data[in_length-lc] = (unsigned) (i&0xff);
            }
            input.length = in_length;
            assert (krb5_c_prf_length(0, enctype, &prfsz) == 0);
            assert (output.data = malloc(prfsz));
            output.length = prfsz;
            assert (krb5_c_prf(0, key, &input, &output) == 0);

            free (input.data);
            input.data = NULL;
        } else {
            prfsz = 0;
        }

        for (; prfsz > 0; prfsz--) {
            printf ("%02x",
                    (unsigned int) ((unsigned char ) output.data[output.length-prfsz]));
        }
        printf ("\n");

        free (output.data);
        output.data = NULL;
        krb5_free_keyblock(0, key);
        key = NULL;
    }

    return (0);
}
