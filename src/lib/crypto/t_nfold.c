/*
 * lib/crypto/t_nfold.c
 *
 * Copyright 1988, 1990 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Program to test the correctness of nfold implementation.
 *
 * exit returns	 0 ==> success
 * 		-1 ==> error
 */

#include <stdio.h>
#include <string.h>

#include "k5-int.h"

unsigned char *nfold_in[] = {
    "basch",
    "eichin",
    "sommerfeld",
    "MASSACHVSETTS INSTITVTE OF TECHNOLOGY" };

unsigned char nfold_192[4][24] = {
    { 0x1a, 0xab, 0x6b, 0x42, 0x96, 0x4b, 0x98, 0xb2, 0x1f, 0x8c, 0xde, 0x2d,
      0x24, 0x48, 0xba, 0x34, 0x55, 0xd7, 0x86, 0x2c, 0x97, 0x31, 0x64, 0x3f },
    { 0x65, 0x69, 0x63, 0x68, 0x69, 0x6e, 0x4b, 0x73, 0x2b, 0x4b, 0x1b, 0x43,
      0xda, 0x1a, 0x5b, 0x99, 0x5a, 0x58, 0xd2, 0xc6, 0xd0, 0xd2, 0xdc, 0xca },
    { 0x2f, 0x7a, 0x98, 0x55, 0x7c, 0x6e, 0xe4, 0xab, 0xad, 0xf4, 0xe7, 0x11,
      0x92, 0xdd, 0x44, 0x2b, 0xd4, 0xff, 0x53, 0x25, 0xa5, 0xde, 0xf7, 0x5c },
    { 0xdb, 0x3b, 0x0d, 0x8f, 0x0b, 0x06, 0x1e, 0x60, 0x32, 0x82, 0xb3, 0x08,
      0xa5, 0x08, 0x41, 0x22, 0x9a, 0xd7, 0x98, 0xfa, 0xb9, 0x54, 0x0c, 0x1b }
};

int
main(argc, argv)
     int argc;
     char *argv[];
{
    unsigned char cipher_text[64];
    int i, j;

    printf("N-fold\n");
    for (i=0; i<sizeof(nfold_in)/sizeof(char *); i++) {
	printf("\tInput:\t\"%.*s\"\n", strlen(nfold_in[i]), nfold_in[i]);
	printf("\t192-Fold:\t");
	krb5_nfold(strlen(nfold_in[i])*8, nfold_in[i], 24*8, cipher_text);
	for (j=0; j<24; j++)
	    printf("%s%02x", (j&3) ? "" : " ", cipher_text[j]);
	printf("\n");
	if (memcmp(cipher_text, nfold_192[i], 24)) {
	    printf("verify: error in n-fold\n");
	    exit(-1);
	};
    }
    printf("verify: N-fold is correct\n\n");

    exit(0);
}
