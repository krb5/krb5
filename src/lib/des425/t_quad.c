/*
 * lib/des425/t_quad.c
 *
 * Copyright 2001 by the Massachusetts Institute of Technology.
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
 */


#include <stdio.h>
#include <errno.h>
#include "des_int.h"
#include "des.h"

extern unsigned long quad_cksum();
char *progname;
int des_debug;
unsigned DES_INT32 out[8];
struct {
    unsigned char text[64];
    unsigned DES_INT32 out[8];
} tests[] = {
    {
	"Now is the time for all ",
	{
	    0x6c6240c5, 0x77db9b1c, 0x7991d316, 0x4e688989,
	    0x27a0ae6a, 0x13be2da4, 0x4a2fdfc6, 0x7dfc494c,
	}
    }, {
	"7654321 Now is the time for ",
	{
	    0x36839db5, 0x4d7be717, 0x15b0f5b6, 0x2304ff9c,
	    0x75472d26, 0x6a5f833c, 0x7399a4ee, 0x1170fdfb,
	}
    }, {
	{2,0,0,0, 1,0,0,0},
	{
	    0x7c81f205, 0x63d38e38, 0x314ece44, 0x05d3a4f8,
	    0x6e10db76, 0x3eda7685, 0x2e841332, 0x1bdc7fd3,
	}
    },
};

/* 0x0123456789abcdef */
unsigned char default_key[8] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};

int
main(argc,argv)
    int argc;
    char *argv[];
{
    int i;
    int fail=0;

    progname=argv[0];		/* salt away invoking program */

    /* use known input and key */

    for (i = 0; i < 3; i++) {
	int wrong = 0, j;
	des_quad_cksum (tests[i].text, out, 64L, 4,
			(mit_des_cblock *) &default_key);
	if (tests[i].text[0] == 2)
	    printf ("quad_cksum(<binary blob 1>) = {");
	else
	    printf ("quad_cksum(\"%s\"...zero fill...) = {", tests[i].text);
	for (j = 0; j < 8; j++) {
	    if (j == 0 || j == 4)
		printf ("\n\t");
	    printf (" 0x%lx,", (unsigned long) out[j]);
	    if (out[j] != tests[i].out[j])
		wrong = 1;
	}
	printf ("\n}\n");
	if (wrong) {
	    printf ("wrong result!\n");
	    fail = 1;
	}
    }
    return fail;
}
