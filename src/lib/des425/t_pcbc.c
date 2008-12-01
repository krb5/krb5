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

char *progname;
int des_debug;

/* These test values were constructed by experimentation, because I
   couldn't be bothered to look up the spec for the encryption mode
   and see if any test vector is defined.  But really, the thing we
   need to test is that the operation we use doesn't changed.  Like
   with quad_cksum, compatibility is more important than strict
   adherence to the spec, if we have to choose.  In any case, if you
   have a useful test vector, send it in....  */
struct {
    unsigned char text[32];
    des_cblock out[4];
} tests[] = {
    {
	"Now is the time for all ",
	{
	    {  0x7f, 0x81, 0x65, 0x41, 0x21, 0xdb, 0xd4, 0xcf, },
	    {  0xf8, 0xaa, 0x09, 0x90, 0xeb, 0xc7, 0x60, 0x2b, },
	    {  0x45, 0x3e, 0x4e, 0x65, 0x83, 0x6c, 0xf1, 0x98, },
	    {  0x4c, 0xfc, 0x69, 0x72, 0x23, 0xdb, 0x48, 0x78, }
	}
    }, {
	"7654321 Now is the time for ",
	{
	    {  0xcc, 0xd1, 0x73, 0xff, 0xab, 0x20, 0x39, 0xf4, },
	    {  0x6d, 0xec, 0xb4, 0x70, 0xa0, 0xe5, 0x6b, 0x15, },
	    {  0xae, 0xa6, 0xbf, 0x61, 0xed, 0x7d, 0x9c, 0x9f, },
	    {  0xf7, 0x17, 0x46, 0x3b, 0x8a, 0xb3, 0xcc, 0x88, }
	}
    }, {
	"hi",
        { {  0x76, 0x61, 0x0e, 0x8b, 0x23, 0xa4, 0x5f, 0x34, } }
    },
};

/* 0x0123456789abcdef */
unsigned char default_key[8] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};
des_cblock ivec = {
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};

int
main(argc,argv)
    int argc;
    char *argv[];
{
    int i;
    int fail=0;
    des_cblock out[32/8];
    des_cblock out2[32/8];
    des_key_schedule sked;

    progname=argv[0];		/* salt away invoking program */

    /* use known input and key */

    for (i = 0; i < 3; i++) {
	int wrong = 0, j, jmax;
	des_key_sched (default_key, sked);
	/* This could lose on alignment... */
	des_pcbc_encrypt ((des_cblock *)&tests[i].text, out,
			  strlen(tests[i].text) + 1, sked, &ivec, 1);
	printf ("pcbc_encrypt(\"%s\") = {", tests[i].text);
	jmax = (strlen (tests[i].text) + 8) & ~7U;
	for (j = 0; j < jmax; j++) {
	    if (j % 8 == 0)
		printf ("\n\t");
	    printf (" 0x%02x,", out[j/8][j%8]);
	    if (out[j/8][j%8] != tests[i].out[j/8][j%8])
		wrong = 1;
	}
	printf ("\n}\n");

	/* reverse it */
	des_pcbc_encrypt (out, out2, jmax, sked, &ivec, 0);
	if (strcmp ((char *)out2, tests[i].text)) {
	    printf ("decrypt failed\n");
	    wrong = 1;
	} else
	    printf ("decrypt worked\n");

	if (wrong) {
	    printf ("wrong result!\n");
	    fail = 1;
	}
    }
    return fail;
}
