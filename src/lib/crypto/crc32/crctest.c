/*
 * lib/crypto/crc32/crctest.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * CRC test driver program.
 */


#include "k5-int.h"
#include "crc-32.h"
#include <stdio.h>

void
main()
{
    unsigned char ckout[4];
    krb5_checksum outck;

    char input[16], expected_crc[16];
    unsigned char inbytes[4], outbytes[4];
    int in_length;
    unsigned long expect;

    int bad = 0;

    outck.length = sizeof(ckout);
    outck.contents = ckout;

    while (scanf("%s %s", input, expected_crc) == 2) {
	in_length = strlen(input);
	if (in_length % 2) {
	    fprintf(stderr, "bad input '%s', not hex data\n", input);
	    exit(1);
	}
	in_length = in_length / 2;
	if (strlen(expected_crc) != 8) {
	    fprintf(stderr, "bad expectation '%s', not 8 chars\n",
		    expected_crc);
	    exit(1);
	}
	if (sscanf(expected_crc, "%lx",  &expect) != 1) {
	    fprintf(stderr, "bad expectation '%s', not 4bytes hex\n",
		    expected_crc);
	    exit(1);
	}
	outbytes[0] = (unsigned char) (expect & 0xff);
	outbytes[1] = (unsigned char) ((expect >> 8) & 0xff);
	outbytes[2] = (unsigned char) ((expect >> 16) & 0xff);
	outbytes[3] = (unsigned char) ((expect >> 24) & 0xff);

	if (sscanf(input, "%lx",  &expect) != 1) {
	    fprintf(stderr, "bad expectation '%s', not hex\n",
		    expected_crc);
	    exit(1);
	}
	inbytes[0] = (unsigned char) (expect & 0xff);
	inbytes[1] = (unsigned char) ((expect >> 8) & 0xff);
	inbytes[2] = (unsigned char) ((expect >> 16) & 0xff);
	inbytes[3] = (unsigned char) ((expect >> 24) & 0xff);

	(*crc32_cksumtable_entry.sum_func)((krb5_pointer)inbytes,
					   in_length, 0, 0, &outck);
	if (memcmp(outbytes, ckout, 4)) {
	    printf("mismatch: input '%s', output '%02x%02x%02x%02x', \
expected '%s'\n",
		   input, ckout[3], ckout[2], ckout[1], ckout[0],
		   expected_crc);
	    bad = 1;
	}	
    }
    if (bad) 
	printf("crctest: failed to pass the test\n");
    else
	printf("crctest: test is passed successfully\n");

    exit(bad);
}
