/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * CRC test driver program.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_crctest_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/crc-32.h>
#include <stdio.h>

void
main()
{
    unsigned char ckout[4];
    krb5_checksum outck;

    char input[16], expected_crc[16];
    unsigned char inbytes[4], outbytes[4];
    int in_length;
    unsigned int expect;

    int bad = 0;

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
	outbytes[0] = expect & 0xff;
	outbytes[1] = (expect >> 8) & 0xff;
	outbytes[2] = (expect >> 16) & 0xff;
	outbytes[3] = (expect >> 24) & 0xff;

	if (sscanf(input, "%lx",  &expect) != 1) {
	    fprintf(stderr, "bad expectation '%s', not hex\n",
		    expected_crc);
	    exit(1);
	}
	inbytes[0] = expect & 0xff;
	inbytes[1] = (expect >> 8) & 0xff;
	inbytes[2] = (expect >> 16) & 0xff;
	inbytes[3] = (expect >> 24) & 0xff;

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
