/*
 * lib/crypto/os/rnd_confoun.c
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_random_confounder()
 */


#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif

/*
 * Generate a random confounder
 */
krb5_error_code
krb5_random_confounder(size, fillin)
int size;
krb5_pointer fillin;
{
    static int seeded = 0;
    register krb5_octet *real_fill; 

#ifdef __STDC__
    /* Use the srand/rand calls, see X3.159-1989, section 4.10.2 */
    if (!seeded) {
	/* time() defined in 4.12.2.4, but returns a time_t, which is an
	   "arithmetic type" (4.12.1) */
	srand((unsigned int) time(0));
	seeded = 1;
    }
#else
    /* assume Berkeley srandom...after all, this is libos! */
    if (!seeded) {
	srandom(time(0));
	seeded = 1;
    }
#endif
    real_fill = (krb5_octet *)fillin;
    while (size > 0) {

#ifdef __STDC__
	int rval;
	rval = rand();
	/* RAND_MAX is at least 32767, so we assume we can use the lower 16 bits
	   of the value of rand(). */
#else
	long rval;
	rval = random();
	/* BSD random number generator generates "in the range from
	   0 to (2**31)-1" (random(3)).  So we can use the bottom 16 bits. */
#endif
	*real_fill = rval & 0xff;
	real_fill++;
	size--;
	if (size) {
	    *real_fill = (rval >> 8) & 0xff;
	    real_fill++;
	    size--;
	}
    }
    return 0;
}
