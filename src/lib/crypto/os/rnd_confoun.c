/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_random_confounder()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rnd_counfoun_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

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
	srandom((unsigned int) time(0));
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
