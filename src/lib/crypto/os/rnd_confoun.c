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
krb5_ui_4
krb5_random_confounder PROTOTYPE((void))
{
    static int seeded = 0;
    long retval;

    /* XXX this needs an alternative for an X3J11 C environment,
       to use srand() and rand() */
    if (!seeded) {
	srandom(time(0));
	seeded = 1;
    }
    /* this only gives us 31 random buts, but so what ? */
    retval = random();
    return (krb5_ui_4) retval;
}
