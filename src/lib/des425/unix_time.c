/*
 * unix_time.c
 * 
 * Glue code for pasting Kerberos into the Unix environment.
 *
 * Originally written by John Gilmore, Cygnus Support, May '94.
 * Public Domain.
 *
 * Required for use by the Cygnus krb.a.
 */


#include "k5-int.h"

#if !defined(_WIN32)
#include <sys/time.h>

krb5_ui_4
unix_time_gmt_unixsec (usecptr)
     krb5_ui_4	*usecptr;
{
	struct timeval	now;

	(void) gettimeofday (&now, (struct timezone *)0);
	if (usecptr)
		*usecptr = now.tv_usec;
	return now.tv_sec;
}

#endif /* !_WIN32 */

#ifdef _WIN32
#include <time.h>

krb5_ui_4
unix_time_gmt_unixsec (usecptr)
    krb5_ui_4 *usecptr;
{
    time_t gmt;

    time(&gmt);
    if (usecptr)
	*usecptr = gmt;
    return gmt;
}
#endif /* _WIN32 */
