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
#include <sys/time.h>

krb5_ui_4 INTERFACE
unix_time_gmt_unixsec (usecptr)
     krb5_ui_4	*usecptr;
{
	struct timeval	now;

	(void) gettimeofday (&now, (struct timezone *)0);
	if (usecptr)
		*usecptr = now.tv_usec;
	return now.tv_sec;
}
