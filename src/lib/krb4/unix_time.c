/*
 * unix_time.c
 * 
 * Glue code for pasting Kerberos into the Unix environment.
 *
 * Originally written by John Gilmore, Cygnus Support, May '94.
 * Public Domain.
 */

#include "krb.h"
#include <sys/time.h>

/* Time handling.  Translate Unix time calls into Kerberos cnternal 
   procedure calls.  See ../../include/cc-unix.h.  */

unsigned KRB4_32 KRB5_CALLCONV
unix_time_gmt_unixsec (usecptr)
	unsigned KRB4_32	*usecptr;
{
	struct timeval	now;

	(void) gettimeofday (&now, (struct timezone *)0);
	if (usecptr)
		*usecptr = now.tv_usec;
	return now.tv_sec;
}
