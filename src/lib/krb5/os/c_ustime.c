/*
 * lib/crypto/os/c_ustime.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * krb5_mstimeofday for BSD 4.3
 */
 
#define	NEED_SOCKETS
#include "k5-int.h"

#ifdef macintosh

/* We're a Macintosh -- do Mac time things.  */

/*
 * This code is derived from kerberos/src/lib/des/mac_time.c from
 * the Cygnus Support release of Kerberos V4:
 *
 * mac_time.c
 * (Originally time_stuff.c)
 * Copyright 1989 by the Massachusetts Institute of Technology.
 * Macintosh ooperating system interface for Kerberos.
 */

#include <ConditionalMacros.h>
#include <script.h>		/* Defines MachineLocation, used by getTimeZoneOffset */
#include <ToolUtils.h>		/* Defines BitTst(), called by getTimeZoneOffset() */
#include <OSUtils.h>		/* Defines GetDateTime */
#include <DriverServices.h> /* Nanosecond timing */
#include <CodeFragments.h>	/* Check for presence of UpTime */
#include <Math64.h>			/* 64-bit integer math */
#include <KerberosSupport/Utilities.h>		/* Mac time -> UNIX time conversion */

/* Mac Cincludes */
#include <string.h>
#include <stddef.h>

static krb5_int32 last_sec = 0, last_usec = 0;

/*
 * The Unix epoch is 1/1/70, the Mac epoch is 1/1/04.
 *
 * 70 - 4 = 66 year differential
 *
 * Thus the offset is:
 *
 * (66 yrs) * (365 days/yr) * (24 hours/day) * (60 mins/hour) * (60 secs/min)
 * plus
 * (17 leap days) * (24 hours/day) * (60 mins/hour) * (60 secs/min)
 *
 * Don't forget the offset from GMT.
 */

/* returns the offset in hours between the mac local time and the GMT  */
/* unsigned krb5_int32 */
krb5_int32
getTimeZoneOffset()
{
    MachineLocation macLocation;
    long gmtDelta;

    macLocation.u.gmtDelta=0L;
    ReadLocation(&macLocation); 
    gmtDelta=macLocation.u.gmtDelta & 0x00FFFFFF;
    if (BitTst((void *)&gmtDelta,23L))
	gmtDelta |= 0xFF000000;
    gmtDelta /= 3600L;
    return(gmtDelta);
}

/* Returns the GMT in seconds (and fake microseconds) using the Unix epoch */

krb5_error_code
krb5_crypto_us_timeofday(seconds, microseconds)
    krb5_int32 *seconds, *microseconds;
{
    krb5_int32 sec, usec;
    time_t the_time;

    GetDateTime (&sec);
    usec = 0;
	
	/* Fix secs to UNIX epoch */
	
	mac_time_to_unix_time (&sec);
	
	/* Make sure that we are _not_ repeating */
	
	if (sec < last_sec) {	/* Seconds should be at least equal to last seconds */
		sec = last_sec;
	}
	
	if (sec == last_sec) {			/* Same seconds as last time? */
		if (usec <= last_usec) {	/* Yep, microseconds must be bigger than last time*/
			usec = last_usec + 1;
		}
		
		if (usec >= 1000000) {		/* handle 1e6 wraparound */
			sec++;
			usec = 0;
		}
	}

    last_sec = sec;						/* Remember for next time */
    last_usec = usec;

    *seconds = sec;
    *microseconds = usec;					/* Return the values */

    return 0;
}

#elif defined(_WIN32)

   /* Microsoft Windows NT and 95   (32bit)  */
   /* This one works for WOW (Windows on Windows, ntvdm on Win-NT) */

#include <time.h>
#include <sys/timeb.h>
#include <string.h>

krb5_error_code
krb5_crypto_us_timeofday(seconds, microseconds)
register krb5_int32 *seconds, *microseconds;
{
    struct _timeb timeptr;
    krb5_int32 sec, usec;
    static krb5_int32 last_sec = 0;
    static krb5_int32 last_usec = 0;

    _ftime(&timeptr);                           /* Get the current time */
    sec  = timeptr.time;
    usec = timeptr.millitm * 1000;

    if ((sec == last_sec) && (usec <= last_usec)) { /* Same as last time??? */
        usec = ++last_usec;
        if (usec >= 1000000) {
            ++sec;
            usec = 0;
        }
    }
    last_sec = sec;                             /* Remember for next time */
    last_usec = usec;

    *seconds = sec;                             /* Return the values */
    *microseconds = usec;

    return 0;
}

#else


/* We're a Unix machine -- do Unix time things.  */

static struct timeval last_tv = {0, 0};

krb5_error_code
krb5_crypto_us_timeofday(register krb5_int32 *seconds, register krb5_int32 *microseconds)
{
    struct timeval tv;

    if (gettimeofday(&tv, (struct timezone *)0) == -1) {
	/* failed, return errno */
	return (krb5_error_code) errno;
    }
    if ((tv.tv_sec == last_tv.tv_sec) && (tv.tv_usec == last_tv.tv_usec)) {
	    if (++last_tv.tv_usec >= 1000000) {
		    last_tv.tv_usec = 0;
		    last_tv.tv_sec++;
	    }
	    tv = last_tv;
    } else 
	    last_tv = tv;
	    
    *seconds = tv.tv_sec;
    *microseconds = tv.tv_usec;
    return 0;
}

#endif
