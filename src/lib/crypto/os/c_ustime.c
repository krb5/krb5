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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_mstimeofday for BSD 4.3
 */

#define	NEED_SOCKETS
#include "k5-int.h"

#ifdef _MACINTOSH

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

#include "AddressXlation.h"	/* for ip_addr, for #if 0'd net-time stuff  */

#include <script.h>		/* Defines MachineLocation, used by getTimeZoneOffset */
#include <ToolUtils.h>		/* Defines BitTst(), called by getTimeZoneOffset() */
#include <OSUtils.h>		/* Defines GetDateTime */

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

    GetDateTime (&the_time);

    sec = the_time - 
    	((66 * 365 * 24 * 60 * 60) + (17 *  24 * 60 * 60) + 
    	(getTimeZoneOffset() * 60 * 60));

    usec = 0;	/* Mac is too slow to count faster than once a second */

    if ((sec == last_sec) && (usec == last_usec)) {
	    if (++last_usec >= 1000000) {
		    last_usec = 0;
		    last_sec++;
	    }
	    sec = last_sec;
	    usec = last_usec;
    }
    else {
	    last_sec = sec;
	    last_usec = usec;
	}

    *seconds = sec;
    *microseconds = usec;

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

#elif defined (_MSDOS)


/*
 * Originally written by John Gilmore, Cygnus Support, May '94.
 * Public Domain.
 */

#include <time.h>
#include <sys/timeb.h>
#include <dos.h>
#include <string.h>

/*
 * Time handling.  Translate Unix time calls into Kerberos internal 
 * procedure calls.
 *
 * Due to the fact that DOS time can be unreliable we have reverted
 * to using the AT hardware clock and converting it to Unix time.
 */

static time_t win_gettime ();
static long win_time_get_epoch();               /* Adjust for MSC 7.00 bug */

krb5_error_code
krb5_crypto_us_timeofday(seconds, microseconds)
register krb5_int32 *seconds, *microseconds;
{
    krb5_int32 sec, usec;
    static krb5_int32 last_sec = 0;
    static krb5_int32 last_usec = 0;

    sec = win_gettime ();                       /* Get the current time */
    usec = 0;                                   /* Can't do microseconds */

    if (sec == last_sec) {                      /* Same as last time??? */
        usec = ++last_usec;                     /* Yep, so do microseconds */
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


static time_t
win_gettime () {
    struct tm tm;
    union _REGS inregs;                         /* For calling BIOS */
    union _REGS outregs;
    struct _timeb now;
    time_t time;
    long convert;                               /* MSC 7.00 bug work around */

    _ftime(&now);                               /* Daylight savings time */

    /* Get time from AT hardware clock INT 0x1A, AH=2 */
    memset(&inregs, 0, sizeof(inregs));
    inregs.h.ah = 2;
    _int86(0x1a, &inregs, &outregs);

    /* 0x13 = decimal 13, hence the decoding below */
    tm.tm_sec = 10 * ((outregs.h.dh & 0xF0) >> 4) + (outregs.h.dh & 0x0F);
    tm.tm_min = 10 * ((outregs.h.cl & 0xF0) >> 4) + (outregs.h.cl & 0x0F);
    tm.tm_hour = 10 * ((outregs.h.ch & 0xF0) >> 4) + (outregs.h.ch & 0x0F);

    /* Get date from AT hardware clock INT 0x1A, AH=4 */
    memset(&inregs, 0, sizeof(inregs));
    inregs.h.ah = 4;
    _int86(0x1a, &inregs, &outregs);

    tm.tm_mday = 10 * ((outregs.h.dl & 0xF0) >> 4) + (outregs.h.dl & 0x0F);
    tm.tm_mon = 10 * ((outregs.h.dh & 0xF0) >> 4) + (outregs.h.dh & 0x0F) - 1;
    tm.tm_year = 10 * ((outregs.h.cl & 0xF0) >> 4) + (outregs.h.cl & 0x0F);
    tm.tm_year += 100 * ((10 * (outregs.h.ch & 0xF0) >> 4)
	            + (outregs.h.ch & 0x0F) - 19);

    tm.tm_wday = 0;
    tm.tm_yday = 0;
    tm.tm_isdst = now.dstflag;

    time = mktime(&tm);

    convert = win_time_get_epoch();
    return time + convert;

}


/*
 * This routine figures out the current time epoch and returns the
 * conversion factor.  It exists because 
 * Microloss screwed the pooch on the time() and _ftime() calls in
 * its release 7.0 libraries.  They changed the epoch to Dec 31, 1899!
 * Idiots...   We try to cope.
 */

static struct tm jan_1_70 = {0, 0, 0, 1, 0, 70};
static long epoch = 0;
static int epoch_set = 0;

long
win_time_get_epoch()
{

    if (!epoch_set) {
        epoch = 0 - mktime (&jan_1_70);	/* Seconds til 1970 localtime */
        epoch += _timezone;		/* Seconds til 1970 GMT */
        epoch_set = 1;
    }
    return epoch;
}


#else


/* We're a Unix machine -- do Unix time things.  */

extern int errno;

static struct timeval last_tv = {0, 0};

krb5_error_code
krb5_crypto_us_timeofday(seconds, microseconds)
    register krb5_int32 *seconds, *microseconds;
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
