/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_mstimeofday for BSD 4.3
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_mstime_c[] =
"$Id$";
#endif	/* lint || SABER */

#include <krb5/config.h>
#include <krb5/krb5.h>
#include <krb5/los-proto.h>
#include <krb5/sysincl.h>

extern int errno;

static struct timeval last_tv = {0, 0};

krb5_error_code
krb5_us_timeofday(seconds, microseconds)
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
