/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * libos: krb5_timeofday function for BSD 4.3 
 */

#ifndef	lint
static char rcsid_timeofday_c[] =
"$Id$";
#endif	/* lint */

#include <krb5/copyright.h>

#include <sys/time.h>			/* for timeval */
#include <stdio.h>			/* needed for libos-proto.h */

#include <krb5/config.h>
#include <krb5/base-defs.h>
#include <krb5/libos-proto.h>

extern int errno;

krb5_error_code
krb5_timeofday(timeret)
register krb5_int32 *timeret;
{
    struct timeval tv;

    if (gettimeofday(&tv, (struct timezone *)0) == -1) {
	/* failed, return errno */
	return (krb5_error_code) errno;
    }
    *timeret = tv.tv_sec;
    return 0;

}
