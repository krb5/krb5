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

#if !defined(lint) && !defined(SABER)
static char rcsid_timeofday_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>

#include <time.h>
#include <stdio.h>			/* needed for libos-proto.h */

#include <krb5/config.h>
#include <krb5/krb5.h>
#include <krb5/libos-proto.h>

#ifdef POSIX
#define timetype time_t
#else
#define timetype long
#endif

extern int errno;

krb5_error_code
krb5_timeofday(timeret)
register krb5_int32 *timeret;
{
    timetype tval;

    tval = time(0);
    if (tval == (timetype) -1)
	return (krb5_error_code) errno;
    *timeret = tval;
    return 0;
}
