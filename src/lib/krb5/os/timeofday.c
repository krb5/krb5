/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * libos: krb5_timeofday function for BSD 4.3 
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_timeofday_c[] =
"$Id$";
#endif	/* lint || saber */

#include <time.h>
#include <stdio.h>			/* needed for libos-proto.h */

#include <krb5/config.h>
#include <krb5/krb5.h>
#include <krb5/los-proto.h>

#ifdef POSIX_TYPES
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
