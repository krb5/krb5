/*
 * lib/krb4/stime.c
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
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
 */

#include "krb.h"
#include "krb4int.h"
#include <stdio.h>                      /* for sprintf() */
#ifndef _WIN32
#include <time.h>
#include <sys/time.h>
#endif

/*
 * Given a pointer to a long containing the number of seconds
 * since the beginning of time (midnight 1 Jan 1970 GMT), return
 * a string containing the local time in the form:
 *
 * "25-Jan-88 10:17:56"
 */

char *krb_stime(t)
    long *t;
{
    static char st[40];
    static time_t adjusted_time;
    struct tm *tm;

    adjusted_time = *t - CONVERT_TIME_EPOCH;
    tm = localtime(&adjusted_time);
    (void) snprintf(st,sizeof(st),"%2d-%s-%d %02d:%02d:%02d",tm->tm_mday,
		    month_sname(tm->tm_mon + 1),1900+tm->tm_year,
		    tm->tm_hour, tm->tm_min, tm->tm_sec);
    return st;
}

