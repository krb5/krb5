/*
 * stime.c
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#define	DEFINE_SOCKADDR
#define NEED_TIME_H
#include "krb.h"
#include <stdio.h>                      /* for sprintf() */

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
    char *month_sname();

    adjusted_time = *t - CONVERT_TIME_EPOCH;
    tm = localtime(&adjusted_time);
    (void) sprintf(st,"%2d-%s-%d %02d:%02d:%02d",tm->tm_mday,
                   month_sname(tm->tm_mon + 1),1900+tm->tm_year,
                   tm->tm_hour, tm->tm_min, tm->tm_sec);
    return st;
}

