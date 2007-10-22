/*
 * lib/krb4/log.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2007 by the Massachusetts Institute of
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

#ifdef KRB_CRYPT_DEBUG
/* This file used to contain log() and set_logfile(). If you define 
   KRB_CRYPT_DEBUG, you'll need to define those to point to krb_log and
   krb_set_logfile, or change all the invokers. */
#endif

#include "krb.h"
#include "autoconf.h"
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#if !defined(VMS) && !defined(_WIN32)
#include <sys/time.h>
#endif
#include <stdio.h>
#include <stdarg.h>

#include "krb4int.h"
#include <klog.h>
#include "k5-platform.h"

static char *log_name = KRBLOG;
#if 0
static is_open;
#endif

/*
 * This file contains three logging routines: set_logfile()
 * to determine the file that log entries should be written to;
 * and log() and new_log() to write log entries to the file.
 */

/*
 * krb_log() is used to add entries to the logfile (see krb_set_logfile()
 * below).  Note that it is probably not portable since it makes
 * assumptions about what the compiler will do when it is called
 * with less than the correct number of arguments which is the
 * way it is usually called.
 *
 * The log entry consists of a timestamp and the given arguments
 * printed according to the given "format".
 *
 * The log file is opened and closed for each log entry.
 *
 * The return value is undefined.
 */

void krb_log(const char *format,...)
{
    FILE *logfile;
    time_t now;
    struct tm *tm;
    va_list args;

    va_start(args, format);

    if ((logfile = fopen(log_name,"a")) != NULL) {
	set_cloexec_file(logfile);
	(void) time(&now);
	tm = localtime(&now);

	fprintf(logfile,"%2d-%s-%d %02d:%02d:%02d ",tm->tm_mday,
		month_sname(tm->tm_mon + 1),1900+tm->tm_year,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
	vfprintf(logfile,format,args);
	fprintf(logfile,"\n");
	(void) fclose(logfile);
    }
    va_end(args);
    return;
}

/*
 * krb_set_logfile() changes the name of the file to which
 * messages are logged.  If krb_set_logfile() is not called,
 * the logfile defaults to KRBLOG, defined in "krb.h".
 */

void
krb_set_logfile(filename)
    char *filename;
{
    log_name = filename;
#if 0
    is_open = 0;
#endif
}

#if 0
/*
 * new_log() appends a log entry containing the give time "t" and the
 * string "string" to the logfile (see set_logfile() above).  The file
 * is opened once and left open.  The routine returns 1 on failure, 0
 * on success.
 */

krb_new_log(t,string)
    long t;
    char *string;
{
    static FILE *logfile;

    struct tm *tm;

    if (!is_open) {
        if ((logfile = fopen(log_name,"a")) == NULL) return(1);
	set_cloexec_file(logfile);
        is_open = 1;
    }

    if (t) {
        tm = localtime(&t);

        fprintf(logfile,"\n%2d-%s-%d %02d:%02d:%02d  %s",tm->tm_mday,
                month_sname(tm->tm_mon + 1),1900+tm->tm_year,
                tm->tm_hour, tm->tm_min, tm->tm_sec, string);
    }
    else {
        fprintf(logfile,"\n%20s%s","",string);
    }

    (void) fflush(logfile);
    return(0);
}
#endif
