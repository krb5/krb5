/*
 * pty_logwtmp: Implement the logwtmp function if not present.
 *
 * Copyright 1995, 2001 by the Massachusetts Institute of Technology.
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * M.I.T. not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 * 
 */

#include "com_err.h"
#include "libpty.h"
#include "pty-int.h"

#if defined(HAVE_SETUTXENT) || defined(HAVE_SETUTENT)
#ifdef HAVE_SETUTXENT
#define PTY_STRUCT_UTMPX struct utmpx
#else
#define PTY_STRUCT_UTMPX struct utmp
#endif

#ifdef NEED_LOGWTMP_PROTO
void logwtmp(const char *, const char *, const char *);
#endif

long
pty_logwtmp(const char *tty, const char *user, const char *host)
{
#ifndef HAVE_LOGWTMP
    PTY_STRUCT_UTMPX utx;
    int loggingin;
    size_t len;
    const char *cp;
    char utmp_id[5];
#endif

#ifdef HAVE_LOGWTMP
    logwtmp(tty,user,host);
    return 0;
#else

    loggingin = (user[0] != '\0');

    memset(&utx, 0, sizeof(utx));
    strncpy(utx.ut_line, tty, sizeof(utx.ut_line));
    strncpy(utx.ut_user, user, sizeof(utx.ut_user));
#if (defined(HAVE_SETUTXENT) && defined(HAVE_STRUCT_UTMPX_UT_HOST))	   \
	|| (!defined(HAVE_SETUTXENT) && defined(HAVE_STRUCT_UTMP_UT_HOST))
    strncpy(utx.ut_host, host, sizeof(utx.ut_host));
    utx.ut_host[sizeof(utx.ut_host) - 1] = '\0';
#endif
#ifdef HAVE_SETUTXENT
    gettimeofday(&utx.ut_tv, NULL);
#else
    (void)time(&utx.ut_time);
#endif
    utx.ut_pid = (loggingin ? getpid() : 0);
    utx.ut_type = (loggingin ? USER_PROCESS : DEAD_PROCESS);

    len = strlen(tty);
    if (len >= 2)
	cp = tty + len - 2;
    else
	cp = tty;
    snprintf(utmp_id, sizeof(utmp_id), "kr%s", cp);
    strncpy(utx.ut_id, utmp_id, sizeof(utx.ut_id));

#ifdef HAVE_SETUTXENT
    return ptyint_update_wtmpx(&utx);
#else
    return ptyint_update_wtmp(&utx);
#endif

#endif /* !HAVE_LOGWTMP */
}

#else  /* !(defined(HAVE_SETUTXENT) || defined(HAVE_SETUTENT)) */

long
pty_logwtmp(const char *tty, const char *user, const char *host)
{
    struct utmp ut;

#ifdef HAVE_LOGWTMP
    logwtmp(tty,user,host);
    return 0;
#else

    memset(&ut, 0, sizeof(ut));
#ifdef HAVE_STRUCT_UTMP_UT_HOST
    strncpy(ut.ut_host, host, sizeof(ut.ut_host));
    ut.ut_host[sizeof(ut.ut_host) - 1] = '\0';
#endif
    strncpy(ut.ut_line, tty, sizeof(ut.ut_line));
    strncpy(ut.ut_name, user, sizeof(ut.ut_name));
    return ptyint_update_wtmp(&ut);

#endif /* !HAVE_LOGWTMP */
}

#endif /* !(defined(HAVE_SETUTXENT) || defined(HAVE_SETUTENT)) */
