/*
 * ptyint_update_wtmp: Update wtmp.
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

#if !defined(WTMP_FILE) && defined(_PATH_WTMP)
#define WTMP_FILE _PATH_WTMP
#endif

#if !defined(WTMPX_FILE) && defined(_PATH_WTMPX)
#define WTMPX_FILE _PATH_WTMPX
#endif

/* if it is *still* missing, assume SunOS */
#ifndef WTMP_FILE
#define	WTMP_FILE	"/usr/adm/wtmp"
#endif

#ifdef HAVE_SETUTXENT

#if defined(HAVE_GETUTMP) && defined(NEED_GETUTMP_PROTO)
extern void getutmp(const struct utmpx *, struct utmp *);
#endif

/*
 * Welcome to conditional salad.
 *
 * This really wants to take a (const struct utmpx *) but updutmpx()
 * on Solaris at least doesn't take a const argument.  *sigh*
 */
long
ptyint_update_wtmpx(struct utmpx *ent)
{
#if !(defined(HAVE_UPDWTMPX) && defined(WTMPX_FILE))
    struct utmp ut;
#endif

#if defined(HAVE_UPDWTMPX) && defined(WTMPX_FILE)
    updwtmpx(WTMPX_FILE, ent);
    return 0;
#else

#ifdef HAVE_GETUTMP
    getutmp(ent, &ut);
#else  /* Emulate getutmp().  Yuck. */
    memset(&ut, 0, sizeof(ut));
    strncpy(ut.ut_name, ent->ut_user, sizeof(ut.ut_name));
    strncpy(ut.ut_line, ent->ut_line, sizeof(ut.ut_line));
    ut.ut_time = ent->ut_tv.tv_sec;
#ifdef HAVE_STRUCT_UTMP_UT_HOST
    strncpy(ut.ut_host, ent->ut_host, sizeof(ut.ut_host));
    ut.ut_host[sizeof(ut.ut_host) - 1] = '\0';
#ifdef HAVE_STRUCT_UTMP_UT_SYSLEN
    ut.ut_syslen = strlen(ut.ut_host) + 1;
#endif
#endif
#ifdef HAVE_STRUCT_UTMP_UT_ID
    strncpy(ut.ut_id, ent->ut_id, sizeof(ut.ut_id));
#endif
#ifdef HAVE_STRUCT_UTMP_UT_PID
    ut.ut_pid = ent->ut_pid;
#endif
#ifdef HAVE_STRUCT_UTMP_UT_TYPE
    ut.ut_type = ent->ut_type;
#endif
#if defined(PTY_UTMP_E_EXIT) && defined(PTY_UTMPX_E_EXIT)
    ut.ut_exit.PTY_UTMP_E_EXIT = ent->ut_exit.PTY_UTMPX_E_EXIT;
    ut.ut_exit.PTY_UTMP_E_TERMINATION =
	ent->ut_exit.PTY_UTMPX_E_TERMINATION;
#endif
#endif /* !HAVE_GETUTMP */

    return ptyint_update_wtmp(&ut);
#endif /* !(defined(WTMPX_FILE) && defined(HAVE_UPDWTMPX)) */
}

#endif  /* HAVE_SETUTXENT */

#if !(defined(WTMPX_FILE) && defined(HAVE_UPDWTMPX)) \
	|| !defined(HAVE_SETUTXENT)

long
ptyint_update_wtmp(struct utmp *ent)
{
#ifndef HAVE_UPDWTMP
    int fd;
    struct stat statb;
#endif

#ifdef HAVE_UPDWTMP
    updwtmp(WTMP_FILE, ent);
#else
    fd = open(WTMP_FILE, O_WRONLY | O_APPEND, 0);
    if (fd != -1 && !fstat(fd, &statb)) {
	if (write(fd, (char *)ent, sizeof(struct utmp))
	    != sizeof(struct utmp))
	    (void)ftruncate(fd, statb.st_size);
	(void)close(fd);
    }
#endif
    /*
     * no current failure cases; file not found is not failure!
     */
    return 0;
}

#endif
