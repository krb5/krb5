/*
 * ptyint_update_utmp: Update or create a utmp entry
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 *
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * M.I.T. not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 * 
 */

#include <com_err.h>
#include "libpty.h"
#include "pty-int.h"

#if !defined(WTMP_FILE) && defined(_PATH_WTMP)
#define WTMP_FILE _PATH_WTMP
#endif
/* Other cases go here as necessary; else use /usr/adm/wtmp*/
#ifndef PATH_WTMP
#define PATH_WTMP "/usr/adm/wtmp"
#endif

long ptyint_update_wtmp (ent)
    struct utmp *ent;
    {
    struct utmp ut;
    struct stat statb;
    int fd;
#ifdef HAVE_SETUTXENT
    struct utmpx utx;

    getutmpx(ent, &utx);
    updwtmpx(WTMPX_FILE, &utx);
#endif

#ifdef HAVE_UPDWTMP
    updwtmp(WTMP_FILE, ent);
#else /* HAVE_UPDWTMP */

    if ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) >= 0) {
	if (!fstat(fd, &statb)) {
	  (void)memset((char *)&ut, 0, sizeof(ut));
	  (void)strncpy(ut.ut_line, ent->ut_line, sizeof(ut.ut_line));
	  (void)strncpy(ut.ut_name, ent->ut_name, sizeof(ut.ut_name));
#ifndef NO_UT_HOST
	  (void)strncpy(ut.ut_host, ent->ut_host, sizeof(ut.ut_host));
#endif
	  (void)time(&ut.ut_time);
#if defined(HAVE_GETUTENT) && defined(USER_PROCESS)
	  if (ent->ut_name) {
	    if (!ut.ut_pid)
	      ut.ut_pid = getpid();
	    ut.ut_type = USER_PROCESS;
	  } else {
#ifdef EMPTY
	    ut.ut_type = EMPTY;
#else
	    ut.ut_type = DEAD_PROCESS; /* For Linux brokenness*/
#endif	    

	  }
#endif
	    if (write(fd, (char *)&ut, sizeof(struct utmp)) !=
		sizeof(struct utmp))
	      (void)ftruncate(fd, statb.st_size);
	}
	(void)close(fd);
    }
#endif /* HAVE_UPDWTMP */
    return 0; /* no current failure cases; file not found is not failure!*/
    
}
