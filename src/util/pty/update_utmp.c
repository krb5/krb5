/*
 * pty_update_utmp: Update or create a utmp entry
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

#if !defined(UTMP_FILE) && defined(_UTMP_PATH)
#define UTMP_FILE _UTMP_PATH
#endif

long pty_update_utmp (process_type, pid, username, line, host)
    int process_type;
    int pid;
    char *username, *line, *host;
{
    struct utmp ent;
#ifdef HAVE_SETUTENT
    struct utmp ut;
#else
    struct stat statb;
    int tty;
#endif
#ifdef HAVE_SETUTXENT
    struct utmpx utx;
#endif
#ifndef NO_UT_PID
    char *tmpx;
    char utmp_id[5];
#endif
    int fd;

    strncpy(ent.ut_line, line+sizeof("/dev/")-1, sizeof(ent.ut_line));
    ent.ut_time = time(0);
#ifdef NO_UT_PID
    ent.ut_pid = pid;
    switch ( process_type ) {
    case PTY_LOGIN_PROCESS:
	ent . ut_type = LOGIN_PROCESS;
	break;
    case PTY_USER_PROCESS:
	ent.ut_type = USER_PROCESS;
	break;
    case PTY_DEAD_PROCESS:
	ent.ut_type = DEAD_PROCESS;
	break;
    default:
	return PTY_UPDATE_UTMP_PROCTYPE_INVALID;
    }
#endif /*NO_UT_PID*/

#ifndef NO_UT_HOST
    if (host)
	strncpy(ent.ut_host, host, sizeof(ent.ut_host));
    else
	ent.ut_host[0] = '\0';
#endif

#ifndef NO_UT_PID
    tmpx = line + strlen(line)-1;
    if (*(tmpx-1) != '/') tmpx--; /* last two characters, unless it's a / */
    sprintf(utmp_id, "kl%s", tmpx);
    strncpy(ent.ut_id, utmp_id, sizeof(ent.ut_id));
    strncpy(ent.ut_user, username, sizeof(ent.ut_user));
#else
    strncpy(ent.ut_name, username, sizeof(ent.ut_name));
#endif
    
#ifdef HAVE_SETUTENT

    utmpname(UTMP_FILE);
    setutent();
    pututline(&ent);
    endutent();

#if 0
    /* XXX -- NOT NEEDED ANYMORE */

    if (ent.ut_type == DEAD_PROCESS) {
	if ((fd = open(UTMP_FILE, O_RDWR)) >= 0) {
	    int cnt = 0;
	    while(read(fd, (char *)&ut, sizeof(ut)) == sizeof(ut)) {
		if (!strncmp(ut.ut_id, ent.ut_id, sizeof(ut.ut_id))) {
		    (void) memset(ut.ut_host, 0, sizeof(ut.ut_host));
		    (void) memset(ut.ut_user, 0, sizeof(ut.ut_user));
		    (void) time(&ut.ut_time);
		    ut.ut_exit.e_exit = ut.ut_pid = 0;
		    ut.ut_type = EMPTY;
		    (void) lseek(fd, -sizeof(ut), SEEK_CUR);
		    (void) write(fd, &ut, sizeof(ut));
		}
		cnt++;
	    }
	    close(fd);
	}
    }
#endif
    
#ifdef HAVE_SETUTXENT
    setutxent();
    getutmpx(&ent, &utx);
    pututxline(&utx);
    endutxent();
#endif /* HAVE_SETUTXENT */

#else /* HAVE_SETUTENT */
	
    tty = ttyslot();
    if (tty > 0 && (fd = open(UTMP_FILE, O_WRONLY, 0)) >= 0) {
	(void)lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET);
	(void)write(fd, (char *)ent, sizeof(struct utmp));
	(void)close(fd);
    }

#endif /* HAVE_SETUTENT */

    return ptyint_update_wtmp(&ent);
}
