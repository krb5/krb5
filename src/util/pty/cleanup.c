/*
 * pty_cleanup: Kill processes associated with pty.
 * and utmp entries.
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * 
 *Permission to use, copy, modify, and
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
 */

#include "mit-copyright.h"
#include <com_err.h>
#include "libpty.h"
#include "pty-int.h"

long pty_cleanup (slave, pid, update_utmp)
    char *slave;
    pid_t pid; /* May be zero for unknown.*/
    int update_utmp;
{
    struct utmp ut;
    int retval, fd;
    
#ifndef NO_UT_PID
    ut.ut_pid = 0;
    ut.ut_type = DEAD_PROCESS;
#endif
    pty_update_utmp(&ut, "", slave, (char *)0);
    
    (void)chmod(slave, 0666);
    (void)chown(slave, 0, 0);
#ifndef HAVE_STREAMS
    slave[strlen("/dev/")] = 'p';
    (void)chmod(slave, 0666);
    (void)chown(slave, 0, 0);
#endif
#ifdef HAVE_REVOKE
    revoke(slave);
    /*
     * Revoke isn't guaranteed to send a SIGHUP to the processes it
     * dissociates from the terminal.  The best solution without a Posix
     * mechanism for forcing a hangup is to killpg() the process
     * group of the pty.  This will at least kill the shell and
     * hopefully, the child processes.  This is not always the case, however.
     * If the shell puts each job in a process group and doesn't pass
     * along SIGHUP, all processes may not die.
     */
    if ( pid > 0 ) {
#ifdef HAVE_KILLPG
	killpg(pid, SIGHUP);
#else
	kill( -(pid), SIGHUP );
#endif /*HAVE_KILLPG*/
    }
#else /* HAVE_REVOKE*/
#ifdef VHANG_LAST
    if ( retval = ( pty_open_ctty( slave, &fd ))) 
	return retval;
    ptyint_vhangup();
    return 0;
#endif
#endif
}
