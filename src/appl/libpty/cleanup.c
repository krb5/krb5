/*
 * pty_cleanup: Kill processes associated with pty.
 *
 * (C)Copyright 1995, 1996 by the Massachusetts Institute of Technology.
 *
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
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

long pty_cleanup (char *slave,
		  /* May be zero for unknown.  */
		  int pid,
		  int update_utmp)
{
#ifdef VHANG_LAST
    int retval, fd;
#endif
    
    if (update_utmp)
	pty_update_utmp(PTY_DEAD_PROCESS, pid,  "", slave, (char *)0, PTY_UTMP_USERNAME_VALID);
    
    (void)chmod(slave, 0666);
    (void)chown(slave, 0, 0);
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
    {
      int status;
#ifdef POSIX_SIGNALS
      sigset_t old, new;
      sigemptyset(&new);
      sigaddset(&new, SIGCHLD);
      sigprocmask ( SIG_BLOCK, &new, &old);
#else /*POSIX_SIGNALS*/
      int mask = sigblock(sigmask(SIGCHLD));
#endif /*POSIX_SIGNALS*/
      switch (retval = fork()) {
      case -1:
#ifdef POSIX_SIGNALS
	sigprocmask(SIG_SETMASK, &old, 0);
#else /*POSIX_SIGNALS*/
	sigsetmask(mask);
#endif /*POSIX_SIGNALS*/
	return errno;
      case 0:
	ptyint_void_association();
	if ((retval = pty_open_ctty(slave, &fd)))
	  exit(retval);
	ptyint_vhangup();
	exit(0);
	break;
      default:
#ifdef HAVE_WAITPID
	waitpid(retval, &status, 0);
#else /*HAVE_WAITPID*/
	wait(&status);
#endif
#ifdef POSIX_SIGNALS
	sigprocmask(SIG_SETMASK, &old, 0);
#else /*POSIX_SIGNALS*/
	sigsetmask(mask);
#endif /*POSIX_SIGNALS*/

	break;
      }
    }
#endif /*VHANG_LAST*/
#endif /* HAVE_REVOKE*/
#ifndef HAVE_STREAMS
    slave[strlen("/dev/")] = 'p';
    (void)chmod(slave, 0666);
    (void)chown(slave, 0, 0);
#endif
    return 0;
}
