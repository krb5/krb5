/*
 * pty_open_slave: open slave side of terminal, clearing for use.
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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

long pty_initialize_slave (fd)
    int fd;
{
#if defined(POSIX_TERMIOS) && !defined(ultrix)
    struct termios new_termio;
#else
    struct sgttyb b;
#endif /* POSIX_TERMIOS */
    int pid;
#ifdef POSIX_SIGNALS
    struct sigaction sa;
    /* Initialize "sa" structure. */
    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
#endif
	    
#ifdef HAVE_STREAMS
#ifdef HAVE_LINE_PUSH
        while (ioctl (fd, I_POP, 0) == 0); /*Clear out any old lined's*/

    if (line_push(fd) < 0)
	{
	    (void) close(fd); fd = -1;
	    return PTY_OPEN_SLAVE_LINE_PUSHFAIL;
	}
#else /*No line_push */
#if 0 /* used to be SUN*/
    if (ioctl(fd, I_PUSH, "ptem") < 0)
	return PTY_OPEN_SLAVE_PUSH_FAIL;
    if (ioctl(fd, I_PUSH, "ldterm") < 0)
	return PTY_OPEN_SLAVE_PUSH_FAIL;
    if (ioctl(fd, I_PUSH, "ttcompat") < 0)
	return PTY_OPEN_SLAVE_PUSH_FAIL;

#endif /*SUN*/
#endif /*LINE_PUSH*/
#endif /*HAVE_STREAMS*/

    /*
	 * Under Ultrix 3.0, the pgrp of the slave pty terminal
	 * needs to be set explicitly.  Why rlogind works at all
	 * without this on 4.3BSD is a mystery.
	 */
#ifdef GETPGRP_ONEARG
    pid = getpgrp(getpid());
#else
    pid = getpgrp();
#endif

#ifdef TIOCSPGRP
    ioctl(fd, TIOCSPGRP, &pid);
#endif

    
#if defined(POSIX_TERMIOS) && !defined(ultrix)
	tcsetpgrp(fd, pid);
	tcgetattr(fd,&new_termio);
	new_termio.c_cc[VMIN] = 1;
	new_termio.c_cc[VTIME] = 0;
    tcsetattr(fd,TCSANOW,&new_termio);
#endif /* POSIX_TERMIOS */

    return 0;
}
