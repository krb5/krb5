/*
 * pty_init_slave: open slave side of terminal, clearing for use.
 *
 * Copyright 1995, 1996 by the Massachusetts Institute of Technology.
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

/* * The following is an array of modules that should be pushed on the
 *  stream.  See configure.in for caviats and notes about when this
 *  array is used and not used.
 */
#if defined(HAVE_STREAMS)&&(!defined(HAVE_LINE_PUSH))
static char *push_list[] = {
#ifdef PUSH_PTEM
  "ptem",
#endif
#ifdef PUSH_LDTERM
  "ldterm",
#endif
#ifdef PUSH_TTCOMPAT
"ttcompat",
#endif
  0};
#endif /*HAVE_STREAMS but not HAVE_LINE_PUSH*/

 

long pty_initialize_slave (fd)
    int fd;
{
#if defined(POSIX_TERMIOS) && !defined(ultrix)
    struct termios new_termio;
#else
    struct sgttyb b;
#endif /* POSIX_TERMIOS */
    int pid;
	    
#ifdef HAVE_STREAMS
#ifdef HAVE_LINE_PUSH
        while (ioctl (fd, I_POP, 0) == 0); /*Clear out any old lined's*/

    if (line_push(fd) < 0)
	{
	    (void) close(fd); fd = -1;
	    return PTY_OPEN_SLAVE_LINE_PUSHFAIL;
	}
#else /*No line_push */
    {
       char **module = &push_list[0];
      while (*module)
		if (ioctl(fd, I_PUSH, *(module++)) < 0)
		  	return PTY_OPEN_SLAVE_PUSH_FAIL;
    }

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
