/*
 * ptyint_void_association(): Void association with controlling terminal
 *
 * Copyright 1995, 1996 by the Massachusetts Institute of Technology.
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
/* 
 * This routine will be called twice.  It's not particularly important
 * that the setsid() or TIOCSTTY ioctls succeed (they may not the
 * second time), but rather that we have a controlling terminal at the
 * end.  It is assumed that vhangup doesn't exist and confuse the
 * process's notion of controlling terminal on any system without
 * TIOCNOTTY.  That is, either vhangup() leaves the controlling
 * terminal in tact, breaks the association completely, or the system
 * provides TIOCNOTTY to get things back into a reasonable state.  In
 * practice, vhangup() either breaks the association completely or
 * doesn't effect controlling terminals, so this condition is met.
 */

long ptyint_void_association()
{
            int con_fd;
#ifdef HAVE_SETSID
    (void) setsid();
#endif

        /* Void tty association first */
#ifdef TIOCNOTTY
        if ((con_fd = open("/dev/tty", O_RDWR)) >= 0) {
          ioctl(con_fd, TIOCNOTTY, 0);
          close(con_fd);
	}
#endif
	    return 0;
}
