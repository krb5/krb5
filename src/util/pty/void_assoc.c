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

/*
 * This function gets called to set up the current process as a
 * session leader (hence, can't be called except from a process that
 * isn't already a session leader) and dissociates the controlling
 * terminal (if any) from the session.
 */
long
ptyint_void_association(void)
{
    int fd;
#ifdef HAVE_SETSID
    (void) setsid();
#endif
    /* Void tty association first */
#ifdef TIOCNOTTY
    fd = open("/dev/tty", O_RDWR);
    if (fd >= 0) {
	ioctl(fd, TIOCNOTTY, 0);
	close(fd);
    }
#endif
    return 0;
}
