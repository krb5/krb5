/*
 * ptyint_void_association(): Void association with controlling terminal
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

long ptyint_void_association()
{
            int con_fd;
#ifdef HAVE_SETSID
    (void) setsid();
#endif

        /* Void tty association first */
        if ((con_fd = open("/dev/tty", O_RDWR)) >= 0) {
          ioctl(con_fd, TIOCNOTTY, 0);
          close(con_fd);
	}
	    return 0;
}
