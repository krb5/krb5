/*
 * pty_open_ctty: Open and establish controlling terminal.
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

/* 
 * This function will be called twice.  The first time it will acquire
 * a controlling terminal from which to vhangup() or revoke() (see
 * comments in open_slave.c); the second time, it will be to open the
 * actual slave device for use by the application.  We no longer call
 * ptyint_void_association(), as that will be called in
 * pty_open_slave() to avoid spurious calls to setsid(), etc.
 *
 * It is assumed that systems where vhangup() exists and does break
 * the ctty association will allow the slave to be re-acquired as the
 * ctty.  Also, if revoke() or vhangup() doesn't break the ctty
 * association, we assume that we can successfully reopen the slave.
 *
 * This function doesn't check whether we actually acquired the ctty;
 * we assume that the caller will check that, or that it doesn't
 * matter in the particular case.
 */
long
pty_open_ctty(const char *slave, int *fd)
{

#ifdef ultrix
    /*
     * The Ultrix (and other BSD tty drivers) require the process
     * group to be zero, in order to acquire the new tty as a
     * controlling tty.  This may actually belong in
     * ptyint_void_association().
     */
    (void) setpgrp(0, 0);
#endif
    *fd = open(slave, O_RDWR);
    if (*fd < 0)
	return PTY_OPEN_SLAVE_OPENFAIL;
#ifdef ultrix
    setpgrp(0, getpid());
#endif

#ifdef TIOCSCTTY
    ioctl(*fd, TIOCSCTTY, 0); /* Don't check return.*/
#endif /* TIOCSTTY */
    return 0;
}
