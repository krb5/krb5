/*
 * pty_open_slave: open slave side of terminal, clearing for use.
 *
 * Copyright 1995, 1996, 2001 by the Massachusetts Institute of
 * Technology.
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

long
pty_open_slave(const char *slave, int *fd)
{
    int tmpfd;
    long retval;

    /* Sanity check. */
    if (slave == NULL || *slave == '\0')
	return PTY_OPEN_SLAVE_TOOSHORT;

    /* First, set up a new session and void old associations. */
    ptyint_void_association();

    /*
     * Make a first attempt at acquiring the ctty under certain
     * condisions.  This is necessary for several reasons:
     *
     * Under Irix, if you open a pty slave and then close it, a
     * subsequent open of the slave will cause the master to read EOF.
     * To prevent this, don't close the first fd until we do the real
     * open following vhangup().
     *
     * Under Tru64 v5.0, if there isn't a fd open on the slave,
     * revoke() fails with ENOTTY, curiously enough.
     *
     * Anyway, sshd seems to make a practice of doing this.
     */
#if defined(VHANG_FIRST) || defined(REVOKE_NEEDS_OPEN)
    retval = pty_open_ctty(slave, fd);
    if (retval)
	return retval;
    if (*fd < 0)
	return PTY_OPEN_SLAVE_OPENFAIL;
#endif

    /* chmod and chown the slave. */
    if (chmod(slave, 0))
	return PTY_OPEN_SLAVE_CHMODFAIL;
    if (chown(slave, 0, 0) == -1)
	return PTY_OPEN_SLAVE_CHOWNFAIL;

#ifdef HAVE_REVOKE
    if (revoke(slave) < 0) {
	return PTY_OPEN_SLAVE_REVOKEFAIL;
    }
#else /* !HAVE_REVOKE */
#ifdef VHANG_FIRST
    ptyint_vhangup();
#endif
#endif /* !HAVE_REVOKE */

    /* Open the pty for real. */
    retval = pty_open_ctty(slave, &tmpfd);
#if defined(VHANG_FIRST) || defined(REVOKE_NEEDS_OPEN)
    close(*fd);
#endif
    if (retval) {
	*fd = -1;
	return PTY_OPEN_SLAVE_OPENFAIL;
    }
    *fd = tmpfd;
    retval = pty_initialize_slave(*fd);
    if (retval)
	return retval;
    /* Make sure it's really our ctty. */
    tmpfd = open("/dev/tty", O_RDWR|O_NDELAY);
    if (tmpfd < 0) {
	close(*fd);
	*fd = -1;
	return PTY_OPEN_SLAVE_NOCTTY;
    }
    close(tmpfd);
    return 0;
}
