/*
 * pty_open_slave: open slave side of terminal, clearing for use.
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

long pty_open_slave ( slave, fd)
    const char *slave;
    int *fd;
{
    int vfd;
long retval;
#ifdef POSIX_SIGNALS
    struct sigaction sa;
    /* Initialize "sa" structure. */
    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
#endif

    /* First, chmod and chown the slave*/
if (( retval = pty_open_ctty ( slave, &vfd )) != 0 )
    return retval;
	
        if (vfd < 0)
	return PTY_OPEN_SLAVE_OPENFAIL;

#ifndef HAVE_FCHMOD
        if (chmod(line, 0))
	    return PTY_OPEN_SLAVE_CHMODFAIL;
#else
        if (fchmod(vfd, 0))
return PTY_OPEN_SLAVE_CHMODFAIL;
#endif /*HAVE_FCHMOD*/
#ifdef HAVE_FCHOWN
    if ( fchown(vfd, 0, 0 ) == -1 ) 
	#else
	if ( chown(slave, 0, 0 ) == -1 ) 
#endif /* HAVE_FCHOWN*/
	    return PTY_OPEN_SLAVE_CHOWNFAIL;

	    #ifdef VHANG_FIRST
    ptyint_vhangup();
#endif

    (void) close(vfd);
    #ifdef HAVE_REVOKE
    if (revoke (slave) < 0 ) {
	return PTY_OPEN_SLAVE_REVOKEFAIL;
    }
#endif /*HAVE_REVOKE*/

/* Open the pty for real. */
    if  (( retval = pty_open_ctty ( slave, fd))  < 0 ) {
	return PTY_OPEN_SLAVE_OPENFAIL;
    }
    return pty_initialize_slave (*fd);
}
