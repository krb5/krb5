/*
 * pty_getpty: open a PTY master.
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
#include "k5-platform.h"

long
ptyint_getpty_ext(int *fd, char *slave, int slavelength, int do_grantpt)
{
#if !defined(HAVE__GETPTY) && !defined(HAVE_OPENPTY)
    char *cp;
    char *p;
    int i,ptynum;
    struct stat stb;
    char slavebuf[1024];
#endif

#ifdef HAVE__GETPTY
    char *slaveret; /*Temporary to hold pointer to slave*/
#endif /*HAVE__GETPTY*/

#ifdef HAVE_OPENPTY
    int slavefd;

    if(openpty(fd, &slavefd, slave, (struct termios *) 0,
         (struct winsize *) 0)) return 1;
    close(slavefd);
    return 0;
#else /*HAVE_OPENPTY*/
#ifdef HAVE__GETPTY
    /* This code is included for Irix; as of version 5.3, Irix has /dev/ptmx,
     * but it fails to work properly; even after calling unlockpt,
     * root gets permission denied opening the pty.
     * The code to support _getpty should be removed if Irix gets working
     * streams ptys in favor of maintaining the least needed code
     * paths.
     */
    if ((slaveret = _getpty(fd, O_RDWR|O_NDELAY, 0600, 0)) == 0) {
	*fd = -1;
	return PTY_GETPTY_NOPTY;
    }
    if (strlcpy(slave, slaveret, slavelength) >= slavelength) {
	close(*fd);
	*fd = -1;
	return PTY_GETPTY_SLAVE_TOOLONG;
    }
    return 0;
#else /*HAVE__GETPTY*/
    
    *fd = open("/dev/ptym/clone", O_RDWR|O_NDELAY);	/* HPUX*/
#ifdef HAVE_STREAMS
    if (*fd < 0) *fd = open("/dev/ptmx",O_RDWR|O_NDELAY); /*Solaris*/
#endif
    if (*fd < 0) *fd = open("/dev/ptc", O_RDWR|O_NDELAY); /* AIX */
    if (*fd < 0) *fd = open("/dev/pty", O_RDWR|O_NDELAY); /* sysvimp */

    if (*fd >= 0) {

#if defined(HAVE_GRANTPT)&&defined(HAVE_STREAMS)
	if (do_grantpt)
	    if (grantpt(*fd) || unlockpt(*fd)) return PTY_GETPTY_STREAMS;
#endif
    
#ifdef HAVE_PTSNAME
	p = ptsname(*fd);
#else
#ifdef	HAVE_TTYNAME
	p = ttyname(*fd);
#else
	/* XXX If we don't have either what do we do */
#endif
#endif
	if (p) {
	    if (strlcpy(slave, p, slavelength) >= slavelength) {
		    close (*fd);
		    *fd = -1;
		    return PTY_GETPTY_SLAVE_TOOLONG;
	    }
	    return 0;
	}

	if (fstat(*fd, &stb) < 0) {
	    close(*fd);
	    return PTY_GETPTY_FSTAT;
	}
	ptynum = (int)(stb.st_rdev&0xFF);
	snprintf(slavebuf, sizeof(slavebuf), "/dev/ttyp%x", ptynum);
	if (strlen(slavebuf) > slavelength - 1) {
	    close(*fd);
	    *fd = -1;
	    return PTY_GETPTY_SLAVE_TOOLONG;
	}
	strncpy(slave, slavebuf, slavelength);
	return 0;
    } else {
    	for (cp = "pqrstuvwxyzPQRST";*cp; cp++) {
	    snprintf(slavebuf,sizeof(slavebuf),"/dev/ptyXX");
	    slavebuf[sizeof("/dev/pty") - 1] = *cp;
	    slavebuf[sizeof("/dev/ptyp") - 1] = '0';
	    if (stat(slavebuf, &stb) < 0)
		break;
	    for (i = 0; i < 16; i++) {
		slavebuf[sizeof("/dev/ptyp") - 1] = "0123456789abcdef"[i];
		*fd = open(slavebuf, O_RDWR);
		if (*fd < 0) continue;

		/* got pty */
		slavebuf[sizeof("/dev/") - 1] = 't';
		if (strlen(slavebuf) > slavelength -1) {
		    close(*fd);
		    *fd = -1;
		    return PTY_GETPTY_SLAVE_TOOLONG;
		}
		strncpy(slave, slavebuf, slavelength);
		return 0;
	    }
	}
	return PTY_GETPTY_NOPTY;
    }
#endif /*HAVE__GETPTY*/
#endif /* HAVE_OPENPTY */
}

long
pty_getpty(int *fd, char *slave, int slavelength)
{
    return ptyint_getpty_ext(fd, slave, slavelength, 1);
}
