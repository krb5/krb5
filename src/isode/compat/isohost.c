/* isohost.c - getlocalhost */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:27:30  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:15:58  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:33:58  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:17:58  isode
 * Release 7.0
 * 
 * 
 */

/*
 *				  NOTICE
 *
 *    Acquisition, use, and distribution of this module and related
 *    materials are subject to the restrictions of a license agreement.
 *    Consult the Preface in the User's Manual for the full terms of
 *    this agreement.
 *
 */


/* LINTLIBRARY */

#include <stdio.h>
#include "general.h"
#include "manifest.h"
#ifdef	TCP
#include "internet.h"
#endif
#include "tailor.h"
#ifdef	SYS5
#include <sys/utsname.h>
#endif

/*  */

char   *getlocalhost () {
    register char   *cp;
#ifdef	TCP
    register struct hostent *hp;
#endif
#ifdef	SYS5
    struct utsname uts;
#endif
    static char buffer[BUFSIZ];

    if (buffer[0])
	return buffer;

    isodetailor (NULLCP, 0);
    if (*isodename)
	(void) strcpy (buffer, isodename);
    else {
#if	!defined(SOCKETS) && !defined(SYS5)
	(void) strcpy (buffer, "localhost");
#endif
#ifdef	SOCKETS
	(void) gethostname (buffer, sizeof buffer);
#endif
#ifdef	SYS5
	(void) uname (&uts);
	(void) strcpy (buffer, uts.nodename);
#endif

#ifdef	TCP
	if (hp = gethostbyname (buffer))
	    (void) strcpy (buffer, hp -> h_name);
	else
	    SLOG (addr_log, LLOG_EXCEPTIONS, NULLCP,
		  ("%s: unknown host", buffer));
#endif

	if (cp = index (buffer, '.'))
	    *cp = NULL;
    }

    return buffer;
}
