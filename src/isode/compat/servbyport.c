/* servbyport.c - getisoserventbyport */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:28:11  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:39  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:38  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:11  isode
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
#include "isoservent.h"
#include "tailor.h"
#include "internet.h"

/*  */

struct isoservent *getisoserventbyport (provider, port)
char   *provider;
unsigned short port;
{
    register struct isoservent *is;

    isodetailor (NULLCP, 0);
    DLOG (addr_log, LLOG_TRACE,
	   ("getisoserventbyport \"%s\" %d", provider, (int) ntohs (port)));

    (void) setisoservent (0);
    while (is = getisoservent ())
	if (sizeof (port) == is -> is_selectlen
		&& port == is -> is_port
		&& strcmp (provider, is -> is_provider) == 0)
	    break;
    (void) endisoservent ();

    if (is) {
#ifdef	DEBUG
	if (addr_log -> ll_events & LLOG_DEBUG)
	    _printsrv (is);
#endif
    }
    else
	SLOG (addr_log, LLOG_EXCEPTIONS, NULLCP,
	      ("lookup of local service %s/%d failed",
	       provider, (int) ntohs (port)));

    return is;
}
