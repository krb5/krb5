/* objectbyname.c - getisobjectbyoid */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:32:54  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:21  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:50  isode
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
#include "psap.h"
#include "tailor.h"

/*  */

struct isobject *getisobjectbyoid (oid)
register OID	oid;
{
    register struct isobject   *io;

    isodetailor (NULLCP, 0);
#ifdef	DEBUG
    SLOG (addr_log, LLOG_TRACE, NULLCP,
	  ("getisobjectbyoid %s", sprintoid (oid)));
#endif

    (void) setisobject (0);
    while (io = getisobject ())
	if (oid_cmp (oid, &io -> io_identity) == 0)
	    break;
    (void) endisobject ();

    if (io) {
#ifdef	DEBUG
	SLOG (addr_log, LLOG_DEBUG, NULLCP,
	      ("\tODE: \"%s\"\tOID: %s",
		    io -> io_descriptor, sprintoid (&io -> io_identity)));
#endif
    }
    else
	SLOG (addr_log, LLOG_EXCEPTIONS, NULLCP,
	      ("lookup of object %s failed", sprintoid (oid)));

    return io;
}
