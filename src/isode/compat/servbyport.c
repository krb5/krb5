/* servbyport.c - getisoserventbyport */

/* 
 * isode/compat/servbyport.c
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
