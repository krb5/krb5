/* oid2ode.c - object identifier to object descriptor  */

/* 
 * isode/psap/oid2ode.c
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

char   *oid2ode_aux (identifier, quoted)
OID	identifier;
int	quoted;
{
    int	    events;
    register struct isobject *io;
    static char buffer[BUFSIZ];
    
    events = addr_log -> ll_events;
    addr_log -> ll_events = LLOG_FATAL;

    io = getisobjectbyoid (identifier);

    addr_log -> ll_events = events;

    if (io) {
	(void) sprintf (buffer, quoted ? "\"%s\"" : "%s",
			io -> io_descriptor);
	return buffer;
    }

    return sprintoid (identifier);
}
