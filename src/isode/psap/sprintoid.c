/* sprintoid.c - object identifier to string */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:51  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:53  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:21  isode
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

/*  */

char   *sprintoid (oid)
register OID oid;
{
    register int    i;
    register unsigned int  *ip;
    register char  *bp,
		   *cp;
    static char buffer[BUFSIZ];

    if (oid == NULLOID || oid -> oid_nelem < 1)
	return "";

    bp = buffer;

    for (ip = oid -> oid_elements, i = oid -> oid_nelem, cp = "";
	    i-- > 0;
	    ip++, cp = ".") {
	(void) sprintf (bp, "%s%u", cp, *ip);
	bp += strlen (bp);
    }

    return buffer;
}
