/* str2elem.c - string to list of integers */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:28:27  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:50  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:49  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:14  isode
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

#include <ctype.h>
#include <stdio.h>
#include "general.h"
#include "manifest.h"

/*  */

int	str2elem (s, elements)
char   *s;
unsigned int elements[];
{
    register int    i;
    register unsigned int  *ip;
    register char  *cp,
                   *dp;

    ip = elements, i = 0;
    for (cp = s; *cp && i <= NELEM; cp = ++dp) {
	for (dp = cp; isdigit ((u_char) *dp); dp++)
	    continue;
	if ((cp == dp) || (*dp && *dp != '.'))
	    break;
	*ip++ = (unsigned int) atoi (cp), i++;
	if (*dp == NULL)
	    break;
    }
    if (*dp || i >= NELEM)
	return NOTOK;
    *ip = 0;

    return i;
}
