/* str2elem.c - string to list of integers */

/* 
 * isode/compat/str2elem.c
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
