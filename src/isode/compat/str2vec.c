/* str2vec.c - string to vector */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:28:35  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:58  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:56  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:19  isode
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


#define	QUOTE	'\\'

/*  */

int	str2vecX (s, vec, nmask, mask, brk, docomma)
register char  *s,
	      **vec,
    	        brk;
int	nmask,
       *mask,
	docomma;
{
    register int    i;
    char    comma = docomma ? ',' : ' ';

    if (mask)
	*mask = 0;

    for (i = 0; i <= NVEC;) {
	vec[i] = NULL;
	if (brk > 0) {
	    if (i > 0 && *s == brk)
		*s++ = NULL;
	}
	else
	    while (isspace ((u_char) *s) || *s == comma)
		*s++ = NULL;
	if (*s == NULL)
	    break;

	if (*s == '"') {
	    if (i < nmask)
		*mask |= 1 << i;
	    for (vec[i++] = ++s; *s != NULL && *s != '"'; s++)
		if (*s == QUOTE) {
		    if (*++s == '"')
			(void) strcpy (s - 1, s);
		    s--;
		}
	    if (*s == '"')
		*s++ = NULL;
	    continue;
	}
	if (*s == QUOTE && *++s != '"')
	    s--;
	vec[i++] = s;

	if (brk > 0) {
	    if (*s != brk)
		for (s++; *s != NULL && *s != brk; s++)
		    continue;
	}
	else
	    for (s++; *s != NULL && !isspace ((u_char) *s) && *s != comma; s++)
		continue;
    }
    vec[i] = NULL;

    return i;
}
