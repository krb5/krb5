/* str2vec.c - string to vector */

/* 
 * isode/compat/str2vec.c
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
