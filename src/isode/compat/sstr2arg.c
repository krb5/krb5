/* sstr2arg: convert string into argument list */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:28:26  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:48  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:47  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:13  isode
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
#include "manifest.h"
#include "general.h"
#include <errno.h>
extern int errno;

/*  */

/*
   stash a pointer to each field into the passed array. any common seperators
   split the words.  extra white-space between fields is ignored.

   specially-interpreted characters:
	double-quote, backslash (preceding a special char with a backslash
	removes its interpretation.  A backslash not followed by a special is
	used to preface an octal specification for one character a string begun
	with double-quote has only double-quote and backslash as special
	characters.

*/




sstr2arg (srcptr, maxpf, argv, dlmstr)
register char *srcptr;  /* source data */
int maxpf;              /* maximum number of permitted fields */
char *argv[];           /* where to put the pointers */
char *dlmstr;           /* Delimiting character */
{
    char gotquote;		/* currently parsing quoted string */
    register int ind;
    register char *destptr;
    char idex[256];

    if (srcptr == 0)
	return (NOTOK);

    bzero (idex, sizeof idex);
    for (destptr = dlmstr; *destptr; destptr++)
	idex[*destptr] = 1;

    for (ind = 0, maxpf -= 2;; ind++) {
	if (ind >= maxpf) 
	    return (NOTOK);

	/* Skip leading white space */
	for (; *srcptr == ' ' || *srcptr == '\t'; srcptr++);

	argv [ind] = srcptr;
	destptr = srcptr;

	for (gotquote = 0; ; ) {

	    if (idex[*srcptr])
	    {
		if (gotquote) {	/* don't interpret the char */
		    *destptr++ = *srcptr++;
		    continue;
		}

		srcptr++;
		*destptr = '\0';
		goto nextarg;
	    } else {
		switch (*srcptr) {
		default:	/* just copy it                     */
		    *destptr++ = *srcptr++;
		    break;

		case '\"':	/* beginning or end of string       */
		    gotquote = (gotquote) ? 0 : 1 ;
		    srcptr++;	/* just toggle */
		    break;

		case '\\':	/* quote next character     */
		    srcptr++;	/* skip the back-slash      */
		    switch (*srcptr) {
			/* Octal character	    */
		    case '0': case '1':
		    case '2': case '3': 
		    case '4': case '5':
		    case '6': case '7': 
			*destptr = '\0';
			do
			    *destptr = (*destptr << 3) | (*srcptr++ - '0');
			while (*srcptr >= '0' && *srcptr <= '7');
			destptr++;
			break;
			/* C escape char	    */
		    case 'b':
			*destptr++ = '\b';
			srcptr++;
			break;
		    case 'n':
			*destptr++ = '\n';
			srcptr++;
			break;
		    case 'r':
			*destptr++ = '\r';
			srcptr++;
			break;
		    case 't':
			*destptr++ = '\t';
			srcptr++;
			break;
						
			/* Boring -- just copy ASIS */
		    default:
			*destptr++ = *srcptr++;
		    }
		    break;

		case '\0':
		    *destptr = '\0';
		    ind++;
		    argv[ind] = (char *) 0;
		    return (ind);
		}
	    }
	}
    nextarg:
	continue;
    }
}
