/* strdup.c - create a duplicate copy of the given string */

#ifndef lint
static char *rcsid = "$Header$";
#endif

/*
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:28:37  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:17:00  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:57  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:19  isode
 * Release 7.0
 * 
 * 
 */

/*
 *                                NOTICE
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
#include "tailor.h"

/*  */
#if (!defined(SVR4) && !defined(linux))

char   *strdup (str)
register char   *str;
{
	register char *ptr;

	if ((ptr = malloc((unsigned) (strlen (str) + 1))) == NULL){
	    LLOG (compat_log,LLOG_FATAL, ("strdup malloc() failure"));
	    abort ();
	    /* NOTREACHED */
	}

	(void) strcpy (ptr, str);

	return ptr;
}

#else

strdup_stub ()
{;}

#endif
