/* smalloc.c - error checking malloc */

#ifndef lint
static char *rcsid = "$Header$";
#endif

/*
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:28:16  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:44  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:44  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:12  isode
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

char *
smalloc(size)
int	size;
{
	register char *ptr;

	if ((ptr = malloc((unsigned) size)) == NULL){
	    LLOG (compat_log,LLOG_FATAL, ("malloc() failure"));
	    abort ();
	    /* NOTREACHED */
	}

	return(ptr);
}
