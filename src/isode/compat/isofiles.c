/* isofiles.c - ISODE files */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:27:28  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:15:56  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:33:57  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:17:58  isode
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
#include "general.h"
#include "manifest.h"
#include "tailor.h"

/*  */

char   *_isodefile (path, file)
char   *path,
       *file;
{
    static char buffer[BUFSIZ];

    isodetailor (NULLCP, 0);	/* not really recursive */

    if (*file == '/'
	    || (*file == '.'
		    && (file[1] == '/'
			    || (file[1] == '.' && file[2] == '/'))))
	(void) strcpy (buffer, file);
    else
	(void) sprintf (buffer, "%s%s", path, file);

    return buffer;
}
