/* baduser.c - check file of bad users */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:26:56  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:15:23  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:33:29  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:17:49  isode
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

int	baduser (file, user)
char   *file,
       *user;
{
    int     hit,
	    tries;
    register char  *bp;
    char    buffer[BUFSIZ];
    FILE   *fp;

    hit = 0;
    for (tries = 0; tries < 2 && !hit; tries++) {
	switch (tries) {
	    case 0:
	        if (file) {
		    bp = isodefile (file, 0);
		    break;
		}
		tries++;
		/* and fall */
	    default:
		bp = "/etc/ftpusers";
		break;
	}
	if ((fp = fopen (bp, "r")) == NULL)
	    continue;

	while (fgets (buffer, sizeof buffer, fp)) {
	    if (bp = index (buffer, '\n'))
		*bp = NULL;
	    if (strcmp (buffer, user) == 0) {
		hit++;
		break;
	    }
	}

	(void) fclose (fp);
    }


    return hit;
}
