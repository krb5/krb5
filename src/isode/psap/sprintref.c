/* sprintref.c - manage encoded session addresses */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:54  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:54  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:22  isode
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
#include "ssap.h"

/*  */

char   *sprintref (sr)
struct SSAPref *sr;
{
    register char  *cp;
    static char buffer[BUFSIZ];

    cp = buffer;
    *cp++ = '<';

    if (sr -> sr_ulen) {
	if (sr -> sr_ulen > 1 && *(sr -> sr_udata + 1) + 2 == sr -> sr_ulen)
	    (void) sprintf (cp, "%*.*s", sr -> sr_ulen - 2, sr -> sr_ulen - 2,
		    sr -> sr_udata + 2);
	else
	    (void) sprintf (cp, "%*.*s", sr -> sr_ulen, sr -> sr_ulen,
		    sr -> sr_udata);
	cp += strlen (cp);
    }
    *cp++ = ',';

    if (sr -> sr_clen) {
	if (sr -> sr_clen > 1 && *(sr -> sr_cdata + 1) + 2 == sr -> sr_clen)
	    (void) sprintf (cp, "%*.*s", sr -> sr_clen - 2, sr -> sr_clen - 2,
		    sr -> sr_cdata + 2);
	else
	    (void) sprintf (cp, "%*.*s", sr -> sr_clen, sr -> sr_clen,
		    sr -> sr_cdata);
	cp += strlen (cp);
    }
    *cp++ = ',';

    if (sr -> sr_alen) {
	if (sr -> sr_alen > 1 && *(sr -> sr_adata + 1) + 2 == sr -> sr_alen)
	    (void) sprintf (cp, "%*.*s", sr -> sr_alen - 2, sr -> sr_alen - 2,
		    sr -> sr_adata + 2);
	else
	    (void) sprintf (cp, "%*.*s", sr -> sr_alen, sr -> sr_alen,
		    sr -> sr_adata);
	cp += strlen (cp);
    }
    *cp++ = ',';

    if (sr -> sr_vlen) {
	if (sr -> sr_vlen > 1 && *(sr -> sr_vdata + 1) + 2 == sr -> sr_vlen)
	    (void) sprintf (cp, "%*.*s", sr -> sr_vlen - 2, sr -> sr_vlen - 2,
		    sr -> sr_vdata + 2);
	else
	    (void) sprintf (cp, "%*.*s", sr -> sr_vlen, sr -> sr_vlen,
		    sr -> sr_vdata);
	cp += strlen (cp);
    }
    *cp++ = '>';

    *cp = NULL;

    return buffer;
}
