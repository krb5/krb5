/* qb_pullup.c - "pullup" a list of qbufs */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.2  1994/06/15 23:24:36  eichin
 * step 3: bcopy->memcpy or memmove (chose by hand), twiddle args
 *
 * Revision 1.1  1994/06/10 03:34:26  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:32  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:13  isode
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

/*  */

int	qb_pullup (qb)
register struct qbuf *qb;
{
    register int    len;
    register char  *d;
    register struct qbuf  *p,
			  *qp,
    			  *qpp;

    len = 0;
#ifdef	notdef		/* want null-termination... */
    if ((p = qb -> qb_forw) -> qb_forw == qb)
	return OK;
#endif
    for (p = qb -> qb_forw; p != qb; p = p -> qb_forw)
	len += p -> qb_len;

    if ((p = (struct qbuf *) malloc ((unsigned) (sizeof *p + len + 1)))
	    == NULL)
	return NOTOK;
    d = p -> qb_data = p -> qb_base;
    p -> qb_len = len;

    for (qp = qb -> qb_forw; qp != qb; qp = qpp) {
	qpp = qp -> qb_forw;

	remque (qp);

	memcpy (d, qp -> qb_data, qp -> qb_len);
	d += qp -> qb_len;

	free ((char *) qp);
    }
    *d = NULL;

    insque (p, qb);

    return OK;
}
