/* qb2str.c - qbuf to string */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.2  1994/06/15 23:24:35  eichin
 * step 3: bcopy->memcpy or memmove (chose by hand), twiddle args
 *
 * Revision 1.1  1994/06/10 03:34:22  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:29  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:12  isode
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

char   *qb2str (q)
register struct qbuf *q;
{
    register int    len;
    register char  *b,
                   *d;
    register struct qbuf   *p;

    p = q -> qb_forw, len = 0;
    do {
	len += p -> qb_len;

	p = p -> qb_forw;
    }
    while (p != q);
    q -> qb_len = len;

    if ((b = d = malloc ((unsigned) (len + 1))) == NULL)
	return NULLCP;

    p = q -> qb_forw;
    do {
	memcpy (d, p -> qb_data, p -> qb_len);
	d += p -> qb_len;

	p = p -> qb_forw;
    }
    while (p != q);
    *d = NULL;

    return b;
}
