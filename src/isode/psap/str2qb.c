/* str2qb.c - string to qbuf */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:35:09  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:39:05  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:25  isode
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

struct qbuf *str2qb (s, len, head)
char   *s;
int	len,
	head;
{
    register struct qbuf *qb,
			 *pb;

    if ((pb = (struct qbuf *) malloc ((unsigned) (sizeof *pb + len))) == NULL)
	return NULL;

    if (head) {
	if ((qb = (struct qbuf *) malloc (sizeof *qb)) == NULL) {
	    free ((char *) pb);
	    return NULL;
	}
	qb -> qb_forw = qb -> qb_back = qb;
	qb -> qb_data = NULL, qb -> qb_len = len;
	insque (pb, qb);
    }
    else {
	pb -> qb_forw = pb -> qb_back = pb;
	qb = pb;
    }

    pb -> qb_data = pb -> qb_base;
    if ((pb -> qb_len = len) > 0 && s)
	bcopy (s, pb -> qb_data, len);

    return qb;
}
