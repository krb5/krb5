/* qb2str.c - qbuf to string */

/* 
 * isode/psap/qb2str.c
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
