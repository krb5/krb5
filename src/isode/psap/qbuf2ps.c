/* qbuf2ps.c - qbuf-backed abstractions for PStreams */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:32  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:37  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:15  isode
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

/* ARGSUSED */

static int  qbuf_read (ps, data, n, in_line)
register PS	ps;
PElementData data;
PElementLen n;
int	in_line;
{
    register int cc,
		 i;
    register struct qbuf *qb,
			 *qp;

    if ((qb = (struct qbuf *) ps -> ps_addr) == NULL)
	return 0;

    for (qp = NULL, cc = 0; n > 0; data += i, cc += i, n -= i) {
	if (qp == NULL && (qp = qb -> qb_forw) == qb)
	    return cc;

	i = min (qp -> qb_len, n);
	bcopy (qp -> qb_data, (char *) data, i);

	qp -> qb_data += i, qp -> qb_len -= i;
	if (qp -> qb_len <= 0) {
	    remque (qp);

	    free ((char *) qp);
	    qp = NULL;
	}
    }

    return cc;
}


static int  qbuf_close (ps)
register PS	ps;
{
    register struct qbuf   *qb;

    if ((qb = (struct qbuf *) ps -> ps_addr) == NULL)
	return;

    QBFREE (qb);
}

/*  */

int	qbuf_open (ps)
register PS	ps;
{
    ps -> ps_readP = qbuf_read;
    ps -> ps_closeP = qbuf_close;

    return OK;
}
