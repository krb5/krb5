/* qbuf2pe.c - read a PE from a SSDU */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:28  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:34  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:14  isode
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
#undef	qbuf2pe
#include "tailor.h"

/*  */

#ifndef	DEBUG
/* ARGSUSED */
#endif

PE	qbuf2pe (qb, len, result)
register struct qbuf *qb;
int	len;
int    *result;
{
#ifdef	notdef
    register struct qbuf *qp;
#endif
    register PE	    pe;
    register PS	    ps;

#ifdef	notdef		/* "inline" nonsense too difficult to handle */
    if ((qp = qb -> qb_forw) != qb && qp -> qb_forw == qb) {
	remque (qp);

	return ssdu2pe (qp -> qb_data, qp -> qb_len, (char *) qp, result);
    }
#endif

    if ((ps = ps_alloc (qbuf_open)) == NULLPS) {
	*result = PS_ERR_NMEM;
	return NULLPE;
    }
    if (qbuf_setup (ps, qb) == NOTOK || (pe = ps2pe (ps)) == NULLPE) {
	if (ps -> ps_errno == PS_ERR_NONE)
	    ps -> ps_errno = PS_ERR_EOF;
	*result = ps -> ps_errno;
	ps_free (ps);
	return NULLPE;
    }

    *result = PS_ERR_NONE;
    ps_free (ps);

#ifdef	DEBUG
    if (psap_log -> ll_events & LLOG_PDUS)
	pe2text (psap_log, pe, 1, len);
#endif

    return pe;
}
