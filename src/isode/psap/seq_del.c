/* seq_del.c - delete a member from a sequence */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:40  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:43  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:17  isode
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

int	seq_del (pe, i)
register PE	pe;
register int	i;
{
    int	    offset;
    register PE	   *p,
		    q;

    for (p = &pe -> pe_cons, offset = 0;
	    q = *p;
	    p = &q -> pe_next, offset = q -> pe_offset)
	if (q -> pe_offset == i) {
	    if (((*p) = q -> pe_next) == NULLPE)
		pe -> pe_cardinal = offset + 1;
	    pe_free (q);
	    return OK;
	}
	else
	    if (q -> pe_offset > i)
		break;
	
    return pe_seterr (pe, PE_ERR_MBER, NOTOK);
}
