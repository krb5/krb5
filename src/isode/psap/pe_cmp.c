/* pe_cmp.c - compare two presentation elements */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:22  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:42  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:57  isode
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

int	pe_cmp (p, q)
register PE	p,
		q;
{
    register int    i;

    if (p == NULLPE)
	return (q ? 1 : 0);
    if (q == NULLPE
	    || p -> pe_class != q -> pe_class
	    || p -> pe_form != q -> pe_form
	    || p -> pe_id != q -> pe_id)
	return 1;

/* XXX: perhaps compare pe_context ??? */

    switch (p -> pe_form) {
	case PE_FORM_ICONS:
	    if (p -> pe_ilen != q -> pe_ilen)
		return 1;
	    /* else fall */
	case PE_FORM_PRIM: 
	    if (i = p -> pe_len) {
		if (i != q -> pe_len || PEDcmp (p -> pe_prim, q -> pe_prim, i))
		    return 1;
	    }
	    else
		if (q -> pe_len)
		    return 1;
	    return 0;

	case PE_FORM_CONS: 
	    for (p = p -> pe_cons, q = q -> pe_cons;
		    p;
		    p = p -> pe_next, q = q -> pe_next)
		if (pe_cmp (p, q))
		    return 1;
	    return (q ? 1 : 0);

	default:		/* XXX */
	    return 1;
    }
}
