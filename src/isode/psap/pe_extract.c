/* pe_extract.c - extract a PE */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:30  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:48  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:59  isode
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

/* assumes that q appears at most once directly under p... */

int	pe_extract (pe, r)
PE	pe,
	r;
{
    register PE	   *p,
		    q;

    switch (pe -> pe_form) {
	case PE_FORM_PRIM: 
	case PE_FORM_ICONS: 
	    break;

	case PE_FORM_CONS: 
	    for (p = &pe -> pe_cons; q = *p; p = &q -> pe_next)
		if (q == r) {
		    (*p) = q -> pe_next;
		    q -> pe_next = NULLPE;
		    if (r->pe_refcnt > 0)
			    r->pe_refcnt--;
		    return 1;
		}
		else
		    if (pe_extract (q, r))
			return 1;
	    break;
    }

    return 0;
}
