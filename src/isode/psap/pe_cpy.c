/* pe_cpy.c - copy a presentation element */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:24  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:43  eichin
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

PE	pe_cpy (pe)
register PE	pe;
{
    register PE	    p,
		   *q,
		    r;

    if ((p = pe_alloc (pe -> pe_class, pe -> pe_form, pe -> pe_id)) == NULLPE)
	return NULLPE;

    p -> pe_context = pe -> pe_context;

    p -> pe_len = pe -> pe_len;
    switch (p -> pe_form) {
	case PE_FORM_ICONS:
	    p -> pe_ilen = pe -> pe_ilen;
	    /* and fall */
	case PE_FORM_PRIM: 
	    if (pe -> pe_prim == NULLPED)
		break;
	    if ((p -> pe_prim = PEDalloc (p -> pe_len)) == NULLPED)
		goto you_lose;
	    PEDcpy (pe -> pe_prim, p -> pe_prim, p -> pe_len);
	    break;

	case PE_FORM_CONS: 
	    for (q = &p -> pe_cons, r = pe -> pe_cons;
		    r;
		    q = &((*q) -> pe_next), r = r -> pe_next)
		if ((*q = pe_cpy (r)) == NULLPE)
		    goto you_lose;
	    break;
    }

    p -> pe_nbits = pe -> pe_nbits;

    return p;

you_lose: ;
    pe_free (p);
    return NULLPE;
}
