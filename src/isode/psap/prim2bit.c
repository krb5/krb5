/* prim2bit.c - presentation element to bit string */

/* 
 * isode/psap/prim2bit.c
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

PE	prim2bit (pe)
register PE	pe;
{
    int	    i;
    register PElementData bp;
    register PElementLen len;
    register PE	    p;

    switch (pe -> pe_form) {
	case PE_FORM_PRIM:	/* very paranoid... */
	    if ((bp = pe -> pe_prim) && (len = pe -> pe_len)) {
		if ((i = *bp & 0xff) > 7)
		    return pe_seterr (pe, PE_ERR_BITS, NULLPE);
		pe -> pe_nbits = ((len - 1) * 8) - i;
	    }
	    else
		pe -> pe_nbits = 0;
	    break;

	case PE_FORM_CONS: 
	    pe -> pe_nbits = 0;
	    for (p = pe -> pe_cons; p; p = p -> pe_next) {
		if (prim2bit (p) == NULLPE)
		    return NULLPE;
		pe -> pe_nbits += p -> pe_nbits;
	    }
	    break;
    }

    return pe;
}
