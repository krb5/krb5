/* time2prim.c - time string to presentation element */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:35:15  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:39:10  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:27  isode
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

PE	time2prim (u, generalized, class, id)
register UTC	u;
int	generalized;
PElementClass	class;
PElementID	id;
{
    register int    len;
    register char  *bp;
    register PE	    pe;

    if ((bp = time2str (u, generalized)) == NULLCP)
	return NULLPE;

    if ((pe = pe_alloc (class, PE_FORM_PRIM, id)) == NULLPE)
	return NULLPE;

    if ((pe -> pe_prim = PEDalloc (len = strlen (bp))) == NULLPED) {
	pe_free (pe);
	return NULLPE;
    }
    PEDcpy (bp, pe -> pe_prim, pe -> pe_len = len);

    return pe;
}
