/* flag2prim.c - boolean to presentation element */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:32:36  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:03  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:43  isode
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

PE	flag2prim (b, class, id)
register int b;
PElementClass	class;
PElementID	id;
{
    register PE	    pe;

    if ((pe = pe_alloc (class, PE_FORM_PRIM, id)) == NULLPE)
	return NULLPE;

    if ((pe -> pe_prim = PEDalloc (pe -> pe_len = 1)) == NULLPED) {
	pe_free (pe);
	return NULLPE;
    }

    *pe -> pe_prim = b ? 0xff : 0x00;

    return pe;
}
