/* prim2num.c - presentation element to integer */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:43  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:59  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:03  isode
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

integer	prim2num (pe)
register PE	pe;
{
    register integer    i;
    register PElementData dp,
			  ep;

    if (pe -> pe_form != PE_FORM_PRIM || pe -> pe_prim == NULLPED)
	return pe_seterr (pe, PE_ERR_PRIM, NOTOK);
    if (pe -> pe_len > sizeof (i))
	return pe_seterr (pe, PE_ERR_OVER, NOTOK);

    pe -> pe_errno = PE_ERR_NONE;/* in case integer is NOTOK-valued */
    i = (*(dp = pe -> pe_prim) & 0x80) ? (-1) : 0;
    for (ep = dp + pe -> pe_len; dp < ep;)
	i = (i << 8) | (*dp++ & 0xff);

    return i;
}
