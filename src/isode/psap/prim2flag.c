/* prim2flag.c - presentation element to boolean */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:42  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:58  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:02  isode
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

int	prim2flag (pe)
register PE	pe;
{
    if (pe -> pe_form != PE_FORM_PRIM
	    || pe -> pe_prim == NULLPED
	    || pe -> pe_len == 0)
	return pe_seterr (pe, PE_ERR_PRIM, NOTOK);

    return (*pe -> pe_prim != 0x00);
}
