/* pe_expunge.c - expunge a PE */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:28  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:46  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:58  isode
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

PE	pe_expunge (pe, r)
PE	pe,
	r;
{
    if (r) {
	if (pe == r)
	    return r;

	if (pe_extract (pe, r))
	    if (pe -> pe_realbase && !r -> pe_realbase) {
		r -> pe_realbase = pe -> pe_realbase;
		pe -> pe_realbase = NULL;
	    }

	r -> pe_refcnt++;
    }

    pe_free (pe);

    return r;
}
