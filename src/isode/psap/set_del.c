/* set_del.c - remove member from set */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:47  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:49  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:19  isode
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

int	set_del (pe, class, id)
register PE	pe;
register PElementClass class;
register PElementID id;
{
    register int    pe_id;
    register PE	   *p,
		    q;

    pe_id = PE_ID (class, id);
    for (p = &pe -> pe_cons; q = *p; p = &q -> pe_next)
	if (PE_ID (q -> pe_class, q -> pe_id) == pe_id) {
	    (*p) = q -> pe_next;
	    pe_free (q);
	    return OK;
	}

    return pe_seterr (pe, PE_ERR_MBER, NOTOK);
}
