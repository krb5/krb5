/* set_find.c - find member of a set */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:49  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:51  eichin
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

PE	set_find (pe, class, id)
register PE	pe;
register PElementClass class;
register PElementID id;
{
    register int    pe_id;
    register PE	    p;

    pe_id = PE_ID (class, id);
    for (p = pe -> pe_cons; p; p = p -> pe_next)
	if (PE_ID (p -> pe_class, p -> pe_id) == pe_id)
	    break;

    return p;
}
