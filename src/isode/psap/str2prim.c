/* str2prim.c - octet string to presentation element */

/* 
 * isode/psap/str2prim.c
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

PE	str2prim (s, len, class, id)
register char *s;
register int len;
PElementClass	class;
PElementID	id;
{
    register PE	    pe;

    if ((pe = pe_alloc (class, PE_FORM_PRIM, id)) == NULLPE)
	return NULLPE;

    if (len && (pe -> pe_prim = PEDalloc (pe -> pe_len = len)) == NULLPED) {
	pe_free (pe);
	return NULLPE;
    }

    if (s)
	PEDcpy (s, pe -> pe_prim, len);

    return pe;
}
