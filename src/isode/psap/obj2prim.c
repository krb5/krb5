/* obj2prim.c - object identifier to presentation element */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:32:51  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:17  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:49  isode
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

PE	obj2prim (o, class, id)
register OID	o;
PElementClass	class;
PElementID	id;
{
    register int    i,
		    m,
		    n,
		   *mp,
		   *np;
    register unsigned int j,
			 *ip;
    register PElementData dp,
			  ep;
    register PE	    pe;

    if (o == NULLOID
	    || o -> oid_nelem <= 1
	    || o -> oid_elements[0] > 2
	    || (o -> oid_elements[0] < 2 && o -> oid_elements[1] > 39))
	return NULLPE;

    if ((pe = pe_alloc (class, PE_FORM_PRIM, id)) == NULLPE)
	return NULLPE;

    if ((np = (int *) malloc ((unsigned) (o -> oid_nelem) * sizeof *np))
	    == NULL) {
	pe_free (pe);
	return NULLPE;
    }

    for (i = n = 0, ip = o -> oid_elements, mp = np;
	    i < o -> oid_nelem;
	    i++, ip++) {
	if (ip == o -> oid_elements)
	    j = *ip++ * 40, i++, j+= *ip;
	else
	    j = *ip;
	m = 0;
	do {
	    m++;
	    j >>= 7;
	}
	while (j);
	n += (*mp++ = m);
    }

    if ((pe -> pe_prim = PEDalloc (pe -> pe_len = n)) == NULLPED) {
	free ((char *) np);
	pe_free (pe);
	return NULLPE;
    }

    dp = pe -> pe_prim; 
    for (i = 0, ip = o -> oid_elements, mp = np;
	    i < o -> oid_nelem;
	    i++, ip++) {
	if (ip == o -> oid_elements)
	    j = *ip++ * 40, i++, j += *ip;
	else
	    j = *ip;

	ep = dp + (m = *mp++) - 1;
	for (dp = ep; m-- > 0; j >>= 7)
	    *dp-- = (j & 0x7f) | 0x80;
	*ep &= ~0x80;
	dp = ep + 1;
    }

    free ((char *) np);

    return pe;
}
