/* oid_cpy.c - copy an object identifier */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:02  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:27  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:52  isode
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

OID	oid_cpy (q)
register OID q;
{
    register unsigned int   i,
			   *ip,
			   *jp;
    register OID	oid;

    if (q == NULLOID)
	return NULLOID;
    if ((i = q -> oid_nelem) < 1)
	return NULLOID;
    if ((oid = (OID) malloc (sizeof *oid)) == NULLOID)
	return NULLOID;

    if ((ip = (unsigned int *) malloc ((unsigned) (i + 1) * sizeof *ip))
	    == NULL) {
	free ((char *) oid);
	return NULLOID;
    }

    oid -> oid_elements = ip, oid -> oid_nelem = i;

    for (i = 0, jp = q -> oid_elements; i < oid -> oid_nelem; i++, jp++)
	*ip++ = *jp;

    return oid;
}
