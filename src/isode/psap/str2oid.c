/* str2oid.c - string to object identifier */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:35:00  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:59  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:23  isode
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

OID	str2oid (s)
char    *s;
{
    int	    i;
    static struct OIDentifier   oids;
    static unsigned int elements[NELEM + 1];

    if ((i = str2elem (s, elements)) < 1
	    || elements[0] > 2
	    || (i > 1 && elements[0] < 2 && elements[1] > 39))
	return NULLOID;

    oids.oid_elements = elements, oids.oid_nelem = i;

    return (&oids);
}
