/* oid_free.c - free an object identifier */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:04  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:29  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:53  isode
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

int	oid_free (oid)
register OID oid;
{
    if (oid == NULLOID)
	return;

    if (oid -> oid_elements)
	free ((char *) oid -> oid_elements);

    free ((char *) oid);
}
