/* oid_free.c - free an object identifier */

/* 
 * isode/psap/oid_free.c
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
