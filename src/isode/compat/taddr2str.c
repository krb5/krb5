/* taddr2str.c - TSAPaddr to string value */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.2  1994/06/15 20:59:31  eichin
 * step 1: bzero->memset(,0,)
 *
 * Revision 1.1  1994/06/10 03:28:41  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:17:04  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:35:01  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:21  isode
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
#include "general.h"
#include "manifest.h"
#include "isoaddrs.h"

/*  */

char   *taddr2str (ta)
register struct TSAPaddr *ta;
{
    struct PSAPaddr pas;
    register struct PSAPaddr *pa = &pas;

    if (!ta)
	return NULL;
    memset ((char *) pa, 0, sizeof *pa);
    pa -> pa_addr.sa_addr = *ta;	/* struct copy */

    return paddr2str (pa, NULLNA);
}
