/* na2str.c - pretty-print NSAPaddr */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:27:48  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:17  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:20  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:05  isode
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

/*    Network Address to String */

char   *na2str (na)
register struct NSAPaddr *na;
{
    switch (na -> na_stack) {
	case NA_TCP: 
	    return na -> na_domain;

	case NA_X25:
	case NA_BRG: 
	    return na -> na_dte;

	case NA_NSAP:
	default:
	    return sel2str (na -> na_address, na -> na_addrlen, 0);
    }
}
