/* na2str.c - pretty-print NSAPaddr */

/* 
 * isode/compat/na2str.c
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
