/* str2saddr.c - string value to SSAPaddr */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:28:29  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:52  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:51  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:16  isode
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

struct SSAPaddr *str2saddr (str)
char   *str;
{
    register struct PSAPaddr *pa;

    if (pa = str2paddr (str))
	return (&pa -> pa_addr);

    return NULLSA;
}
