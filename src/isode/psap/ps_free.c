/* ps_free.c - free a presentation stream */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:07  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:16  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:09  isode
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

void	ps_free (ps)
register PS	ps;
{
    if (ps -> ps_closeP)
	(void) (*ps -> ps_closeP) (ps);

    free ((char *) ps);
}
