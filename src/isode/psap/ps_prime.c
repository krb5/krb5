/* ps_prime.c - prime a presentation stream */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:14  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:21  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:10  isode
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

int	ps_prime (ps, waiting)
register PS	ps;
int	waiting;
{
    if (ps -> ps_primeP)
	return (*ps -> ps_primeP) (ps, waiting);

    return OK;
}
