/* int2strb.c - integer to string of bits */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.2  1994/06/15 20:59:55  eichin
 * step 1: bzero->memset(,0,)
 *
 * Revision 1.1  1994/06/10 03:32:42  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:09  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:44  isode
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

char   *int2strb (n, len)
register int    n;
int     len;
{
    register int    i;
    static char buffer[sizeof (int) + 1];

    memset (buffer, 0, sizeof (buffer));
    for (i = 0; i < len; i++)
	if (n & (1 << i))
	    buffer[i / 8] |= (1 << (7 - (i % 8)));

    return buffer;
}
