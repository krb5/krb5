/* pe_error.c - presentation element error to string */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:26  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:45  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:46:58  isode
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

/*  */

static char *pe_errorlist[] = {
    "Error 0",
    "Overflow",
    "Out of memory",
    "No such bit",
    "Malformed universal timestring",
    "Malformed generalized timestring",
    "No such member",
    "Not a primitive form",
    "Not a constructor form",
    "Class/ID mismatch in constructor",
    "Malformed object identifier",
    "Malformed bitstring",
    "Type not supported",
    "Signed integer not expected"
};

static int pe_maxerror = sizeof pe_errorlist / sizeof pe_errorlist[0];

/*  */

char   *pe_error (c)
int	c;
{
    register char  *bp;
    static char buffer[30];

    if (c < pe_maxerror && (bp = pe_errorlist[c]))
	return bp;

    (void) sprintf (buffer, "Error %d", c);
    return buffer;
}
