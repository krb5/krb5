/* ps_error.c - presentation stream error to string */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:03  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:13  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:08  isode
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

static char *ps_errorlist[] = {
    "Error 0",
    "Overflow in ID",
    "Overflow in length",
    "Out of memory",
    "End of file",
    "End of file reading extended ID",
    "End of file reading extended length",
    "Length Mismatch",
    "Truncated",
    "Indefinite length in primitive form",
    "I/O error",
    "Extraneous octets",
    "XXX"
};

static int ps_maxerror = sizeof ps_errorlist / sizeof ps_errorlist[0];

/*  */

char   *ps_error (c)
int	c;
{
    register char  *bp;
    static char buffer[30];

    if (c < ps_maxerror && (bp = ps_errorlist[c]))
	return bp;

    (void) sprintf (buffer, "Error %d", c);
    return buffer;
}
