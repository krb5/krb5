/* explode.c - explode octets into ascii */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:27:12  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:15:39  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:33:43  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:17:53  isode
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

/*    DATA */

static char nib2hex[0x10] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

/*  */

int	explode (a, b, n)
register char  *a;
register u_char *b;
register int    n;
{
    register int    i;
    register u_char c;

    for (i = 0; i < n; i++) {
	c = *b++;
	*a++ = nib2hex[(u_char)(c & 0xf0) >> 4];
	*a++ = nib2hex[(c & 0x0f)];
    }
    *a = NULL;

    return (n * 2);
}
