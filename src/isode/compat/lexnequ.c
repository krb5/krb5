/* lexnequ.c - Compare two strings ignoring case upto n octets */

#ifndef lint
static char *rcsid = "$Header$";
#endif

/*
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:27:39  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:08  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:08  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:01  isode
 * Release 7.0
 * 
 * 
 */

/*
 *                                NOTICE
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

/*  */

lexnequ (str1, str2, len)
register char   *str1,
		*str2;
int             len;
{
    register int count = 1;

    if (str1 == NULL)
	if (str2 == NULL)
		return (0);
	else
		return (1);

    if (str2 == NULL)
	return (-1);

    while (chrcnv[*str1] == chrcnv[*str2++]) {
	if (count++ >= len)
	    return (0);
	if (*str1++ == NULL)
	    return (0);
    }

    str2--;
    if (chrcnv[*str1] > chrcnv[*str2])
	return (1);
    else
	return (-1);
}
