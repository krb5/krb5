/* serror.c - get system error */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:28:06  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:16:35  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:34:34  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:18:10  isode
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

extern	int sys_nerr;
extern  char *sys_errlist[];

/*  */

char   *sys_errname (i)
int	i;
{
    static char buffer[30];

    if (0 < i && i < sys_nerr)
	return sys_errlist[i];
    (void) sprintf (buffer, "Error %d", i);

    return buffer;
}
