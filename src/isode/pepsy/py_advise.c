/* py_advise.c - standard "advise" routine for pepsy/pepy */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:31:34  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/05/31 20:40:28  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:43:15  isode
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
#include <varargs.h>

/*  */

#ifndef	lint
char   PY_pepy[BUFSIZ];


void	PY_advise (va_alist)
va_dcl
{
    va_list	ap;

    va_start (ap);

    asprintf (PY_pepy, ap);

    va_end (ap);
}
#else
/* VARARGS */

void	PY_advise (what, fmt)
char   *what,
       *fmt;
{
    PY_advise (what, fmt);
}
#endif
