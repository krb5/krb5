/* py_advise.c - standard "advise" routine for pepsy/pepy */

/* 
 * isode/pepsy/py_advise.c
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
