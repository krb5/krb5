/* ps_free.c - free a presentation stream */

/* 
 * isode/psap/ps_free.c
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
