/* ps_flush.c - flush a presentation stream */

/* 
 * isode/psap/ps_flush.c
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

int	ps_flush (ps)
register PS	ps;
{
    if (ps -> ps_flushP)
	return (*ps -> ps_flushP) (ps);

    return OK;
}
