/* ps_prime.c - prime a presentation stream */

/* 
 * isode/psap/ps_prime.c
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

int	ps_prime (ps, waiting)
register PS	ps;
int	waiting;
{
    if (ps -> ps_primeP)
	return (*ps -> ps_primeP) (ps, waiting);

    return OK;
}
