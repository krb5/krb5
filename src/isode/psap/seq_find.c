/* seq_find.c - find an element in a sequence */

/* 
 * isode/psap/seq_find.c
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

PE	seq_find (pe, i)
register PE	pe;
register int	i;
{
    register PE	    p;

    if (i >= pe -> pe_cardinal)
	return pe_seterr (pe, PE_ERR_MBER, NULLPE);

    for (p = pe -> pe_cons; p; p = p -> pe_next)
	if (p -> pe_offset == i)
	    break;

    return p;
}
