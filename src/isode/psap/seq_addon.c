/* seq_addon.c - add a member to the end of a sequence (efficiency hack) */

/* 
 * isode/psap/seq_addon.c
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

int	seq_addon (pe, last, new)
PE	pe,
        last,
        new;
{
    if (pe == NULLPE)
	return NOTOK;
    if (last == NULLPE)
	return seq_add (pe, new, -1);
    new -> pe_offset = pe -> pe_cardinal++;
    last -> pe_next = new;
    return OK;
}
