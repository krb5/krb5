/* set_addon.c - add member to end of a set */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:34:45  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:38:48  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:18  isode
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
#include "psap.h"

/*  */

int	set_addon (pe, last, new)
PE	pe,
        last,
        new;
{
    if (pe == NULLPE)
	return NOTOK;
    if (last == NULLPE)
	return set_add (pe, new);
    new -> pe_offset = pe -> pe_cardinal++;
    last -> pe_next = new;

    return OK;
}
