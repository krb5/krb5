/* set_find.c - find member of a set */

/* 
 * isode/psap/set_find.c
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

PE	set_find (pe, class, id)
register PE	pe;
register PElementClass class;
register PElementID id;
{
    register int    pe_id;
    register PE	    p;

    pe_id = PE_ID (class, id);
    for (p = pe -> pe_cons; p; p = p -> pe_next)
	if (PE_ID (p -> pe_class, p -> pe_id) == pe_id)
	    break;

    return p;
}
