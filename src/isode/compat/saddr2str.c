/* saddr2str.c - SSAPaddr to string value */

/* 
 * isode/compat/saddr2str.c
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
#include "isoaddrs.h"

/*  */

char   *saddr2str (sa)
register struct SSAPaddr *sa;
{
    struct PSAPaddr pas;
    register struct PSAPaddr *pa = &pas;

    if (!sa)
	return NULL;
    memset ((char *) pa, 0, sizeof *pa);
    pa -> pa_addr = *sa;		/* struct copy */

    return paddr2str (pa, NULLNA);
}
