/* taddr2str.c - TSAPaddr to string value */

/* 
 * isode/compat/taddr2str.c
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

char   *taddr2str (ta)
register struct TSAPaddr *ta;
{
    struct PSAPaddr pas;
    register struct PSAPaddr *pa = &pas;

    if (!ta)
	return NULL;
    memset ((char *) pa, 0, sizeof *pa);
    pa -> pa_addr.sa_addr = *ta;	/* struct copy */

    return paddr2str (pa, NULLNA);
}
