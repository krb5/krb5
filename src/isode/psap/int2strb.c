/* int2strb.c - integer to string of bits */

/* 
 * isode/psap/int2strb.c
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

char   *int2strb (n, len)
register int    n;
int     len;
{
    register int    i;
    static char buffer[sizeof (int) + 1];

    memset (buffer, 0, sizeof (buffer));
    for (i = 0; i < len; i++)
	if (n & (1 << i))
	    buffer[i / 8] |= (1 << (7 - (i % 8)));

    return buffer;
}
