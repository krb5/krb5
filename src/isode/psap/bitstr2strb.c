/* bitstr2strb.c - bit string to string of bits */

/* 
 * isode/psap/bitstr2strb.c
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

char   *bitstr2strb (pe, k)
PE	pe;
int    *k;
{
    register int    i,
		    j,
		    len,
		    bit,
		    mask;
    register char   *dp;
    char   *cp;

    if (pe == NULLPE)
	return NULLCP;

    *k = len = pe -> pe_nbits;
    if ((cp = dp = calloc (1, (unsigned) (len / 8 + 2))) == NULLCP)
	return NULLCP;

    for (bit = i = 0, mask = 1 << (j = 7); i < len; i++) {
	if (bit_test (pe, i))
	    bit |= mask;
	if (j-- == 0)
	    *dp++ = bit & 0xff, bit = 0, mask = 1 << (j = 7);
	else
	    mask >>= 1;
    }
    if (j != 7)
	*dp = bit & 0xff;

    return cp;
}
