/*
 * lib/krb5/krb/faddr_ordr.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_fulladdr_order()
 */


#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#ifndef min
#define min(a,b) ((a) > (b) ? (a) : (b))
#endif

/*
 * Return an ordering on the two full addresses:  0 if the same,
 * < 0 if first is less than 2nd, > 0 if first is greater than 2nd.
 */
int
krb5_fulladdr_order(context, addr1, addr2)
    krb5_context context;
    register const krb5_fulladdr *addr1;
    register const krb5_fulladdr *addr2;
{
    int dir;
    const int minlen = min(addr1->address->length, addr2->address->length);
    register int i;

    dir = addr1->address->addrtype - addr2->address->addrtype;
    if (dir)
	return(dir);

    dir = addr1->address->length - addr2->address->length;
    if (dir)
	return(dir);

    for (i = 0; i < minlen; i++) {
	if ((unsigned char) addr1->address->contents[i] <
	    (unsigned char) addr2->address->contents[i])
	    return -1;
	else if ((unsigned char) addr1->address->contents[i] >
		 (unsigned char) addr2->address->contents[i])
	    return 1;
    }
    if (addr1->port > addr2->port)
	return(1);
    else if (addr1->port < addr2->port)
	return(-1);
    else
	return(0);
}
