/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_address_order()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_addr_order_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/*
 * Return an ordering on two addresses:  0 if the same,
 * < 0 if first is less than 2nd, > 0 if first is greater than 2nd.
 */
int
krb5_address_order(addr1, addr2)
register const krb5_address *addr1;
register const krb5_address *addr2;
{
    int dir;
    register int i;
    const int minlen = min(addr1->length, addr2->length);

    if (addr1->addrtype != addr2->addrtype)
	return(FALSE);

    dir = addr1->length - addr2->length;

    
    for (i = 0; i < minlen; i++) {
	if ((unsigned char) addr1->contents[i] <
	    (unsigned char) addr2->contents[i])
	    return -1;
	else if ((unsigned char) addr1->contents[i] >
		 (unsigned char) addr2->contents[i])
	    return 1;
    }
    /* compared equal so far...which is longer? */
    return dir;
}
