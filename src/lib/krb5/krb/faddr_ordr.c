/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_fulladdr_order()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_faddr_ordr_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
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
krb5_fulladdr_order(addr1, addr2)
const krb5_fulladdr *addr1;
const krb5_fulladdr *addr2;
{
    int dir;
    dir = addr1->address->addrtype - addr2->address->addrtype;
    if (dir)
	return(dir);

    dir = addr1->address->length - addr2->address->length;
    if (dir)
	return(dir);

    dir = bcmp((char *)addr1->address->contents,
	       (char *)addr2->address->contents,
	       min(addr1->address->length, addr2->address->length));
    if (dir)
	return(dir);

    if (addr1->port > addr2->port)
	return(1);
    else if (addr1->port < addr2->port)
	return(-1);
    else
	return(0);
}
