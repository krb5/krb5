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
 * krb5_address_search()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_addr_srch_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>

/*
 * if addr is listed in addrlist, or addrlist is null, return TRUE.
 * if not listed, return FALSE
 */
krb5_boolean
krb5_address_search(addr, addrlist)
const krb5_address *addr;
krb5_address * const * addrlist;
{
    if (!addrlist)
	return TRUE;
    for (; *addrlist; addrlist++) {
	if (krb5_address_compare(addr, *addrlist))
	    return TRUE;
    }
    return FALSE;
}
