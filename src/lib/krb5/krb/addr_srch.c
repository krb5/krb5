/*
 * $Source$
 * $Author$
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
