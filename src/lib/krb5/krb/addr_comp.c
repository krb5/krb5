/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_address_compare()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_addr_comp_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

/*
 * If the two addresses are the same, return TRUE, else return FALSE
 */
krb5_boolean
krb5_address_compare(addr1, addr2)
const krb5_address *addr1;
const krb5_address *addr2;
{
    if (addr1->addrtype != addr2->addrtype)
	return(FALSE);

    if (addr1->length != addr2->length)
	return(FALSE);
    if (bcmp((char *)addr1->contents, (char *)addr2->contents, addr1->length))
	return FALSE;
    else
	return TRUE;
}
