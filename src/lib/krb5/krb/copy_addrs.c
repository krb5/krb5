/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_copy_addresses()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_addrs_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

static krb5_error_code
krb5_copy_addr(inad, outad)
const krb5_address *inad;
krb5_address **outad;
{
    krb5_address *tmpad;

    if (!(tmpad = (krb5_address *)malloc(sizeof(*tmpad))))
	return ENOMEM;
    *tmpad = *inad;
    if (!(tmpad->contents = (krb5_octet *)malloc(inad->length))) {
	xfree(tmpad);
	return ENOMEM;
    }
    memcpy((char *)tmpad->contents, (char *)inad->contents, inad->length);
    *outad = tmpad;
    return 0;
}

/*
 * Copy an address array, with fresh allocation.
 */
krb5_error_code
krb5_copy_addresses(inaddr, outaddr)
krb5_address * const * inaddr;
krb5_address ***outaddr;
{
    krb5_error_code retval;
    krb5_address ** tempaddr;
    register int nelems;

    for (nelems = 0; inaddr[nelems]; nelems++);

    /* one more for a null terminated list */
    if (!(tempaddr = (krb5_address **) calloc(nelems+1, sizeof(*tempaddr))))
	return ENOMEM;

    for (nelems = 0; inaddr[nelems]; nelems++)
	if (retval = krb5_copy_addr(inaddr[nelems], &tempaddr[nelems])) {
	    krb5_free_address(tempaddr);
	    return retval;
	}

    *outaddr = tempaddr;
    return 0;
}
