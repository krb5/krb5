/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * krb5_copy_addresses()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_addrs_c[] =
"$Id$";
#endif	/* !lint & !SABER */

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
    register int nelems = 0;

    if (!inaddr) {
	    *outaddr = 0;
	    return 0;
    }
    
    while (inaddr[nelems]) nelems++;

    /* one more for a null terminated list */
    if (!(tempaddr = (krb5_address **) calloc(nelems+1, sizeof(*tempaddr))))
	return ENOMEM;

    for (nelems = 0; inaddr[nelems]; nelems++)
	retval = krb5_copy_addr(inaddr[nelems], &tempaddr[nelems]);
        if (retval) {
	    krb5_free_addresses(tempaddr);
	    return retval;
	}

    *outaddr = tempaddr;
    return 0;
}

/*
 * Append an address array, to another address array, with fresh allocation.
 * Note that this function may change the value of *outaddr even if it
 * returns failure, but it will not change the contents of the list.
 */
krb5_error_code
krb5_append_addresses(inaddr, outaddr)
krb5_address * const * inaddr;
krb5_address ***outaddr;
{
    krb5_error_code retval;
    krb5_address ** tempaddr;
    krb5_address ** tempaddr2;
    register int nelems = 0;
    register int norigelems = 0;

    if (!inaddr)
	return 0;

    tempaddr2 = *outaddr;

    while (inaddr[nelems]) nelems++;
    while (tempaddr2[norigelems]) norigelems++;

    tempaddr = (krb5_address **) realloc((char *)*outaddr,
		       (nelems + norigelems + 1) * sizeof(*tempaddr));
    if (!tempaddr)
	return ENOMEM;

    /* The old storage has been freed.  */
    *outaddr = tempaddr;


    for (nelems = 0; inaddr[nelems]; nelems++) {
	retval = krb5_copy_addr(inaddr[nelems],
				&tempaddr[norigelems + nelems]);
	if (retval)
	    goto cleanup;
    }

    tempaddr[norigelems + nelems] = 0;
    return 0;

  cleanup:
    while (--nelems >= 0)
	krb5_free_address(tempaddr[norigelems + nelems]);

    /* Try to allocate a smaller amount of memory for *outaddr.  */
    tempaddr = (krb5_address **) realloc((char *)tempaddr,
					 (norigelems + 1) * sizeof(*tempaddr));
    if (tempaddr)
	*outaddr = tempaddr;
    return retval;
}

