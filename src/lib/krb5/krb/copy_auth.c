/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_copy_authdata()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_auth_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

static krb5_error_code
krb5_copy_authdatum(inad, outad)
const krb5_authdata *inad;
krb5_authdata **outad;
{
    krb5_authdata *tmpad;

    if (!(tmpad = (krb5_authdata *)malloc(sizeof(*tmpad))))
	return ENOMEM;
    *tmpad = *inad;
    if (!(tmpad->contents = (krb5_octet *)malloc(inad->length))) {
	xfree(tmpad);
	return ENOMEM;
    }
    bcopy((char *)inad->contents, (char *)tmpad->contents, inad->length);
    *outad = tmpad;
    return 0;
}

/*
 * Copy an authdata array, with fresh allocation.
 */
krb5_error_code
krb5_copy_authdata(inauthdat, outauthdat)
krb5_authdata * const * inauthdat;
krb5_authdata ***outauthdat;
{
    krb5_error_code retval;
    krb5_authdata ** tempauthdat;
    register int nelems;

    for (nelems = 0; inauthdat[nelems]; nelems++);

    /* one more for a null terminated list */
    if (!(tempauthdat = (krb5_authdata **) calloc(nelems+1,
						  sizeof(*tempauthdat))))
	return ENOMEM;

    for (nelems = 0; inauthdat[nelems]; nelems++)
	if (retval = krb5_copy_authdatum(inauthdat[nelems],
					 &tempauthdat[nelems])) {
	    krb5_free_authdata(tempauthdat);
	    return retval;
	}

    *outauthdat = tempauthdat;
    return 0;
}
