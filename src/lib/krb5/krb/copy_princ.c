/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_copy_principal()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_princ_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <errno.h>

#include <krb5/ext-proto.h>

/*
 * Copy a principal structure, with fresh allocation.
 */
krb5_error_code
krb5_copy_principal(inprinc, outprinc)
krb5_principal inprinc, *outprinc;
{
    krb5_error_code retval;
    krb5_principal tempprinc;
    register int nelems;

    for (nelems = 0; inprinc[nelems]; nelems++);

    /* one more for a null terminated list */
    if (!(tempprinc = (krb5_principal) calloc(nelems+1, sizeof(krb5_data *))))
	return ENOMEM;

    for (nelems = 0; inprinc[nelems]; nelems++)
	if (retval = krb5_copy_data(inprinc[nelems], &tempprinc[nelems])) {
	    krb5_free_principal(tempprinc);
	    return ENOMEM;
	}

    *outprinc = tempprinc;
    return 0;
}
