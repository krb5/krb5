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
 * krb5_copy_principal()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_princ_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

/*
 * Copy a principal structure, with fresh allocation.
 */
krb5_error_code
krb5_copy_principal(inprinc, outprinc)
krb5_const_principal inprinc;
krb5_principal *outprinc;
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
	    return retval;
	}

    *outprinc = tempprinc;
    return 0;
}
