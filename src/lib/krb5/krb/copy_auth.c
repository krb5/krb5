/*
 * lib/krb5/krb/copy_auth.c
 *
 * Portions Copyright (C) 2008 Novell Inc.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_copy_authdata()
 */

#include "k5-int.h"

static krb5_error_code
krb5_copy_authdatum(krb5_context context, const krb5_authdata *inad, krb5_authdata **outad)
{
    krb5_authdata *tmpad;

    if (!(tmpad = (krb5_authdata *)malloc(sizeof(*tmpad))))
	return ENOMEM;
    *tmpad = *inad;
    if (!(tmpad->contents = (krb5_octet *)malloc(inad->length))) {
	krb5_xfree(tmpad);
	return ENOMEM;
    }
    memcpy((char *)tmpad->contents, (char *)inad->contents, inad->length);
    *outad = tmpad;
    return 0;
}

/*
 * Copy an authdata array, with fresh allocation.
 */
krb5_error_code KRB5_CALLCONV
krb5_copy_authdata(krb5_context context, krb5_authdata *const *inauthdat, krb5_authdata ***outauthdat)
{
    krb5_error_code retval;
    krb5_authdata ** tempauthdat;
    register unsigned int nelems = 0;

    if (!inauthdat) {
	    *outauthdat = 0;
	    return 0;
    }

    while (inauthdat[nelems]) nelems++;

    /* one more for a null terminated list */
    if (!(tempauthdat = (krb5_authdata **) calloc(nelems+1,
						  sizeof(*tempauthdat))))
	return ENOMEM;

    for (nelems = 0; inauthdat[nelems]; nelems++) {
	retval = krb5_copy_authdatum(context, inauthdat[nelems],
				     &tempauthdat[nelems]);
	if (retval) {
	    krb5_free_authdata(context, tempauthdat);
	    return retval;
	}
    }

    *outauthdat = tempauthdat;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_decode_ad_if_relevant(krb5_context context, const krb5_authdata *if_relevant, krb5_authdata ***authdata)
{
    krb5_error_code code;
    krb5_data data;

    *authdata = NULL;

    if (if_relevant->ad_type != KRB5_AUTHDATA_IF_RELEVANT)
	return EINVAL;

    data.length = if_relevant->length;
    data.data = (char *)if_relevant->contents;

    code = decode_krb5_authdata(&data, authdata);
    if (code)
	return code;

    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_encode_ad_if_relevant(krb5_context context, krb5_authdata *const*authdata, krb5_authdata ***if_relevant_p)
{
    krb5_error_code code;
    krb5_data *data;
    krb5_authdata ad_datum;
    krb5_authdata *ad_data[2];

    *if_relevant_p = NULL;

    code = encode_krb5_authdata((krb5_authdata * const *)authdata, &data);
    if (code)
	return code;

    ad_datum.ad_type = KRB5_AUTHDATA_IF_RELEVANT;
    ad_datum.length = data->length;
    ad_datum.contents = (unsigned char *)data->data;

    ad_data[0] = &ad_datum;
    ad_data[1] = NULL;

    code = krb5_copy_authdata(context, ad_data, if_relevant_p);

    krb5_free_data(context, data);

    return code;
}
