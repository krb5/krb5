/*
 * lib/krb5/krb/copy_auth.c
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
/*
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
	free(tmpad);
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
krb5_merge_authdata(krb5_context context, krb5_authdata *const *inauthdat1, krb5_authdata * const *inauthdat2,
		    krb5_authdata ***outauthdat)
{
    krb5_error_code retval;
    krb5_authdata ** tempauthdat;
    register unsigned int nelems = 0, nelems2 = 0;

    *outauthdat = NULL;
    if (!inauthdat1 && !inauthdat2) {
	    *outauthdat = 0;
	    return 0;
    }

    if (inauthdat1) 
	while (inauthdat1[nelems]) nelems++;
    if (inauthdat2) 
	while (inauthdat2[nelems2]) nelems2++;

    /* one more for a null terminated list */
    if (!(tempauthdat = (krb5_authdata **) calloc(nelems+nelems2+1,
						  sizeof(*tempauthdat))))
	return ENOMEM;

    if (inauthdat1) {
	for (nelems = 0; inauthdat1[nelems]; nelems++) {
	    retval = krb5_copy_authdatum(context, inauthdat1[nelems],
					 &tempauthdat[nelems]);
	    if (retval) {
		krb5_free_authdata(context, tempauthdat);
		return retval;
	    }
	}
    }

    if (inauthdat2) {
	for (nelems2 = 0; inauthdat2[nelems2]; nelems2++) {
	    retval = krb5_copy_authdatum(context, inauthdat2[nelems2],
					 &tempauthdat[nelems++]);
	    if (retval) {
		krb5_free_authdata(context, tempauthdat);
		return retval;
	    }
	}
    }

    *outauthdat = tempauthdat;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_copy_authdata(krb5_context context,
		   krb5_authdata *const *in_authdat, krb5_authdata ***out)
{
    return krb5_merge_authdata(context, in_authdat, NULL, out);
}

krb5_error_code KRB5_CALLCONV
krb5_decode_authdata_container(krb5_context context,
			       krb5_authdatatype type,
			       const krb5_authdata *container,
			       krb5_authdata ***authdata)
{
    krb5_error_code code;
    krb5_data data;

    *authdata = NULL;

    if ((container->ad_type & AD_TYPE_FIELD_TYPE_MASK) != type)
	return EINVAL;

    data.length = container->length;
    data.data = (char *)container->contents;

    code = decode_krb5_authdata(&data, authdata);
    if (code)
	return code;

    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_encode_authdata_container(krb5_context context,
			       krb5_authdatatype type,
			       krb5_authdata *const*authdata,
			       krb5_authdata ***container)
{
    krb5_error_code code;
    krb5_data *data;
    krb5_authdata ad_datum;
    krb5_authdata *ad_data[2];

    *container = NULL;

    code = encode_krb5_authdata((krb5_authdata * const *)authdata, &data);
    if (code)
	return code;

    ad_datum.ad_type = type & AD_TYPE_FIELD_TYPE_MASK;
    ad_datum.length = data->length;
    ad_datum.contents = (unsigned char *)data->data;

    ad_data[0] = &ad_datum;
    ad_data[1] = NULL;

    code = krb5_copy_authdata(context, ad_data, container);

    krb5_free_data(context, data);

    return code;
}
