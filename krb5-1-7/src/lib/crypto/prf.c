/*
 * lib/crypto/prf.c
 *
 * Copyright (C) 2004 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 *
 * This contains the implementation of krb5_c_prf, which  will find
 *the enctype-specific PRF and then generate pseudo-random data.  This
 *function yields krb5_c_prf_length bytes of output.
 */


#include "k5-int.h"
#include "etypes.h"

#include <assert.h>

krb5_error_code KRB5_CALLCONV
krb5_c_prf_length(krb5_context context, krb5_enctype enctype,
		  size_t *len)
{
    int i;
    assert (len);

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    *len = krb5_enctypes_list[i].prf_length;
    return 0;
    
}

krb5_error_code KRB5_CALLCONV
krb5_c_prf(krb5_context context, const krb5_keyblock *key,
krb5_data *input, krb5_data *output)
{
    int i;
    size_t len;
    assert(input && output);
    assert (output->data);


    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == key->enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    output->magic = KV5M_DATA;
    if (!krb5_enctypes_list[i].prf)
	return (KRB5_CRYPTO_INTERNAL);
    krb5_c_prf_length (context, key->enctype, &len);
    if( len != output->length)
	return (KRB5_CRYPTO_INTERNAL);
            return((*(krb5_enctypes_list[i].prf))
	   (krb5_enctypes_list[i].enc, krb5_enctypes_list[i].hash,
	    key,  input, output));
}

