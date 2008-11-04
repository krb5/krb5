/*
 * lib/crypto/aead.c
 *
 * Copyright 2008 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"
#include "etypes.h"
#include "cksumtypes.h"
#include "dk.h"
#include "aead.h"

krb5_crypto_iov * KRB5_CALLCONV
krb5int_c_locate_iov(krb5_crypto_iov *data,
		     size_t num_data,
		     krb5_cryptotype type)
{
    size_t i;
    krb5_crypto_iov *iov = NULL;

    if (data == NULL)
	return NULL;

    for (i = 0; i < num_data; i++) {
	if (data[i].flags == type) {
	    if (iov == NULL)
		iov = &data[i];
	    else
		return NULL; /* can't appear twice */
	}
    }

    return iov;
}

static krb5_error_code
make_unkeyed_checksum_iov(const struct krb5_hash_provider *hash_provider,
			  const krb5_crypto_iov *data,
			  size_t num_data,
			  krb5_data *output)
{
    krb5_data *sign_data;
    size_t num_sign_data;
    krb5_error_code ret;
    size_t i, j;

    /* Create a checksum over all the data to be signed */
    for (i = 0, num_sign_data = 0; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];

	if (SIGN_IOV(iov))
	    num_sign_data++;
    }

    /* XXX cleanup to avoid alloc */
    sign_data = (krb5_data *)calloc(num_sign_data, sizeof(krb5_data));
    if (sign_data == NULL)
	return ENOMEM;

    for (i = 0, j = 0; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];

	if (SIGN_IOV(iov))
	    sign_data[j++] = iov->data;
    }

    ret = hash_provider->hash(num_sign_data, sign_data, output);

    free(sign_data);

    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5int_c_make_checksum_iov(const struct krb5_cksumtypes *cksum_type,
			    const krb5_keyblock *key,
			    krb5_keyusage usage,
			    const krb5_crypto_iov *data,
			    size_t num_data,
			    krb5_data *cksum_data)
{
    int e1, e2;
    krb5_error_code ret;

    if (cksum_type->keyhash != NULL) {
	/* check if key is compatible */

	if (cksum_type->keyed_etype) {
	    for (e1=0; e1<krb5_enctypes_length; e1++) 
		if (krb5_enctypes_list[e1].etype ==
		    cksum_type->keyed_etype)
		    break;

	    for (e2=0; e2<krb5_enctypes_length; e2++) 
		if (krb5_enctypes_list[e2].etype == key->enctype)
		    break;

	    if ((e1 == krb5_enctypes_length) ||
		(e2 == krb5_enctypes_length) ||
		(krb5_enctypes_list[e1].enc != krb5_enctypes_list[e2].enc)) {
		ret = KRB5_BAD_ENCTYPE;
		goto cleanup;
	    }
	}

	if (cksum_type->keyhash->hash_iov == NULL) {
	    return KRB5_BAD_ENCTYPE;
	}

	ret = (*(cksum_type->keyhash->hash_iov))(key, usage, 0,
							     data, num_data, cksum_data);
    } else if (cksum_type->flags & KRB5_CKSUMFLAG_DERIVE) {
	ret = krb5_dk_make_checksum_iov(cksum_type->hash,
					key, usage, data, num_data,
					cksum_data);
    } else {
	ret = make_unkeyed_checksum_iov(cksum_type->hash, data, num_data,
					cksum_data);
    }

    if (ret == 0) {
	if (cksum_type->trunc_size) {
	    cksum_data->length = cksum_type->trunc_size;
	}
    }

cleanup:
    if (ret != 0) {
	memset(cksum_data->data, 0, cksum_data->length);
    }

    return ret;
}
