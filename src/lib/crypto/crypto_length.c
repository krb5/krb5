/*
 * lib/crypto/crypto_length.c
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
#include "aead.h"

krb5_error_code KRB5_CALLCONV
krb5_c_crypto_length(krb5_context context,
		     krb5_enctype enctype,
		     krb5_cryptotype type,
		     unsigned int *size)
{
    int i;
    const struct krb5_keytypes *ktp = NULL;
    krb5_error_code ret;

    for (i = 0; i < krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype) {
	    ktp = &krb5_enctypes_list[i];
	    break;
	}
    }

    if (ktp == NULL || ktp->aead == NULL) {
	return KRB5_BAD_ENCTYPE;
    }

    switch (type) {
    case KRB5_CRYPTO_TYPE_EMPTY:
    case KRB5_CRYPTO_TYPE_SIGN_ONLY:
	*size = 0;
	ret = 0;
	break;
    case KRB5_CRYPTO_TYPE_DATA:
	*size = (size_t)~0; /* match Heimdal */
	ret = 0;
	break;
    case KRB5_CRYPTO_TYPE_HEADER:
    case KRB5_CRYPTO_TYPE_PADDING:
    case KRB5_CRYPTO_TYPE_TRAILER:
    case KRB5_CRYPTO_TYPE_CHECKSUM:
	ret = ktp->aead->crypto_length(ktp->aead, ktp->enc, ktp->hash, type, size);
	break;
    default:
	ret = EINVAL;
	break;
    }

    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_c_padding_length(krb5_context context,
		      krb5_enctype enctype,
		      size_t data_length,
		      unsigned int *pad_length)
{
    int i;
    const struct krb5_keytypes *ktp = NULL;

    for (i = 0; i < krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype) {
	    ktp = &krb5_enctypes_list[i];
	    break;
	}
    }

    if (ktp == NULL || ktp->aead == NULL) {
	return KRB5_BAD_ENCTYPE;
    }

    return krb5int_c_padding_length(ktp->aead, ktp->enc, ktp->hash, data_length, pad_length);
}

krb5_error_code KRB5_CALLCONV
krb5_c_crypto_length_iov(krb5_context context,
			 krb5_enctype enctype,
			 krb5_crypto_iov *data,
			 size_t num_data)
{
    krb5_error_code ret = 0;
    size_t i;
    const struct krb5_keytypes *ktp = NULL;
    unsigned int data_length = 0, pad_length;
    krb5_crypto_iov *padding = NULL;

    /*
     * XXX need to rejig internal interface so we can accurately
     * report variable header lengths
     */

    for (i = 0; i < (size_t)krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype) {
	    ktp = &krb5_enctypes_list[i];
	    break;
	}
    }

    if (ktp == NULL || ktp->aead == NULL) {
	return KRB5_BAD_ENCTYPE;
    }

    for (i = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	switch (iov->flags) {
	case KRB5_CRYPTO_TYPE_DATA:
	    data_length += iov->data.length;
	    break;
	case KRB5_CRYPTO_TYPE_PADDING:
	    if (padding != NULL)
		return EINVAL;

	    padding = iov;
	    break;
	case KRB5_CRYPTO_TYPE_HEADER:
	case KRB5_CRYPTO_TYPE_TRAILER:
	case KRB5_CRYPTO_TYPE_CHECKSUM:
	    ret = ktp->aead->crypto_length(ktp->aead, ktp->enc, ktp->hash, iov->flags, &iov->data.length);
	    break;
	case KRB5_CRYPTO_TYPE_EMPTY:
	case KRB5_CRYPTO_TYPE_SIGN_ONLY:
	default:
	    break;
	}

	if (ret != 0)
	    break;
    }

    if (ret != 0)
	return ret;

    ret = krb5int_c_padding_length(ktp->aead, ktp->enc, ktp->hash, data_length, &pad_length);
    if (ret != 0)
	return ret;

    if (pad_length != 0 && padding == NULL)
	return EINVAL;

    if (padding != NULL)
	padding->data.length = pad_length;

    return 0;
}

