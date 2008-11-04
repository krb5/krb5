/*
 * lib/crypto/encrypt_iov.c
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

