/*
 * lib/crypto/make_checksum_iov.c
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
#include "cksumtypes.h"
#include "aead.h"

krb5_error_code KRB5_CALLCONV
krb5_c_make_checksum_iov(krb5_context context,
			 krb5_cksumtype cksumtype,
			 const krb5_keyblock *key,
			 krb5_keyusage usage,
			 krb5_crypto_iov *data,
			 size_t num_data)
{
    unsigned int i;
    size_t cksumlen;
    krb5_error_code ret;
    krb5_data cksum_data;
    krb5_crypto_iov *checksum;

    for (i = 0; i < krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == cksumtype)
	    break;
    }

    if (i == krb5_cksumtypes_length)
	return(KRB5_BAD_ENCTYPE);

    if (krb5_cksumtypes_list[i].keyhash != NULL)
	cksum_data.length = krb5_cksumtypes_list[i].keyhash->hashsize;
    else
	cksum_data.length = krb5_cksumtypes_list[i].hash->hashsize;

    if (krb5_cksumtypes_list[i].trunc_size != 0)
	cksumlen = krb5_cksumtypes_list[i].trunc_size;
    else
	cksumlen = cksum_data.length;

    checksum = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_CHECKSUM);
    if (checksum == NULL || checksum->data.length < cksumlen)
	return(KRB5_BAD_MSIZE);

    cksum_data.data = malloc(cksum_data.length);
    if (cksum_data.data == NULL)
	return(ENOMEM);

    ret = krb5int_c_make_checksum_iov(&krb5_cksumtypes_list[i],
				      key, usage, data, num_data,
				      &cksum_data);
    if (ret == 0) {
	memcpy(checksum->data.data, cksum_data.data, cksumlen);
	checksum->data.length = cksumlen;
    }

    free(cksum_data.data);

    return(ret);
}
