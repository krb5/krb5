/*
 * lib/crypto/verify_checksum_iov.c
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
krb5_c_verify_checksum_iov(krb5_context context, 
			   krb5_cksumtype checksum_type,
			   const krb5_keyblock *key,
			   krb5_keyusage usage,
			   const krb5_crypto_iov *data,
			   size_t num_data,
			   krb5_boolean *valid)
{
    unsigned int i;
    size_t cksumlen;
    krb5_error_code ret;
    krb5_data computed;
    krb5_crypto_iov *checksum;

    for (i = 0; i < krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == checksum_type)
	    break;
    }

    if (i == krb5_cksumtypes_length)
	return(KRB5_BAD_ENCTYPE);

    checksum = krb5int_c_locate_iov((krb5_crypto_iov *)data, num_data, KRB5_CRYPTO_TYPE_CHECKSUM);
    if (checksum == NULL)
	return(KRB5_BAD_MSIZE);

    /* if there's actually a verify function, call it */

    if (krb5_cksumtypes_list[i].keyhash &&
	krb5_cksumtypes_list[i].keyhash->verify_iov)
	return((*(krb5_cksumtypes_list[i].keyhash->verify_iov))(key, usage, 0,
								data, num_data,
								&checksum->data,
								valid));

    /* otherwise, make the checksum again, and compare */

    if (krb5_cksumtypes_list[i].keyhash != NULL)
	computed.length = krb5_cksumtypes_list[i].keyhash->hashsize;
    else
	computed.length = krb5_cksumtypes_list[i].hash->hashsize;

    if (krb5_cksumtypes_list[i].trunc_size != 0)
	cksumlen = krb5_cksumtypes_list[i].trunc_size;
    else
	cksumlen = computed.length;

    if (checksum->data.length != cksumlen)
	return(KRB5_BAD_MSIZE);

    computed.data = malloc(computed.length);
    if (computed.data == NULL)
	return(ENOMEM);

    if ((ret = krb5int_c_make_checksum_iov(&krb5_cksumtypes_list[i], key, usage,
					   data, num_data, &computed))) {
	free(computed.data);
	return(ret);
    }

    *valid = (computed.length == cksumlen) &&
	     (memcmp(computed.data, checksum->data.data, cksumlen) == 0);

    free(computed.data);

    return(0);
}
