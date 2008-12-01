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
#include "aead.h"

krb5_error_code KRB5_CALLCONV
krb5int_c_locate_iov(krb5_context context,
		     krb5_crypto_iov *data,
		     size_t num_data,
		     krb5_cryptotype type,
		     krb5_crypto_iov **iov)
{
    size_t i;

    *iov = NULL;

    if (data == NULL)
	return KRB5_BAD_MSIZE;

    for (i = 0; i < num_data; i++) {
	if (data[i].flags == type) {
	    *iov = &data[i];
	    return 0;
	}
    }

    return KRB5_BAD_MSIZE;
}

