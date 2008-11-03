/*
 * lib/crypto/dk/dk_aead.c
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
#include "dk.h"
#include "aead.h"

/* AEAD */

static krb5_error_code
krb5int_dk_crypto_length(const struct krb5_aead_provider *aead,
			 const struct krb5_enc_provider *enc,
			 const struct krb5_hash_provider *hash,
			 krb5_cryptotype type,
			 size_t *length)
{
    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
	*length = 8;
	break;
    case KRB5_CRYPTO_TYPE_PADDING:
	*length = enc->block_size;
	break;
    case KRB5_CRYPTO_TYPE_TRAILER:
    case KRB5_CRYPTO_TYPE_CHECKSUM:
	*length = hash->hashsize;
	break;
    default:
	assert(0 && "invalid cryptotype passed to krb5int_dk_crypto_length");
	break;
    }

    return 0;
}

const struct krb5_aead_provider krb5int_aead_dk = {
    krb5int_dk_crypto_length,
    NULL,
    NULL
};

static krb5_error_code
krb5int_aes_crypto_length(const struct krb5_aead_provider *aead,
			 const struct krb5_enc_provider *enc,
			 const struct krb5_hash_provider *hash,
			 krb5_cryptotype type,
			 size_t *length)
{
    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
	*length = enc->block_size;
	break;
    case KRB5_CRYPTO_TYPE_PADDING:
	*length = 0;
	break;
    case KRB5_CRYPTO_TYPE_TRAILER:
    case KRB5_CRYPTO_TYPE_CHECKSUM:
	*length = hash->hashsize;
	break;
    default:
	assert(0 && "invalid cryptotype passed to krb5int_aes_crypto_length");
	break;
    }

    return 0;
}

const struct krb5_aead_provider krb5int_aead_aes = {
    krb5int_aes_crypto_length,
    NULL,
    NULL
};

