/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/openssl/pbkdf2.c */
/*
 * Copyright 2002, 2008, 2009 by the Massachusetts Institute of Technology.
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

#include "crypto_int.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

krb5_error_code
krb5int_pbkdf2_hmac_sha1 (const krb5_data *out, unsigned long count,
                          const krb5_data *pass, const krb5_data *salt)
{
/*
 * This is an implementation of PKCS#5 v2.0
 * Does not return an error
 */
    PKCS5_PBKDF2_HMAC_SHA1(pass->data, pass->length,
                           (unsigned char *)salt->data, salt->length, count,
                           out->length, (unsigned char *)out->data);
    return 0;
}
