/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "etypes.h"
#include "dk.h"
#include "aead.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

krb5_error_code
krb5int_dk_make_checksum(const struct krb5_hash_provider *hash,
                         krb5_key key, krb5_keyusage usage,
                         const krb5_data *input, krb5_data *output)
{
    const struct krb5_keytypes *ktp;
    const struct krb5_enc_provider *enc;
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data datain;
    krb5_key kc;

    ktp = find_enctype(key->keyblock.enctype);
    if (ktp == NULL)
        return KRB5_BAD_ENCTYPE;
    enc = ktp->enc;

    /*
     * key->length will be tested in enc->encrypt.
     * output->length will be tested in krb5int_hmac.
     */

    /* Derive the key. */

    datain.data = (char *) constantdata;
    datain.length = K5CLENGTH;

    store_32_be(usage, constantdata);

    datain.data[4] = (char) 0x99;

    ret = krb5int_derive_key(enc, key, &kc, &datain);
    if (ret)
        return ret;

    /* hash the data */

    datain = *input;

    ret = krb5int_hmac(hash, kc, 1, &datain, output);
    if (ret)
        memset(output->data, 0, output->length);

    krb5_k_free_key(NULL, kc);
    return ret;
}

krb5_error_code
krb5int_dk_make_checksum_iov(const struct krb5_hash_provider *hash,
                             krb5_key key, krb5_keyusage usage,
                             const krb5_crypto_iov *data, size_t num_data,
                             krb5_data *output)
{
    const struct krb5_keytypes *ktp;
    const struct krb5_enc_provider *enc;
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data datain;
    krb5_key kc;

    ktp = find_enctype(key->keyblock.enctype);
    if (ktp == NULL)
        return KRB5_BAD_ENCTYPE;
    enc = ktp->enc;

    /*
     * key->length will be tested in enc->encrypt.
     * output->length will be tested in krb5int_hmac.
     */

    /* Derive the key. */

    datain.data = (char *) constantdata;
    datain.length = K5CLENGTH;

    store_32_be(usage, constantdata);

    datain.data[4] = (char) 0x99;

    ret = krb5int_derive_key(enc, key, &kc, &datain);
    if (ret)
        return ret;

    /* Hash the data. */

    ret = krb5int_hmac_iov(hash, kc, data, num_data, output);
    if (ret)
        memset(output->data, 0, output->length);

    krb5_k_free_key(NULL, kc);
    return ret;
}
