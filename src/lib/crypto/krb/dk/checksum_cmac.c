/*
 * lib/crypto/krb/dk/checksum_cmac.c
 *
 * Copyright 2010 by the Massachusetts Institute of Technology.
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
#include "dk.h"
#include "aead.h"
#include "cksumtypes.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

krb5_error_code
krb5int_dk_cmac_checksum(const struct krb5_cksumtypes *ctp,
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

    /* Use the key's enctype (more flexible than setting an enctype in ctp). */
    ktp = find_enctype(key->keyblock.enctype);
    if (ktp == NULL)
        return KRB5_BAD_ENCTYPE;
    enc = ktp->enc;
    if (key->keyblock.length != enc->keylength)
        return KRB5_BAD_KEYSIZE;
    if (ctp->compute_size != enc->block_size)
        return KRB5_BAD_MSIZE;

    /* Derive the key. */
    datain = make_data(constantdata, K5CLENGTH);
    store_32_be(usage, constantdata);
    constantdata[4] = (char) 0x99;
    ret = krb5int_derive_key(enc, key, &kc, &datain);
    if (ret != 0)
        return ret;

    /* Hash the data. */
    ret = krb5int_cmac_checksum(enc, kc, data, num_data, output);
    if (ret != 0)
        memset(output->data, 0, output->length);

    krb5_k_free_key(NULL, kc);
    return ret;
}

