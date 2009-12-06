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
#include "cksumtypes.h"

krb5_error_code KRB5_CALLCONV
krb5_k_verify_checksum(krb5_context context, krb5_key key,
                       krb5_keyusage usage, const krb5_data *data,
                       const krb5_checksum *cksum, krb5_boolean *valid)
{
    unsigned int i;
    const struct krb5_cksumtypes *ctp;
    const struct krb5_keyhash_provider *keyhash;
    size_t hashsize;
    krb5_error_code ret;
    krb5_data indata;
    krb5_checksum computed;

    for (i=0; i<krb5int_cksumtypes_length; i++) {
        if (krb5int_cksumtypes_list[i].ctype == cksum->checksum_type)
            break;
    }
    if (i == krb5int_cksumtypes_length)
        return KRB5_BAD_ENCTYPE;
    ctp = &krb5int_cksumtypes_list[i];

    indata.length = cksum->length;
    indata.data = (char *) cksum->contents;

    /* If there's actually a verify function, call it. */
    if (ctp->keyhash) {
        keyhash = ctp->keyhash;

        if (keyhash->verify == NULL && keyhash->verify_iov != NULL) {
            krb5_crypto_iov iov[1];

            iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
            iov[0].data.data = data->data;
            iov[0].data.length = data->length;

            return (*keyhash->verify_iov)(key, usage, iov, 1, &indata, valid);
        } else if (keyhash->verify != NULL) {
            return (*keyhash->verify)(key, usage, data, &indata, valid);
        }
    }

    /* Otherwise, make the checksum again, and compare. */
    ret = krb5_c_checksum_length(context, cksum->checksum_type, &hashsize);
    if (ret)
        return ret;

    if (cksum->length != hashsize)
        return KRB5_BAD_MSIZE;

    computed.length = hashsize;

    ret = krb5_k_make_checksum(context, cksum->checksum_type, key, usage,
                               data, &computed);
    if (ret)
        return ret;

    *valid = (memcmp(computed.contents, cksum->contents, hashsize) == 0);

    free(computed.contents);
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_c_verify_checksum(krb5_context context, const krb5_keyblock *keyblock,
                       krb5_keyusage usage, const krb5_data *data,
                       const krb5_checksum *cksum, krb5_boolean *valid)
{
    krb5_key key = NULL;
    krb5_error_code ret;

    if (keyblock != NULL) {
        ret = krb5_k_create_key(context, keyblock, &key);
        if (ret != 0)
            return ret;
    }
    ret = krb5_k_verify_checksum(context, key, usage, data, cksum, valid);
    krb5_k_free_key(context, key);
    return ret;
}
