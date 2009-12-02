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
#include "etypes.h"
#include "dk.h"

/* A 0 checksum type means use the mandatory checksum*/

krb5_error_code KRB5_CALLCONV
krb5_k_make_checksum(krb5_context context, krb5_cksumtype cksumtype,
                     krb5_key key, krb5_keyusage usage,
                     const krb5_data *input, krb5_checksum *cksum)
{
    unsigned int i;
    const struct krb5_cksumtypes *ctp;
    const struct krb5_keytypes *ktp1, *ktp2;
    const struct krb5_keyhash_provider *keyhash;
    krb5_data data;
    krb5_octet *trunc;
    krb5_error_code ret;
    size_t cksumlen;

    if (cksumtype == 0) {
        ret = krb5int_c_mandatory_cksumtype(context, krb5_k_key_enctype(context, key), &cksumtype);
        if (ret != 0)
            return ret;
    }

    for (i = 0; i < krb5int_cksumtypes_length; i++) {
        if (krb5int_cksumtypes_list[i].ctype == cksumtype)
            break;
    }
    if (i == krb5int_cksumtypes_length)
        return KRB5_BAD_ENCTYPE;
    ctp = &krb5int_cksumtypes_list[i];

    if (ctp->keyhash != NULL)
        cksumlen = ctp->keyhash->hashsize;
    else
        cksumlen = ctp->hash->hashsize;

    cksum->length = cksumlen;
    cksum->checksum_type = cksumtype;
    cksum->contents = malloc(cksum->length);
    if (cksum->contents == NULL)
        return ENOMEM;

    data.length = cksum->length;
    data.data = (char *) cksum->contents;

    if (ctp->keyhash) {
        /* check if key is compatible */
        if (ctp->keyed_etype) {
            ktp1 = find_enctype(ctp->keyed_etype);
            ktp2 = key ? find_enctype(key->keyblock.enctype) : NULL;
            if (ktp1 == NULL || ktp2 == NULL || ktp1->enc != ktp2->enc) {
                ret = KRB5_BAD_ENCTYPE;
                goto cleanup;
            }
        }

        keyhash = ctp->keyhash;
        if (keyhash->hash == NULL) {
            krb5_crypto_iov iov[1];

            iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
            iov[0].data.data = input->data;
            iov[0].data.length = input->length;

            assert(keyhash->hash_iov != NULL);

            ret = (*keyhash->hash_iov)(key, usage, 0, iov, 1, &data);
        } else {
            ret = (*keyhash->hash)(key, usage, 0, input, &data);
        }
    } else if (ctp->flags & KRB5_CKSUMFLAG_DERIVE) {
        ret = krb5int_dk_make_checksum(ctp->hash, key, usage, input, &data);
    } else {
        /* No key is used. */
        ret = (*ctp->hash->hash)(1, input, &data);
    }

    if (!ret) {
        cksum->magic = KV5M_CHECKSUM;
        cksum->checksum_type = cksumtype;
        if (ctp->trunc_size) {
            cksum->length = ctp->trunc_size;
            trunc = realloc(cksum->contents, cksum->length);
            if (trunc)
                cksum->contents = trunc;
        }
    }

cleanup:
    if (ret) {
        zapfree(cksum->contents, cksum->length);
        cksum->contents = NULL;
    }

    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_c_make_checksum(krb5_context context, krb5_cksumtype cksumtype,
                     const krb5_keyblock *keyblock, krb5_keyusage usage,
                     const krb5_data *input, krb5_checksum *cksum)
{
    krb5_key key = NULL;
    krb5_error_code ret;

    if (keyblock != NULL) {
        ret = krb5_k_create_key(context, keyblock, &key);
        if (ret != 0)
            return ret;
    }
    ret = krb5_k_make_checksum(context, cksumtype, key, usage, input, cksum);
    krb5_k_free_key(context, key);
    return ret;
}
