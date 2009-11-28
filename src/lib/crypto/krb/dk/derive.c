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
#include "dk.h"

static krb5_key
find_cached_dkey(struct derived_key *list, const krb5_data *constant)
{
    for (; list; list = list->next) {
        if (data_eq(list->constant, *constant)) {
            krb5_k_reference_key(NULL, list->dkey);
            return list->dkey;
        }
    }
    return NULL;
}

static krb5_error_code
add_cached_dkey(krb5_key key, const krb5_data *constant,
                const krb5_keyblock *dkeyblock, krb5_key *cached_dkey)
{
    krb5_key dkey;
    krb5_error_code ret;
    struct derived_key *dkent = NULL;
    char *data = NULL;

    /* Allocate fields for the new entry. */
    dkent = malloc(sizeof(*dkent));
    if (dkent == NULL)
        goto cleanup;
    data = malloc(constant->length);
    if (data == NULL)
        goto cleanup;
    ret = krb5_k_create_key(NULL, dkeyblock, &dkey);
    if (ret != 0)
        goto cleanup;

    /* Add the new entry to the list. */
    memcpy(data, constant->data, constant->length);
    dkent->dkey = dkey;
    dkent->constant.data = data;
    dkent->constant.length = constant->length;
    dkent->next = key->derived;
    key->derived = dkent;

    /* Return a "copy" of the cached key. */
    krb5_k_reference_key(NULL, dkey);
    *cached_dkey = dkey;
    return 0;

cleanup:
    free(dkent);
    free(data);
    return ENOMEM;
}

/*
 * Compute a derived key into the keyblock outkey.  This variation on
 * krb5int_derive_key does not cache the result, as it is only used
 * directly in situations which are not expected to be repeated with
 * the same inkey and constant.
 */
krb5_error_code
krb5int_derive_keyblock(const struct krb5_enc_provider *enc,
                        krb5_key inkey, krb5_keyblock *outkey,
                        const krb5_data *in_constant)
{
    size_t blocksize, keybytes, n;
    unsigned char *inblockdata = NULL, *outblockdata = NULL, *rawkey = NULL;
    krb5_data inblock, outblock;
    krb5_error_code ret;

    blocksize = enc->block_size;
    keybytes = enc->keybytes;

    if (inkey->keyblock.length != enc->keylength ||
        outkey->length != enc->keylength)
        return KRB5_CRYPTO_INTERNAL;

    /* Allocate and set up buffers. */
    inblockdata = k5alloc(blocksize, &ret);
    if (ret)
        goto cleanup;
    outblockdata = k5alloc(blocksize, &ret);
    if (ret)
        goto cleanup;
    rawkey = k5alloc(keybytes, &ret);
    if (ret)
        goto cleanup;

    inblock.data = (char *) inblockdata;
    inblock.length = blocksize;

    outblock.data = (char *) outblockdata;
    outblock.length = blocksize;

    /* Initialize the input block. */

    if (in_constant->length == inblock.length) {
        memcpy(inblock.data, in_constant->data, inblock.length);
    } else {
        krb5int_nfold(in_constant->length*8, (unsigned char *) in_constant->data,
                      inblock.length*8, (unsigned char *) inblock.data);
    }

    /* Loop encrypting the blocks until enough key bytes are generated */

    n = 0;
    while (n < keybytes) {
        ret = (*enc->encrypt)(inkey, 0, &inblock, &outblock);
        if (ret)
            goto cleanup;

        if ((keybytes - n) <= outblock.length) {
            memcpy(rawkey + n, outblock.data, (keybytes - n));
            break;
        }

        memcpy(rawkey+n, outblock.data, outblock.length);
        memcpy(inblock.data, outblock.data, outblock.length);
        n += outblock.length;
    }

    /* postprocess the key */

    inblock.data = (char *) rawkey;
    inblock.length = keybytes;

    ret = (*enc->make_key)(&inblock, outkey);
    if (ret)
        goto cleanup;

cleanup:
    zapfree(inblockdata, blocksize);
    zapfree(outblockdata, blocksize);
    zapfree(rawkey, keybytes);
    return ret;
}

krb5_error_code
krb5int_derive_key(const struct krb5_enc_provider *enc,
                   krb5_key inkey, krb5_key *outkey,
                   const krb5_data *in_constant)
{
    krb5_keyblock keyblock;
    krb5_error_code ret;
    krb5_key dkey;

    *outkey = NULL;

    /* Check for a cached result. */
    dkey = find_cached_dkey(inkey->derived, in_constant);
    if (dkey != NULL) {
        *outkey = dkey;
        return 0;
    }

    /* Derive into a temporary keyblock. */
    keyblock.length = enc->keylength;
    keyblock.contents = malloc(keyblock.length);
    if (keyblock.contents == NULL)
        return ENOMEM;
    ret = krb5int_derive_keyblock(enc, inkey, &keyblock, in_constant);
    if (ret)
        goto cleanup;

    /* Cache the derived key. */
    ret = add_cached_dkey(inkey, in_constant, &keyblock, &dkey);
    if (ret != 0)
        goto cleanup;

    *outkey = dkey;

cleanup:
    zapfree(keyblock.contents, keyblock.length);
    return ret;
}

krb5_error_code
krb5int_derive_random(const struct krb5_enc_provider *enc,
                      krb5_key inkey, krb5_data *outrnd,
                      const krb5_data *in_constant)
{
    size_t blocksize, keybytes, n;
    unsigned char *inblockdata = NULL, *outblockdata = NULL, *rawkey = NULL;
    krb5_data inblock, outblock;
    krb5_error_code ret;

    blocksize = enc->block_size;
    keybytes = enc->keybytes;

    if (inkey->keyblock.length != enc->keylength || outrnd->length != keybytes)
        return KRB5_CRYPTO_INTERNAL;

    /* Allocate and set up buffers. */

    inblockdata = k5alloc(blocksize, &ret);
    if (ret)
        goto cleanup;
    outblockdata = k5alloc(blocksize, &ret);
    if (ret)
        goto cleanup;
    rawkey = k5alloc(keybytes, &ret);
    if (ret)
        goto cleanup;

    inblock.data = (char *) inblockdata;
    inblock.length = blocksize;

    outblock.data = (char *) outblockdata;
    outblock.length = blocksize;

    /* Initialize the input block. */
    if (in_constant->length == inblock.length) {
        memcpy(inblock.data, in_constant->data, inblock.length);
    } else {
        krb5int_nfold(in_constant->length*8, (unsigned char *) in_constant->data,
                      inblock.length*8, (unsigned char *) inblock.data);
    }

    /* Loop encrypting the blocks until enough key bytes are generated. */
    n = 0;
    while (n < keybytes) {
        ret = (*enc->encrypt)(inkey, 0, &inblock, &outblock);
        if (ret)
            goto cleanup;

        if ((keybytes - n) <= outblock.length) {
            memcpy(rawkey + n, outblock.data, (keybytes - n));
            break;
        }

        memcpy(rawkey+n, outblock.data, outblock.length);
        memcpy(inblock.data, outblock.data, outblock.length);
        n += outblock.length;
    }

    /* Postprocess the key. */
    memcpy(outrnd->data, rawkey, keybytes);

cleanup:
    zapfree(inblockdata, blocksize);
    zapfree(outblockdata, blocksize);
    zapfree(rawkey, keybytes);
    return ret;
}
