/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/cf2.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 *
 *
 *
 * Implement KRB_FX_CF2 function per
 *draft-ietf-krb-wg-preauth-framework-09.  Take two keys and two
 *pepper strings as input and return a combined key.
 */

#include <k5-int.h>
#include <assert.h>
#include "etypes.h"


/*
 * Call the PRF function multiple times with the pepper prefixed with
 * a count byte  to get enough bits of output.
 */
static krb5_error_code
prf_plus(krb5_context context, krb5_keyblock *k, const char *pepper,
         size_t keybytes, char **out)
{
    krb5_error_code retval = 0;
    size_t prflen, iterations;
    krb5_data out_data;
    krb5_data in_data;
    char *buffer = NULL;
    struct k5buf prf_inbuf;

    krb5int_buf_init_dynamic(&prf_inbuf);
    krb5int_buf_add_len(&prf_inbuf, "\001", 1);
    krb5int_buf_add(&prf_inbuf, pepper);
    retval = krb5_c_prf_length( context, k->enctype, &prflen);
    if (retval)
        goto cleanup;
    iterations = keybytes / prflen;
    if (keybytes % prflen != 0)
        iterations++;
    assert(iterations <= 254);
    buffer = k5alloc(iterations * prflen, &retval);
    if (retval)
        goto cleanup;
    if (krb5int_buf_len(&prf_inbuf) == -1) {
        retval = ENOMEM;
        goto cleanup;
    }
    in_data.length = (krb5_int32) krb5int_buf_len(&prf_inbuf);
    in_data.data = krb5int_buf_data(&prf_inbuf);
    out_data.length = prflen;
    out_data.data = buffer;

    while (iterations > 0) {
        retval = krb5_c_prf(context, k, &in_data, &out_data);
        if (retval)
            goto cleanup;
        out_data.data += prflen;
        in_data.data[0]++;
        iterations--;
    }

    *out = buffer;
    buffer = NULL;

cleanup:
    free(buffer);
    krb5int_free_buf(&prf_inbuf);
    return retval;
}


krb5_error_code KRB5_CALLCONV
krb5_c_fx_cf2_simple(krb5_context context,
                     krb5_keyblock *k1, const char *pepper1,
                     krb5_keyblock *k2, const char *pepper2,
                     krb5_keyblock **out)
{
    const struct krb5_keytypes *out_enctype;
    size_t keybytes, keylength, i;
    char *prf1 = NULL, *prf2 = NULL;
    krb5_data keydata;
    krb5_enctype out_enctype_num;
    krb5_error_code retval = 0;
    krb5_keyblock *out_key = NULL;

    if (k1 == NULL || !krb5_c_valid_enctype(k1->enctype))
        return KRB5_BAD_ENCTYPE;
    if (k2 == NULL || !krb5_c_valid_enctype(k2->enctype))
        return KRB5_BAD_ENCTYPE;
    out_enctype_num = k1->enctype;
    assert(out != NULL);
    assert((out_enctype = find_enctype(out_enctype_num)) != NULL);
    if (out_enctype->prf == NULL) {
        if (context)
            krb5int_set_error(&(context->err), KRB5_CRYPTO_INTERNAL,
                              "Enctype %d has no PRF", out_enctype_num);
        return KRB5_CRYPTO_INTERNAL;
    }
    keybytes = out_enctype->enc->keybytes;
    keylength = out_enctype->enc->keylength;

    retval = prf_plus(context, k1, pepper1, keybytes, &prf1);
    if (retval)
        goto cleanup;
    retval = prf_plus(context, k2, pepper2, keybytes, &prf2);
    if (retval)
        goto cleanup;
    for (i = 0; i < keybytes; i++)
        prf1[i] ^= prf2[i];
    retval = krb5int_c_init_keyblock(context, out_enctype_num, keylength,
                                     &out_key);
    if (retval)
        goto cleanup;
    keydata.data = prf1;
    keydata.length = keybytes;
    retval = (*out_enctype->enc->make_key)(&keydata, out_key);
    if (retval)
        goto cleanup;

    *out = out_key;
    out_key = NULL;

cleanup:
    krb5int_c_free_keyblock( context, out_key);
    zapfree(prf1, keybytes);
    zapfree(prf2, keybytes);
    return retval;
}
