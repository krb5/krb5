/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/krb/cf2.c */
/*
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
 */

/*
 * Implement KRB_FX_CF2 function per draft-ietf-krb-wg-preauth-framework-09.
 * Take two keys and two pepper strings as input and return a combined key.
 */

#include "crypto_int.h"

krb5_error_code KRB5_CALLCONV
krb5_c_prfplus(krb5_context context, const krb5_keyblock *k,
               const krb5_data *input, krb5_data *output)
{
    krb5_error_code retval = 0;
    size_t prflen = 0;
    krb5_data out;
    krb5_data in;

    retval = krb5_c_prf_length(context, k->enctype, &prflen);
    if (retval)
        return retval;

    out = make_data(malloc(prflen), prflen);
    in = make_data(malloc(input->length + 1), input->length + 1);
    retval = (in.data == NULL || out.data == NULL) ? ENOMEM : 0;
    if (retval)
        goto cleanup;

    retval = (output->length > 254 * prflen) ? E2BIG : 0;
    if (retval)
        goto cleanup;

    memcpy(&in.data[1], input->data, input->length);
    for (size_t i = 0; i < (output->length + prflen - 1) / prflen; i++) {
        in.data[0] = i + 1;
        retval = krb5_c_prf(context, k, &in, &out);
        if (retval)
            goto cleanup;

        memcpy(&output->data[i * prflen], out.data,
               MIN(prflen, output->length - i * prflen));
    }

cleanup:
    zapfree(out.data, out.length);
    zapfree(in.data, in.length);
    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_c_derive_prfplus(krb5_context context, const krb5_keyblock *k,
                      const krb5_data *input, krb5_enctype enctype,
                      krb5_keyblock **output)
{
    const struct krb5_keytypes *etype = NULL;
    krb5_error_code retval = 0;
    krb5_data rnd = {};

    if (enctype == 0)
        enctype = k->enctype;

    if (!krb5_c_valid_enctype(enctype))
        return KRB5_BAD_ENCTYPE;

    etype = find_enctype(enctype);
    if (etype == NULL)
        return KRB5_BAD_ENCTYPE;

    rnd = make_data(malloc(etype->enc->keybytes), etype->enc->keybytes);
    if (rnd.data == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }

    retval = krb5_c_prfplus(context, k, input, &rnd);
    if (retval != 0)
        goto cleanup;

    retval = krb5int_c_init_keyblock(context, etype->etype,
                                     etype->enc->keylength, output);
    if (retval != 0)
        goto cleanup;

    retval = (*etype->rand2key)(&rnd, *output);
    if (retval != 0)
        krb5int_c_free_keyblock(context, *output);

cleanup:
    zapfree(rnd.data, rnd.length);
    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_c_fx_cf2_simple(krb5_context context,
                     const krb5_keyblock *k1, const char *pepper1,
                     const krb5_keyblock *k2, const char *pepper2,
                     krb5_keyblock **out)
{
    const krb5_data p1 = { 0, strlen(pepper1), (char *) pepper1 };
    const krb5_data p2 = { 0, strlen(pepper2), (char *) pepper2 };
    const struct krb5_keytypes *etype = NULL;
    krb5_error_code retval = 0;
    krb5_data prf1;
    krb5_data prf2;

    if (!krb5_c_valid_enctype(k1->enctype))
        return KRB5_BAD_ENCTYPE;

    etype = find_enctype(k1->enctype);
    if (etype == NULL)
        return KRB5_BAD_ENCTYPE;

    prf1 = make_data(malloc(etype->enc->keybytes), etype->enc->keybytes);
    prf2 = make_data(malloc(etype->enc->keybytes), etype->enc->keybytes);
    if (prf1.data == NULL || prf2.data == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }

    retval = krb5_c_prfplus(context, k1, &p1, &prf1);
    if (retval)
        goto cleanup;

    retval = krb5_c_prfplus(context, k2, &p2, &prf2);
    if (retval)
        goto cleanup;

    for (size_t i = 0; i < prf1.length; i++)
        prf1.data[i] ^= prf2.data[i];

    retval = krb5int_c_init_keyblock(context, etype->etype,
                                     etype->enc->keylength, out);
    if (retval != 0)
        goto cleanup;

    retval = (*etype->rand2key)(&prf1, *out);
    if (retval != 0)
        krb5int_c_free_keyblock(context, *out);

cleanup:
    zapfree(prf2.data, prf2.length);
    zapfree(prf1.data, prf1.length);
    return retval;
}
