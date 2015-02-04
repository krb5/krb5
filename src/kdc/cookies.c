/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kdc/cookie.c - Secure Cookies */
/*
 * Copyright 2015 Red Hat, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "cookies.h"

#include <kdb.h>

/* Number from internal use reserved; see RFC 4120 7.5.1. */
#define KEYUSAGE_PA_FX_COOKIE 513

/* Let cookies be valid for one hour. */
#define COOKIE_LIFETIME 3600

static krb5_error_code
load_key(krb5_context context, krb5_const_principal server,
         krb5_enctype etype, krb5_keyblock **key)
{
    krb5_db_entry *entry = NULL;
    krb5_key_data *kdata = NULL;
    krb5_error_code retval = 0;
    krb5_keyblock kblock = {};
    krb5_int32 start = 0;

    /* Look up the server's principal. */
    retval = krb5_db_get_principal(context, server,
                                   KRB5_KDB_FLAG_ALIAS_OK, &entry);
    if (retval != 0)
        return retval;

    /* Find the key with the specified enctype. */
    retval = krb5_dbe_search_enctype(context, entry, &start,
                                     etype, -1, 0, &kdata);
    /* Valgrind tells me that entry leaks here.
     * What function should I use to free it? */
    if (retval != 0)
        return retval;

    /* Decrypt the key. */
    retval = krb5_dbe_decrypt_key_data(context, NULL, kdata, &kblock, NULL);
    if (retval != 0)
        return retval;

    /* Copy the keyblock. */
    retval = krb5_copy_keyblock(context, &kblock, key);
    krb5_free_keyblock_contents(context, &kblock);
    return retval;
}

static krb5_error_code
cookie_decrypt(krb5_context context, const krb5_keyblock *key,
               krb5_timestamp now, const krb5_enc_data *ed,
               krb5_pa_data *padata)
{
    krb5_secure_cookie *sc = NULL;
    krb5_error_code retval = 0;
    krb5_data pt = {};

    /* Prepare input for decryption. */
    pt.length = ed->ciphertext.length;
    pt.data = malloc(pt.length);
    if (pt.data == NULL)
        return ENOMEM;

    /* Perform decryption. */
    retval = krb5_c_decrypt(context, key, KEYUSAGE_PA_FX_COOKIE,
                            NULL, ed, &pt);
    if (retval != 0) {
        krb5_free_data_contents(context, &pt);
        return retval;
    }

    /* Decode the cookie. */
    retval = decode_krb5_secure_cookie(&pt, &sc);
    krb5_free_data_contents(context, &pt);
    if (retval != 0)
        return retval;

    /* Determine if the cookie is expired. */
    if (sc->time + COOKIE_LIFETIME < now) {
        free(sc->data.contents);
        free(sc);
        return ETIMEDOUT;
    }

    free(padata->contents);
    *padata = sc->data;
    free(sc);
    return 0;
}

static krb5_error_code
cookie_encrypt(krb5_context context, const krb5_keyblock *key,
               krb5_timestamp now, krb5_pa_data *padata)
{
    krb5_secure_cookie cookie = { .time = now, .data = *padata };
    krb5_error_code retval = 0;
    krb5_enc_data ct = {};
    krb5_data *pt = NULL;
    krb5_data *ed = NULL;
    size_t ctlen;

    /* Encode the cookie with a timestamp. */
    retval = encode_krb5_secure_cookie(&cookie, &pt);
    if (retval != 0)
        return retval;

    /* Find out how much buffer to allocate. */
    retval = krb5_c_encrypt_length(context, key->enctype,
                                   pt->length, &ctlen);
    if (retval != 0) {
        krb5_free_data(context, pt);
        return retval;
    }

    /* Allocate the output buffer. */
    ct.ciphertext.length = ctlen;
    ct.ciphertext.data = malloc(ctlen);
    if (ct.ciphertext.data == NULL) {
        krb5_free_data(context, pt);
        retval = ENOMEM;
        return retval;
    }

    /* Perform the encryption. */
    retval = krb5_c_encrypt(context, key, KEYUSAGE_PA_FX_COOKIE,
                            NULL, pt, &ct);
    krb5_free_data(context, pt);
    if (retval != 0) {
        free(ct.ciphertext.data);
        return retval;
    }

    /* Encode to EncryptedData. */
    retval = encode_krb5_enc_data(&ct, &ed);
    free(ct.ciphertext.data);
    if (retval != 0)
        return retval;

    /* Set the encryption in the cookie. */
    free(padata->contents);
    padata->contents = (krb5_octet *)ed->data;
    padata->length = ed->length;
    ed->data = NULL;
    krb5_free_data(context, ed);
    return 0;
}

krb5_error_code
cookies_decrypt(krb5_context context, krb5_const_principal princ,
                krb5_pa_data **padata)
{
    krb5_error_code retval = 0;
    krb5_keyblock *key = NULL;
    krb5_enc_data *ed = NULL;
    krb5_timestamp now = 0;
    size_t i;

    /* Get the time. */
    retval = krb5_timeofday(context, &now);
    if (retval != 0)
        return retval;

    for (i = 0; padata[i] != NULL; i++) {
        krb5_data pt = {
            .data = (char *)padata[i]->contents,
            .length = padata[i]->length
        };

        if (padata[i]->pa_type != KRB5_PADATA_FX_COOKIE)
            continue;

        /* Parse the incoming data. */
        krb5_free_enc_data(context, ed);
        ed = NULL;
        retval = decode_krb5_enc_data(&pt, &ed);
        if (retval != 0)
            break;

        /* Find a key. */
        retval = load_key(context, princ, ed->enctype, &key);
        if (retval != 0)
            break;

        /* Decrypt the cookie. */
        retval = cookie_decrypt(context, key, now, ed, padata[i]);
        krb5_free_keyblock(context, key);
        if (retval != 0)
            break;
    }

    krb5_free_enc_data(context, ed);
    return retval;
}

krb5_error_code
cookies_encrypt(krb5_context context, krb5_const_principal princ,
                krb5_pa_data **padata)
{
    krb5_error_code retval = 0;
    krb5_keyblock *key = NULL;
    krb5_timestamp now = 0;
    size_t i;

    retval = krb5_timeofday(context, &now);
    if (retval != 0)
        return retval;

    for (i = 0; padata[i] != NULL; i++) {
        if (padata[i]->pa_type != KRB5_PADATA_FX_COOKIE)
            continue;

        if (key == NULL) {
            retval = load_key(context, princ, -1, &key);
            if (retval != 0)
                break;
        }

        retval = cookie_encrypt(context, key, now, padata[i]);
        if (retval != 0)
            break;
    }

    krb5_free_keyblock(context, key);
    return retval;
}
