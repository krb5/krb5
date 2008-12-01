/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * Copyright2001 by the Massachusetts Institute of Technology.
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

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
#include "gssapiP_krb5.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

int
kg_confounder_size(context, key)
    krb5_context context;
    krb5_keyblock *key;
{
    krb5_error_code code;
    size_t blocksize;
    /* We special case rc4*/
    if (key->enctype == ENCTYPE_ARCFOUR_HMAC)
        return 8;
    code = krb5_c_block_size(context, key->enctype, &blocksize);
    if (code)
        return(-1); /* XXX */

    return(blocksize);
}

krb5_error_code
kg_make_confounder(context, key, buf)
    krb5_context context;
    krb5_keyblock *key;
    unsigned char *buf;
{
    krb5_error_code code;
    size_t blocksize;
    krb5_data lrandom;

    code = krb5_c_block_size(context, key->enctype, &blocksize);
    if (code)
        return(code);

    lrandom.length = blocksize;
    lrandom.data = buf;

    return(krb5_c_random_make_octets(context, &lrandom));
}

krb5_error_code
kg_encrypt(context, key, usage, iv, in, out, length)
    krb5_context context;
    krb5_keyblock *key;
    int usage;
    krb5_pointer iv;
    krb5_const_pointer in;
    krb5_pointer out;
    unsigned int length;
{
    krb5_error_code code;
    size_t blocksize;
    krb5_data ivd, *pivd, inputd;
    krb5_enc_data outputd;

    if (iv) {
        code = krb5_c_block_size(context, key->enctype, &blocksize);
        if (code)
            return(code);

        ivd.length = blocksize;
        ivd.data = malloc(ivd.length);
        if (ivd.data == NULL)
            return ENOMEM;
        memcpy(ivd.data, iv, ivd.length);
        pivd = &ivd;
    } else {
        pivd = NULL;
    }

    inputd.length = length;
    inputd.data = in;

    outputd.ciphertext.length = length;
    outputd.ciphertext.data = out;

    code = krb5_c_encrypt(context, key, usage, pivd, &inputd, &outputd);
    if (pivd != NULL)
        free(pivd->data);
    return code;
}

/* length is the length of the cleartext. */

krb5_error_code
kg_decrypt(context, key, usage, iv, in, out, length)
    krb5_context context;
    krb5_keyblock *key;
    int usage;
    krb5_pointer iv;
    krb5_const_pointer in;
    krb5_pointer out;
    unsigned int length;
{
    krb5_error_code code;
    size_t blocksize;
    krb5_data ivd, *pivd, outputd;
    krb5_enc_data inputd;

    if (iv) {
        code = krb5_c_block_size(context, key->enctype, &blocksize);
        if (code)
            return(code);

        ivd.length = blocksize;
        ivd.data = malloc(ivd.length);
        if (ivd.data == NULL)
            return ENOMEM;
        memcpy(ivd.data, iv, ivd.length);
        pivd = &ivd;
    } else {
        pivd = NULL;
    }

    inputd.enctype = ENCTYPE_UNKNOWN;
    inputd.ciphertext.length = length;
    inputd.ciphertext.data = in;

    outputd.length = length;
    outputd.data = out;

    code = krb5_c_decrypt(context, key, usage, pivd, &inputd, &outputd);
    if (pivd != NULL)
        free(pivd->data);
    return code;
}

krb5_error_code
kg_arcfour_docrypt (const krb5_keyblock *longterm_key , int ms_usage,
                    const unsigned char *kd_data, size_t kd_data_len,
                    const unsigned char *input_buf, size_t input_len,
                    unsigned char *output_buf)
{
    krb5_error_code code;
    krb5_data input, output;
    krb5int_access kaccess;
    krb5_keyblock seq_enc_key, usage_key;
    unsigned char t[4];

    usage_key.length = longterm_key->length;
    usage_key.contents = malloc(usage_key.length);
    if (usage_key.contents == NULL)
        return (ENOMEM);
    seq_enc_key.length = longterm_key->length;
    seq_enc_key.contents = malloc(seq_enc_key.length);
    if (seq_enc_key.contents == NULL) {
        free ((void *) usage_key.contents);
        return (ENOMEM);
    }
    code = krb5int_accessor (&kaccess, KRB5INT_ACCESS_VERSION);
    if (code)
        goto cleanup_arcfour;

    t[0] = ms_usage &0xff;
    t[1] = (ms_usage>>8) & 0xff;
    t[2] = (ms_usage>>16) & 0xff;
    t[3] = (ms_usage>>24) & 0xff;
    input.data = (void *) &t;
    input.length = 4;
    output.data = (void *) usage_key.contents;
    output.length = usage_key.length;
    code = (*kaccess.krb5_hmac) (kaccess.md5_hash_provider,
                                 longterm_key, 1, &input, &output);
    if (code)
        goto cleanup_arcfour;

    input.data = ( void *) kd_data;
    input.length = kd_data_len;
    output.data = (void *) seq_enc_key.contents;
    code = (*kaccess.krb5_hmac) (kaccess.md5_hash_provider,
                                 &usage_key, 1, &input, &output);
    if (code)
        goto cleanup_arcfour;
    input.data = ( void * ) input_buf;
    input.length = input_len;
    output.data = (void * ) output_buf;
    output.length = input_len;
    code =  ((*kaccess.arcfour_enc_provider->encrypt)(
                 &seq_enc_key, 0,
                 &input, &output));
cleanup_arcfour:
    memset ((void *) seq_enc_key.contents, 0, seq_enc_key.length);
    memset ((void *) usage_key.contents, 0, usage_key.length);
    free ((void *) usage_key.contents);
    free ((void *) seq_enc_key.contents);
    return (code);
}
