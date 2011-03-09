/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/enc_provider/rc4.c */
/*
 * Copyright (c) 2010 Red Hat, Inc.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 *  * Neither the name of Red Hat, Inc., nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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

#include "crypto_int.h"
#include "nss_gen.h"

#define RC4_KEY_SIZE 16
#define RC4_BLOCK_SIZE 1

/* In-place IOV crypto */
static krb5_error_code
k5_arcfour_encrypt_iov(krb5_key key, const krb5_data *state,
                       krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret;

    ret = k5_nss_gen_import(key, CKM_RC4, CKA_ENCRYPT);
    if (ret != 0)
        return ret;
    return k5_nss_gen_stream_iov(key, state, CKM_RC4, CKA_ENCRYPT,
                                 data, num_data);
}

/* In-place IOV crypto */
static krb5_error_code
k5_arcfour_decrypt_iov(krb5_key key, const krb5_data *state,
                       krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret;

    ret = k5_nss_gen_import(key, CKM_RC4, CKA_DECRYPT);
    if (ret != 0)
        return ret;
    return k5_nss_gen_stream_iov(key, state, CKM_RC4, CKA_DECRYPT,
                                 data, num_data);
}

static void
k5_arcfour_free_state(krb5_data *state)
{
    (void)k5_nss_stream_free_state(state);
}

static krb5_error_code
k5_arcfour_init_state(const krb5_keyblock *key,
                      krb5_keyusage keyusage, krb5_data *new_state)
{
    /* key can't quite be used here.  See comment in k5_arcfour_init_state. */
    return k5_nss_stream_init_state(new_state);
}

const struct krb5_enc_provider krb5int_enc_arcfour = {
    /* This seems to work... although I am not sure what the
       implications are in other places in the kerberos library. */
    RC4_BLOCK_SIZE,
    /* Keysize is arbitrary in arcfour, but the constraints of the
       system, and to attempt to work with the MSFT system forces us
       to 16byte/128bit.  Since there is no parity in the key, the
       byte and length are the same.  */
    RC4_KEY_SIZE, RC4_KEY_SIZE,
    k5_arcfour_encrypt_iov,
    k5_arcfour_decrypt_iov,
    NULL,
    k5_arcfour_init_state,
    k5_arcfour_free_state,
    k5_nss_gen_cleanup
};
