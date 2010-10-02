/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/enc_provider/des.c
 *
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

#include "k5-int.h"
#include "nss_gen.h"
#include <aead.h>
#include <rand2key.h>
#include "des_int.h"


static krb5_error_code
k5_des_encrypt_iov(krb5_key key, const krb5_data *ivec,
                   krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret;

    ret = k5_nss_gen_import(key, CKM_DES_CBC, CKA_ENCRYPT);
    if (ret != 0)
        return ret;
    return k5_nss_gen_block_iov(key, CKM_DES_CBC, CKA_ENCRYPT,
                                ivec, data, num_data);
}

static krb5_error_code
k5_des_decrypt_iov(krb5_key key,
           const krb5_data *ivec,
           krb5_crypto_iov *data,
           size_t num_data)
{
    krb5_error_code ret;

    ret = k5_nss_gen_import(key, CKM_DES_CBC, CKA_ENCRYPT);
    if (ret != 0)
        return ret;
    return k5_nss_gen_block_iov(key, CKM_DES_CBC, CKA_DECRYPT,
                                ivec, data, num_data);
}

const struct krb5_enc_provider krb5int_enc_des = {
    8,
    7, KRB5_MIT_DES_KEYSIZE,
    k5_des_encrypt_iov,
    k5_des_decrypt_iov,
    NULL,
    krb5int_des_make_key,
    krb5int_des_init_state,
    krb5int_default_free_state,
    k5_nss_gen_cleanup
};
