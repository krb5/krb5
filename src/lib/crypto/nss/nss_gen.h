/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/nss_gen.h
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
#include "pkcs11t.h"
#include "sechash.h"
#include "secmodt.h"

/* 512 bits is bigger than anything defined to date */
#define MAX_KEY_LENGTH 64
#define MAX_BLOCK_SIZE 64

/*
 * Common nss utils
 */

/* Make sure NSS is properly initialized. */
krb5_error_code k5_nss_init(void);

/* Import a key into NSS and store the handle in krb5_key. */
krb5_error_code
k5_nss_gen_import(krb5_key key, CK_MECHANISM_TYPE mech,
                  CK_ATTRIBUTE_TYPE operation);

/* Clean up an imported key. */
void
k5_nss_gen_cleanup(krb5_key key);

/* Create a new crypto/hash/sign context from a krb5_key. */
PK11Context *
k5_nss_create_context(krb5_key krb_key, CK_MECHANISM_TYPE mechanism,
                      CK_ATTRIBUTE_TYPE operation, SECItem * param);

/* Map an NSS error into a krb5_error_code. */
krb5_error_code k5_nss_map_error(int nss_error);
krb5_error_code k5_nss_map_last_error(void);


/*
 * Common encryption functions
 */

/* Encrypt/decrypt block modes except cts using iov. */
krb5_error_code
k5_nss_gen_block_iov(krb5_key key, CK_MECHANISM_TYPE mech,
                     CK_ATTRIBUTE_TYPE operation, const krb5_data *ivec,
                     krb5_crypto_iov *data, size_t num_data);

/* Encrypt/decrypt stream modes using iov. */
krb5_error_code
k5_nss_gen_stream_iov(krb5_key key, krb5_data *state, CK_MECHANISM_TYPE mech,
                      CK_ATTRIBUTE_TYPE operation, krb5_crypto_iov *data,
                      size_t num_data);

/* Encrypt/decrypt block modes using cts. */
krb5_error_code
k5_nss_gen_cts_iov(krb5_key key, CK_MECHANISM_TYPE mech,
                   CK_ATTRIBUTE_TYPE operation, const krb5_data *ivec,
                   krb5_crypto_iov *data, size_t num_data);

/* Compute a CBC-MAC. */
krb5_error_code
k5_nss_gen_cbcmac_iov(krb5_key key, CK_MECHANISM_TYPE mech,
                      const krb5_data *ivec, const krb5_crypto_iov *data,
                      size_t num_data, krb5_data *output);

/* Stream state management calls. */
krb5_error_code k5_nss_stream_init_state(krb5_data *new_state);
krb5_error_code k5_nss_stream_free_state(krb5_data *state);

/*
 * Common hash functions
 */

/* All hash modes. */
krb5_error_code
k5_nss_gen_hash(HASH_HashType hashType, const krb5_crypto_iov *data,
                size_t num_data, krb5_data *output);
