/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/enc_provider/enc_gen.c
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
#include "enc_provider.h"
#include "rand2key.h"
#include "aead.h"
#include "seccomon.h"
#include "secmod.h"
#include "pk11pub.h"
#include "nss.h"

/* 512 bits is bigger than anything defined to date */
#define MAX_KEY_LENGTH 64
#define MAX_BLOCK_SIZE 64

static NSSInitContext *k5_nss_ctx = NULL;
static pid_t k5_nss_pid = 0;
static k5_mutex_t k5_nss_lock = K5_MUTEX_PARTIAL_INITIALIZER;

struct stream_state {
    struct stream_state *loopback;  /* To detect copying */
    pid_t pid;                      /* To detect use across fork */
    PK11Context *ctx;
};

struct cached_key {
    pid_t pid;                  /* To detect use across fork */
    PK11SymKey *symkey;
};

krb5_error_code
k5_nss_map_error(int nss_error)
{
    /* Currently KRB5 does not define a full set of CRYPTO failures.
     * for now just use KRB5_CRYPTO_INTERNAL.  We really should return
     * errors for Not logged in, and maybe a few others. */
    return KRB5_CRYPTO_INTERNAL;
}

krb5_error_code
k5_nss_map_last_error(void)
{
    return k5_nss_map_error(PORT_GetError());
}

int
krb5int_crypto_impl_init(void)
{
    return k5_mutex_finish_init(&k5_nss_lock);
}

void
krb5int_crypto_impl_cleanup(void)
{
    k5_mutex_destroy(&k5_nss_lock);
}

/*
 * krb5 doesn't have a call into the crypto engine to initialize it, so we do
 * it here.  This code will try to piggyback on any application initialization
 * done to NSS.  Otherwise get our one library init context.
 */
#define NSS_KRB5_CONFIGDIR "sql:/etc/pki/nssdb"
krb5_error_code
k5_nss_init(void)
{
    PRUint32 flags = NSS_INIT_READONLY | NSS_INIT_NOROOTINIT;
    krb5_error_code ret;
    SECStatus rv;
    pid_t pid;

    ret = k5_mutex_lock(&k5_nss_lock);
    if (ret)
        return ret;

    pid = getpid();
    if (k5_nss_ctx != NULL) {
        /* Do nothing if the existing context is still good. */
        if (k5_nss_pid == pid)
            goto cleanup;
        /* The caller has forked.  Restart the NSS modules.  This will
         * invalidate all of our PKCS11 handles, which we're prepared for. */
        rv = SECMOD_RestartModules(TRUE);
        if (rv != SECSuccess) {
            ret = k5_nss_map_last_error();
            goto cleanup;
        }
        k5_nss_pid = pid;
        goto cleanup;
    }
    k5_nss_ctx = NSS_InitContext(NSS_KRB5_CONFIGDIR, "", "", "", NULL, flags);
    if (k5_nss_ctx == NULL) {
        /* There may be no system database; try again without it. */
        flags |= NSS_INIT_NOMODDB | NSS_INIT_NOCERTDB;
        k5_nss_ctx = NSS_InitContext(NULL, "", "", "", NULL, flags);
        if (k5_nss_ctx == NULL) {
            ret = k5_nss_map_last_error();
            goto cleanup;
        }
    }
    k5_nss_pid = pid;

cleanup:
    k5_mutex_unlock(&k5_nss_lock);
    return ret;
}

PK11Context *
k5_nss_create_context(krb5_key krb_key, CK_MECHANISM_TYPE mechanism,
                      CK_ATTRIBUTE_TYPE operation, SECItem *param)
{
    struct cached_key *ckey = krb_key->cache;

    return PK11_CreateContextBySymKey(mechanism, operation, ckey->symkey,
                                      param);
}

static void inline
xor(unsigned char *x, unsigned char *y, int size)
{
    int i;

#define ALIGNED(x,type) (!(((size_t)(x))&(sizeof(type)-1)))
    if (ALIGNED(x,unsigned long) && ALIGNED(y, unsigned long)
        && ALIGNED(size, unsigned long)) {
        unsigned long *ux = (unsigned long *)x;
        unsigned long *uy = (unsigned long *)y;
        for (i=0; i < (int)(size/sizeof(unsigned long)); i++) {
            *ux++ ^= *uy++;
        }
        return;
    }
    for (i=0; i < size; i++) {
        *x++ ^= *y++;
    }
}

krb5_error_code
k5_nss_gen_block_iov(krb5_key krb_key, CK_MECHANISM_TYPE mech,
                     CK_ATTRIBUTE_TYPE operation, const krb5_data *ivec,
                     krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret = 0;
    PK11Context *ctx = NULL;
    SECStatus rv;
    SECItem *param = NULL;
    struct iov_block_state input_pos, output_pos;
    unsigned char storage[MAX_BLOCK_SIZE];
    unsigned char iv0[MAX_BLOCK_SIZE];
    unsigned char *ptr = NULL,*lastptr = NULL;
    SECItem iv;
    size_t blocksize;
    int length = 0;
    int lastblock = -1;
    int currentblock;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    blocksize = PK11_GetBlockSize(mech, NULL);
    assert(blocksize <= sizeof(storage));

    if (ivec && ivec->data) {
        iv.data = (unsigned char *)ivec->data;
        iv.len = ivec->length;
        if (operation == CKA_DECRYPT) {
            int i, inputlength;

            /* Count the blocks so we know which block is last. */
            for (i = 0, inputlength = 0; i < (int)num_data; i++) {
                krb5_crypto_iov *iov = &data[i];

                if (ENCRYPT_IOV(iov))
                    inputlength += iov->data.length;
            }
            lastblock = (inputlength/blocksize) -1;
        }
    } else {
        memset(iv0, 0, sizeof(iv0));
        iv.data = iv0;
        iv.len = blocksize;
    }
    param = PK11_ParamFromIV(mech, &iv);

    ctx = k5_nss_create_context(krb_key, mech, operation, param);
    if (ctx == NULL) {
        ret = k5_nss_map_last_error();
        goto done;
    }

    for (currentblock = 0;;currentblock++) {
        if (!krb5int_c_iov_get_block_nocopy(storage, blocksize, data, num_data,
                                            &input_pos, &ptr))
            break;

        lastptr = NULL;

        /* only set if we are decrypting */
        if (lastblock == currentblock)
            memcpy(ivec->data, ptr, blocksize);

        rv = PK11_CipherOp(ctx, ptr, &length, blocksize, ptr, blocksize);
        if (rv != SECSuccess) {
            ret = k5_nss_map_last_error();
            break;
        }

        lastptr = ptr;
        krb5int_c_iov_put_block_nocopy(data, num_data, storage, blocksize,
                                       &output_pos, ptr);
    }

    if (lastptr && ivec && ivec->data && operation == CKA_ENCRYPT) {
        memcpy(ivec->data, lastptr, blocksize);
    }
done:
    if (ctx) {
        PK11_Finalize(ctx);
        PK11_DestroyContext(ctx, PR_TRUE);
    }
    if (param)
        SECITEM_FreeItem(param, PR_TRUE);
    return ret;
}

krb5_error_code
k5_nss_stream_init_state(krb5_data *new_state)
{
    struct stream_state *sstate;

    /* Create a state structure with an uninitialized context. */
    sstate = calloc(1, sizeof(*sstate));
    if (sstate == NULL)
        return ENOMEM;
    sstate->loopback = NULL;
    new_state->data = (char *) sstate;
    new_state->length = sizeof(*sstate);
    return 0;
}

krb5_error_code
k5_nss_stream_free_state(krb5_data *state)
{
    struct stream_state *sstate = (struct stream_state *) state->data;

    /* Clean up the OpenSSL context if it was initialized. */
    if (sstate && sstate->loopback == sstate) {
        PK11_Finalize(sstate->ctx);
        PK11_DestroyContext(sstate->ctx, PR_TRUE);
    }
    free(sstate);
    return 0;
}

krb5_error_code
k5_nss_gen_stream_iov(krb5_key krb_key, krb5_data *state,
                      CK_MECHANISM_TYPE mech, CK_ATTRIBUTE_TYPE operation,
                      krb5_crypto_iov *data, size_t num_data)
{
    int ret = 0;
    PK11Context *ctx = NULL;
    SECStatus rv;
    SECItem  param;
    krb5_crypto_iov *iov;
    struct stream_state *sstate = NULL;
    int i;

    param.data = NULL;
    param.len = 0;

    sstate = (state == NULL) ? NULL : (struct stream_state *) state->data;
    if (sstate == NULL || sstate->loopback == NULL) {
        ctx = k5_nss_create_context(krb_key, mech, operation, &param);
        if (ctx == NULL) {
            ret = k5_nss_map_last_error();
            goto done;
        }
        if (sstate) {
            sstate->loopback = sstate;
            sstate->pid = getpid();
            sstate->ctx = ctx;
        }
    } else {
        /* Cipher state can't be copied or used across a fork. */
        if (sstate->loopback != sstate || sstate->pid != getpid())
            return EINVAL;
        ctx = sstate->ctx;
    }

    for (i=0; i < (int)num_data; i++) {
        int return_length;
        iov = &data[i];
        if (iov->data.length <= 0)
            break;

        if (ENCRYPT_IOV(iov)) {
            rv = PK11_CipherOp(ctx, (unsigned char *)iov->data.data,
                               &return_length, iov->data.length,
                               (unsigned char *)iov->data.data,
                               iov->data.length);
            if (rv != SECSuccess) {
                ret = k5_nss_map_last_error();
                goto done;
            }
            iov->data.length = return_length;
        }
    }
done:
    if (!state && ctx) {
        PK11_Finalize(ctx);
        PK11_DestroyContext(ctx, PR_TRUE);
    }
    return ret;
}

krb5_error_code
k5_nss_gen_cts_iov(krb5_key krb_key, CK_MECHANISM_TYPE mech,
                   CK_ATTRIBUTE_TYPE operation, const krb5_data *ivec,
                   krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret = 0;
    PK11Context *ctx = NULL;
    SECStatus rv;
    SECItem *param = NULL;
    struct iov_block_state input_pos, output_pos;
    unsigned char storage[MAX_BLOCK_SIZE];
    unsigned char recover1[MAX_BLOCK_SIZE];
    unsigned char recover2[MAX_BLOCK_SIZE];
    unsigned char block1[MAX_BLOCK_SIZE];
    unsigned char block2[MAX_BLOCK_SIZE];
    unsigned char iv0[MAX_BLOCK_SIZE];
    unsigned char *ptr = NULL;
    SECItem iv;
    size_t blocksize;
    size_t bulk_length, remainder;
    size_t input_length, lastblock;
    size_t length;
    int i, len;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    blocksize = PK11_GetBlockSize(mech, NULL);
    assert(blocksize <= sizeof(storage));

    if (ivec) {
        iv.data = (unsigned char *)ivec->data;
        iv.len = ivec->length;
    } else {
        memset(iv0, 0, sizeof(iv0));
        iv.data = iv0;
        iv.len = blocksize;
    }
    param = PK11_ParamFromIV(mech, &iv);

    for (i = 0, input_length = 0; i < (int)num_data; i++) {
        krb5_crypto_iov *iov = &data[i];

        if (ENCRYPT_IOV(iov))
            input_length += iov->data.length;
    }
    /* Must be at least a block or we fail. */
    if (input_length < blocksize) {
        ret = EINVAL;
        goto done;
    }

    bulk_length = (input_length / blocksize)*blocksize;
    remainder = input_length - bulk_length;
    /* Do the block swap even if the input data is aligned, only
     * drop it if we are encrypting exactly one block. */
    if (remainder == 0 && bulk_length != blocksize) {
        remainder = blocksize;
        bulk_length -= blocksize;
    }

    ctx = k5_nss_create_context(krb_key, mech, operation, param);
    if (ctx == NULL) {
        ret = k5_nss_map_last_error();
        goto done;
    }

    /* Now we bulk encrypt each block in the loop.  We need to know where to
     * stop to do special processing.  For single block operations we stop at
     * the end.  For all others we stop and the last second to last block
     * (counting partial blocks).  For decrypt operations we need to save cn-2
     * so we stop at the third to last block if it exists, otherwise cn-2 = the
     * iv. */
    lastblock = bulk_length;
    if (remainder) {
        /* We need to process the last full block and last partitial block
         * differently. */
        lastblock = bulk_length - blocksize;
        if (operation == CKA_DECRYPT) {
            if (bulk_length > blocksize) {
                /* Stop at cn-2 so we can save it before going on. */
                lastblock = bulk_length - 2*blocksize;
            } else {
                /* iv is cn-2, save it now, cn - 2. */
                memcpy(recover1, iv.data, blocksize);
                memcpy(recover2, iv.data, blocksize);
            }
        }
    }
    for (length = 0; length < lastblock; length += blocksize) {
        if (!krb5int_c_iov_get_block_nocopy(storage, blocksize, data, num_data,
                                            &input_pos, &ptr))
            break;

        rv = PK11_CipherOp(ctx, ptr, &len, blocksize, ptr, blocksize);
        if (rv != SECSuccess) {
            ret = k5_nss_map_last_error();
            break;
        }

        krb5int_c_iov_put_block_nocopy(data, num_data, storage, blocksize,
                                       &output_pos, ptr);
    }
    if (remainder) {
        if (operation == CKA_DECRYPT) {
            if (bulk_length > blocksize) {
                /* we need to save cn-2 */
                if (!krb5int_c_iov_get_block_nocopy(storage, blocksize, data,
                                                    num_data, &input_pos,
                                                    &ptr))
                    goto done; /* shouldn't happen */

                /* save cn-2 */
                memcpy(recover1, ptr, blocksize);
                memcpy(recover2, ptr, blocksize);

                /* now process it as normal */
                rv = PK11_CipherOp(ctx, ptr, &len, blocksize, ptr, blocksize);
                if (rv != SECSuccess) {
                    ret = k5_nss_map_last_error();
                    goto done;
                }

                krb5int_c_iov_put_block_nocopy(data, num_data, storage,
                                               blocksize, &output_pos, ptr);
            }
        }
        /* fetch the last 2 blocks */
        memset(block1, 0, blocksize); /* last block, could be partial */
        krb5int_c_iov_get_block(block2, blocksize, data, num_data, &input_pos);
        krb5int_c_iov_get_block(block1, remainder, data, num_data, &input_pos);
        if (operation == CKA_DECRYPT) {
            /* recover1 and recover2 are xor values to recover the true
             * underlying data of the last 2 decrypts. This keeps us from
             * having to try to reset our IV to do the final decryption. */
            /* Currently: block1 is cn || 0, block2 is cn-1.
             * recover1 & recover2 is set to cn-2. */
            /* recover2 recovers pn || c' from p'n-1. The raw decrypted block
             * will be p'n-1 xor with cn-2 while pn || c' = p'n-1 xor cn || 0.
             * recover2 is cn-2 xor cn || 0, so we can simple xor recover1
             * with the raw decrypted block. */
            /* recover1 recovers pn-1 from the raw decryption of cn || c'.
             * the raw decrypt of cn || c' = p'n xor cn-1 while
             * pn-1 = p'n xor cn-2
             * recover1 is cn-2 xor cn-1, so we can simple xor recover 2 with
             * the raw decrypt of cn||c' to get pn-1. */
            xor(recover1, block2, blocksize);
            xor(recover2, block1, blocksize);
            if (ivec && ivec->data)
                memcpy(ivec->data, block2, blocksize);
        }
        rv = PK11_CipherOp(ctx, block2, &len, blocksize, block2, blocksize);
        if (rv != SECSuccess) {
            ret = k5_nss_map_last_error();
            goto done;
        }
        if (operation == CKA_DECRYPT) {
            /* block2 now has p'n-1 xor cn-2. */
            xor(block2, recover2, blocksize);
            /* block 2 now has pn || c'. */
            /* copy c' into cn || c'. */
            memcpy(block1 + remainder, block2 + remainder,
                   blocksize - remainder);
        }
        rv = PK11_CipherOp(ctx, block1, &len, blocksize, block1, blocksize);
        if (rv != SECSuccess) {
            ret = k5_nss_map_last_error();
            goto done;
        }
        if (operation == CKA_DECRYPT) {
            /* block1 now has p'n xor cn-1 */
            xor(block1, recover1, blocksize);
           /* block 1 now has pn-1 */
        } else {
            if (ivec && ivec->data) {
                memcpy(ivec->data, block1, blocksize);
            }
        }
        krb5int_c_iov_put_block(data,num_data, block1, blocksize, &output_pos);
        krb5int_c_iov_put_block(data,num_data, block2, remainder, &output_pos);
    }

done:
    if (ctx) {
        PK11_Finalize(ctx);
        PK11_DestroyContext(ctx, PR_TRUE);
    }
    if (param)
        SECITEM_FreeItem(param, PR_TRUE);
    return ret;
}

krb5_error_code
k5_nss_gen_cbcmac_iov(krb5_key krb_key, CK_MECHANISM_TYPE mech,
                      const krb5_data *ivec, const krb5_crypto_iov *data,
                      size_t num_data, krb5_data *output)
{
    krb5_error_code ret = 0;
    PK11Context *ctx = NULL;
    SECStatus rv;
    SECItem *param = NULL;
    struct iov_block_state input_pos, output_pos;
    unsigned char storage[MAX_BLOCK_SIZE];
    unsigned char iv0[MAX_BLOCK_SIZE];
    unsigned char *ptr = NULL, *lastptr = NULL;
    SECItem iv;
    size_t blocksize;
    int length = 0;
    int currentblock;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    blocksize = PK11_GetBlockSize(mech, NULL);
    assert(blocksize <= sizeof(storage));
    if (output->length < blocksize)
        return KRB5_BAD_MSIZE;

    if (ivec && ivec->data) {
        iv.data = (unsigned char *)ivec->data;
        iv.len = ivec->length;
    } else {
        memset(iv0, 0, sizeof(iv0));
        iv.data = iv0;
        iv.len = blocksize;
    }
    param = PK11_ParamFromIV(mech, &iv);

    ctx = k5_nss_create_context(krb_key, mech, CKA_ENCRYPT, param);
    if (ctx == NULL) {
        ret = k5_nss_map_last_error();
        goto done;
    }

    lastptr = iv.data;
    for (currentblock = 0;;currentblock++) {
        if (!krb5int_c_iov_get_block_nocopy(storage, blocksize, data, num_data,
                                            &input_pos, &ptr))
            break;

        lastptr = NULL;

        rv = PK11_CipherOp(ctx, ptr, &length, blocksize, ptr, blocksize);
        if (rv != SECSuccess) {
            ret = k5_nss_map_last_error();
            goto done;
        }

        lastptr = ptr;
    }
    memcpy(output->data, lastptr, blocksize);

done:
    if (ctx) {
        PK11_Finalize(ctx);
        PK11_DestroyContext(ctx, PR_TRUE);
    }
    if (param)
        SECITEM_FreeItem(param, PR_TRUE);
    return ret;
}

void
k5_nss_gen_cleanup(krb5_key krb_key)
{
    struct cached_key *ckey = krb_key->cache;

    if (ckey) {
        PK11_FreeSymKey(ckey->symkey);
        free(ckey);
        krb_key->cache = NULL;
    }
}

krb5_error_code
k5_nss_gen_import(krb5_key krb_key, CK_MECHANISM_TYPE mech,
                  CK_ATTRIBUTE_TYPE operation)
{
    krb5_error_code ret = 0;
    pid_t pid = getpid();
    struct cached_key *ckey = krb_key->cache;
    PK11SymKey *symkey;
    PK11SlotInfo *slot = NULL;
    SECItem raw_key;
#ifdef FAKE_FIPS
    PK11SymKey *wrapping_key = NULL;
    PK11Context *ctx = NULL;
    SECItem wrapped_key;
    SECItem params;
    unsigned char wrapped_key_data[MAX_KEY_LENGTH];
    unsigned char padded_key_data[MAX_KEY_LENGTH];
    int wrapping_index, series, blocksize;
    int keyLength;
    CK_MECHANISM_TYPE mechanism;
    SECStatus rv;
#endif

    if (ckey && ckey->pid == pid)
        return 0;

    ret = k5_nss_init();
    if (ret)
        return ret;

    if (ckey) {
        /* Discard the no-longer-valid symkey and steal its container. */
        PK11_FreeSymKey(ckey->symkey);
        ckey->symkey = NULL;
        krb_key->cache = NULL;
    } else {
        /* Allocate a new container. */
        ckey = k5alloc(sizeof(*ckey), &ret);
        if (ckey == NULL)
            return ret;
    }

    slot = PK11_GetBestSlot(mech, NULL);
    if (slot == NULL) {
        ret = k5_nss_map_last_error();
        goto done;
    }
    raw_key.data = krb_key->keyblock.contents;
    raw_key.len = krb_key->keyblock.length;

#ifdef FAKE_FIPS
    /* First, fetch a wrapping key. */
    wrapping_index = PK11_GetCurrentWrapIndex(slot);
    series = PK11_GetSlotSeries(slot);
    wrapping_key = PK11_GetWrapKey(slot, wrapping_index,
                                   CKM_INVALID_MECHANISM, series, NULL);
    if (wrapping_key == NULL) {
        /* One doesn't exist, create one. */
        mechanism = PK11_GetBestWrapMechanism(slot);
        keyLength = PK11_GetBestKeyLength(slot, mechanism);
        wrapping_key = PK11_TokenKeyGenWithFlags(slot, mechanism, NULL,
                                                 keyLength, NULL,
                                                 CKF_UNWRAP | CKF_ENCRYPT, 0,
                                                 NULL);
        if (!wrapping_key) {
            ret = k5_nss_map_last_error();
            goto done;
        }
        PK11_SetWrapKey(slot, wrapping_index, wrapping_key);
    }

    /* Now encrypt the data with the wrapping key. */
    mechanism = PK11_GetMechanism(wrapping_key);
    params.data = NULL;
    params.len = 0;
    ctx = PK11_CreateContextBySymKey(mechanism, CKA_ENCRYPT,
                                     wrapping_key, &params);
    if (ctx == NULL) {
        ret = k5_nss_map_last_error();
        goto done;
    }

    wrapped_key.data = wrapped_key_data;
    wrapped_key.len = sizeof(wrapped_key_data);
    blocksize = PK11_GetBlockSize(mechanism, NULL);
    keyLength = raw_key.len;

    /*
     * ECB modes need keys in integral multiples of the block size.
     * if the key isn't and integral multiple, pad it with zero. Unwrap
     * will use the length parameter to appropriately set the key.
     */
    if ((raw_key.len % blocksize) != 0) {
        int keyblocks = (raw_key.len + (blocksize - 1)) / blocksize;
        keyLength = keyblocks * blocksize;
        assert(keyLength <= sizeof(padded_key_data));
        memset(padded_key_data, 0, keyLength);
        memcpy(padded_key_data, raw_key.data, raw_key.len);
        raw_key.data = padded_key_data;
    }
    rv = PK11_CipherOp(ctx, wrapped_key.data, (int *)&wrapped_key.len,
                       sizeof(wrapped_key_data), raw_key.data, keyLength);
    if (keyLength != raw_key.len) {
        /* Clear our copy of the key bits. */
        memset(padded_key_data, 0, keyLength);
    }
    if (rv != SECSuccess) {
        ret = k5_nss_map_last_error();
        goto done;
    }
    PK11_Finalize(ctx);
    PK11_DestroyContext(ctx, PR_TRUE);
    ctx = NULL;

    /* Now now we have a 'wrapped' version of the, we can import it into
     * the token without running afoul with FIPS. */
    symkey = PK11_UnwrapSymKey(wrapping_key, mechanism, &params, &wrapped_key,
                               mech, operation, raw_key.len);
#else
    symkey = PK11_ImportSymKey(slot, mech, PK11_OriginGenerated, operation,
                               &raw_key, NULL);
#endif
    if (symkey == NULL) {
        ret = k5_nss_map_last_error();
        goto done;
    }
    ckey->pid = pid;
    ckey->symkey = symkey;
    krb_key->cache = ckey;
    ckey = NULL;

done:
    free(ckey);
    if (slot)
        PK11_FreeSlot(slot);
#ifdef FAKE_FIPS
    if (ctx) {
        PK11_Finalize(ctx);
        PK11_DestroyContext(ctx, PR_TRUE);
    }
    if (wrapping_key)
        PK11_FreeSymKey(wrapping_key);
#endif

    return ret;
}
