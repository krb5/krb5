/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/pbkdf2.c */
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

#include <ctype.h>
#include "crypto_int.h"
#include "pk11pub.h"
#include "nss_gen.h"


krb5_error_code
krb5int_pbkdf2_hmac_sha1(const krb5_data *out, unsigned long count,
                         const krb5_data *pass, const krb5_data *salt)
{

    PK11SlotInfo *slot = NULL;
    SECAlgorithmID *algid = NULL;
    PK11SymKey *symKey = NULL;
    SECItem saltItem, pwItem;
    const SECItem *keydata = NULL;
    SECOidTag pbeAlg = SEC_OID_PKCS5_PBKDF2;
    SECOidTag cipherAlg = SEC_OID_AES_256_CBC;
    SECOidTag prfAlg = SEC_OID_HMAC_SHA1;
    krb5_error_code ret;

    ret = k5_nss_init();
    if (ret)
        return ret;

    slot = PK11_GetBestSlot(PK11_AlgtagToMechanism(pbeAlg), NULL);
    if (slot == NULL)
        return k5_nss_map_last_error();

    /* NSS treats a null saltItem.data as a request for a random salt. */
    saltItem.type = siBuffer;
    saltItem.data = (salt->data == NULL) ? "" : (unsigned char *)salt->data;
    saltItem.len = salt->length;

    /* PKCS 5 was designed to be DER encoded. Algid's carry all the
     * information needed to describe the encoding the the recipient.
     * This usually allows for crypto agility in the protocol automatically.
     * Kerberos already had to solve it's crypto agility issues, so the
     * algid is just and extra step we need that we will throw away */
    algid = PK11_CreatePBEV2AlgorithmID(pbeAlg, cipherAlg, prfAlg,
                                        out->length, count, &saltItem);
    if (algid == NULL) {
        ret = k5_nss_map_last_error();
        goto loser;
    }

    pwItem.type = siBuffer;
    pwItem.data = (unsigned char *)pass->data;
    pwItem.len = pass->length;

    symKey = PK11_PBEKeyGen(slot, algid, &pwItem, PR_FALSE, NULL);
    if (symKey == NULL) {
        ret = k5_nss_map_last_error();
        goto loser;
    }

    /* At this point we should return symKey as a key, but kerberos is
     * still passing bits around instead of key handles. */
    PK11_ExtractKeyValue(symKey);

    /* keydata here is a const * and is valid as long as the key has not been
     * destroyed. */
    keydata = PK11_GetKeyData(symKey);
    if (keydata == NULL) {
        ret = k5_nss_map_last_error();
        goto loser;
    }

    if (out->length != keydata->len) {
        ret = -1; /* XXXXX */
        goto loser;
    }
    memcpy(out->data, keydata->data, keydata->len);
    ret = 0;

loser:
    if (symKey)
        PK11_FreeSymKey(symKey);
    if (algid)
        SECOID_DestroyAlgorithmID(algid, PR_TRUE);
    if (slot)
        PK11_FreeSlot(slot);

    return ret;
}
