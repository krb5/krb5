/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/nss/pbkdf2.c
 *
 * Copyright 2002, 2008, 2009 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * Implementation of PBKDF2 using NSS.
 */

#include <ctype.h>
#include "k5-int.h"
#include "hash_provider.h"
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

    saltItem.type = siBuffer;
    saltItem.data = (unsigned char *)salt->data;
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
