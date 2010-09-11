/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/openssl/des/string2key.c
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
 */

#include "des_int.h"
#include "pk11pub.h"
#include "nss_gen.h"

krb5_error_code
mit_des_string_to_key_int(krb5_keyblock *key, const krb5_data *pw,
                          const krb5_data *salt)
{
    PK11SlotInfo *slot = NULL;
    PK11SymKey *symKey = NULL;
    SECItem pwItem;
    SECItem paramsItem;
    CK_PBE_PARAMS pbe_params;
    CK_MECHANISM_TYPE pbeMech = CKM_NETSCAPE_PBE_SHA1_DES_CBC;
    krb5_error_code ret;
    SECItem *keyData;

    ret = k5_nss_init();
    if (ret)
        return ret;

    slot = PK11_GetBestSlot(pbeMech, NULL);
    if (slot == NULL) {
        ret = k5_nss_map_last_error();
        goto loser;
    }

    pwItem.data = (unsigned char *)pw->data;
    pwItem.len = pw->length;
    memset(&pbe_params, 0, sizeof(pbe_params));
    pbe_params.pSalt = (unsigned char *)salt->data;
    pbe_params.ulSaltLen = salt->length;
    pbe_params.ulIteration = 1;
    paramsItem.data = (unsigned char *)&pbe_params;
    paramsItem.len = sizeof(pbe_params);

    symKey = PK11_RawPBEKeyGen(slot, pbeMech, &paramsItem, &pwItem,
                               PR_FALSE, NULL);
    if (symKey == NULL) {
        ret = k5_nss_map_last_error();
        goto loser;
    }
    PK11_ExtractKeyValue(symKey);
    keyData = PK11_GetKeyData(symKey);
    if (!keyData) {
        ret = k5_nss_map_last_error();
        goto loser;
    }
    key->length = keyData->len;
    memcpy(key->contents, keyData->data, key->length);
    ret = 0;

loser:
    if (symKey)
        PK11_FreeSymKey(symKey);
    if (slot)
        PK11_FreeSlot(slot);
    return ret;
}
