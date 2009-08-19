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
#include "hash_provider.h"
#include "keyhash_provider.h"
#include "cksumtypes.h"

const struct krb5_cksumtypes krb5_cksumtypes_list[] = {
    { CKSUMTYPE_CRC32, KRB5_CKSUMFLAG_NOT_COLL_PROOF,
      "crc32", { 0 }, "CRC-32",
      0, NULL,
      &krb5int_hash_crc32 },

    { CKSUMTYPE_RSA_MD4, 0,
      "md4", { 0 }, "RSA-MD4",
      0, NULL,
      &krb5int_hash_md4 },
    { CKSUMTYPE_RSA_MD4_DES, 0,
      "md4-des", { 0 }, "RSA-MD4 with DES cbc mode",
      ENCTYPE_DES_CBC_CRC, &krb5int_keyhash_md4des,
      NULL },

    { CKSUMTYPE_DESCBC, 0,
      "des-cbc", { 0 }, "DES cbc mode",
      ENCTYPE_DES_CBC_CRC, &krb5int_keyhash_descbc,
      NULL },

    { CKSUMTYPE_RSA_MD5, 0,
      "md5", { 0 }, "RSA-MD5",
      0, NULL,
      &krb5int_hash_md5 },
    { CKSUMTYPE_RSA_MD5_DES, 0,
      "md5-des", { 0 }, "RSA-MD5 with DES cbc mode",
      ENCTYPE_DES_CBC_CRC, &krb5int_keyhash_md5des,
      NULL },

    { CKSUMTYPE_NIST_SHA, 0,
      "sha", { 0 }, "NIST-SHA",
      0, NULL,
      &krb5int_hash_sha1 },

    { CKSUMTYPE_HMAC_SHA1_DES3, KRB5_CKSUMFLAG_DERIVE,
      "hmac-sha1-des3", { "hmac-sha1-des3-kd" }, "HMAC-SHA1 DES3 key",
      0, NULL,
      &krb5int_hash_sha1 },
    { CKSUMTYPE_HMAC_MD5_ARCFOUR, 0,
      "hmac-md5-rc4", { "hmac-md5-enc", "hmac-md5-earcfour" },
      "Microsoft HMAC MD5 (RC4 key)", 
      ENCTYPE_ARCFOUR_HMAC, &krb5int_keyhash_hmac_md5,
      NULL },

    { CKSUMTYPE_HMAC_SHA1_96_AES128, KRB5_CKSUMFLAG_DERIVE,
      "hmac-sha1-96-aes128", { 0 }, "HMAC-SHA1 AES128 key",
      0, NULL, 
      &krb5int_hash_sha1, 12 },
    { CKSUMTYPE_HMAC_SHA1_96_AES256, KRB5_CKSUMFLAG_DERIVE,
      "hmac-sha1-96-aes256", { 0 }, "HMAC-SHA1 AES256 key",
      0, NULL, 
      &krb5int_hash_sha1, 12 },
    { CKSUMTYPE_MD5_HMAC_ARCFOUR, 0,
      "md5-hmac-rc4", { 0 }, "Microsoft MD5 HMAC (RC4 key)",
      ENCTYPE_ARCFOUR_HMAC, &krb5int_keyhash_md5_hmac, 
      NULL }
};

const unsigned int krb5_cksumtypes_length =
sizeof(krb5_cksumtypes_list)/sizeof(struct krb5_cksumtypes);
