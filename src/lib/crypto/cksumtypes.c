#include "k5-int.h"
#include "hash_provider.h"
#include "keyhash_provider.h"
#include "cksumtypes.h"

struct krb5_cksumtypes krb5_cksumtypes_list[] = {
    { CKSUMTYPE_CRC32, KRB5_CKSUMFLAG_NOT_COLL_PROOF,
      "crc32", "CRC-32",
      0, NULL,
      &krb5_hash_crc32 },

    { CKSUMTYPE_RSA_MD4, 0,
      "md4", "RSA-MD4",
      0, NULL,
      &krb5_hash_md4 },
    { CKSUMTYPE_RSA_MD4_DES, 0,
      "md4-des", "RSA-MD4 with DES cbc mode",
      ENCTYPE_DES_CBC_CRC, &krb5_keyhash_md4des,
      NULL },

    { CKSUMTYPE_DESCBC, 0,
      "des-cbc", "DES cbc mode",
      ENCTYPE_DES_CBC_CRC, &krb5_keyhash_descbc,
      NULL },

    { CKSUMTYPE_RSA_MD5, 0,
      "md5", "RSA-MD5",
      0, NULL,
      &krb5_hash_md5 },
    { CKSUMTYPE_RSA_MD5_DES, 0,
      "md5-des", "RSA-MD5 with DES cbc mode",
      ENCTYPE_DES_CBC_CRC, &krb5_keyhash_md5des,
      NULL },

    { CKSUMTYPE_NIST_SHA, 0,
      "sha", "NIST-SHA",
      0, NULL,
      &krb5_hash_sha1 },

    { CKSUMTYPE_HMAC_SHA1, KRB5_CKSUMFLAG_DERIVE,
      "hmac-sha1", "HMAC-SHA1",
      0, NULL,
      &krb5_hash_sha1 },
};

int krb5_cksumtypes_length =
sizeof(krb5_cksumtypes_list)/sizeof(struct krb5_cksumtypes);

