#include "k5-int.h"
#include "enc_provider.h"
#include "hash_provider.h"
#include "etypes.h"
#include "old.h"
#include "raw.h"
#include "dk.h"

/* these will be linear searched.  if they ever get big, a binary
   search or hash table would be better, which means these would need
   to be sorted.  An array would be more efficient, but that assumes
   that the keytypes are all near each other.  I'd rather not make
   that assumption. */

struct krb5_keytypes krb5_enctypes_list[] = {
    { ENCTYPE_DES_CBC_CRC,
      "des-cbc-crc", "DES cbc mode with CRC-32",
      &krb5_enc_des, &krb5_hash_crc32,
      krb5_old_encrypt_length, krb5_old_encrypt, krb5_old_decrypt,
      krb5_des_string_to_key },
    { ENCTYPE_DES_CBC_MD4,
      "des-cbc-md4", "DES cbc mode with RSA-MD4",
      &krb5_enc_des, &krb5_hash_md4,
      krb5_old_encrypt_length, krb5_old_encrypt, krb5_old_decrypt,
      krb5_des_string_to_key },
    { ENCTYPE_DES_CBC_MD5,
      "des-cbc-md5", "DES cbc mode with RSA-MD5",
      &krb5_enc_des, &krb5_hash_md5,
      krb5_old_encrypt_length, krb5_old_encrypt, krb5_old_decrypt,
      krb5_des_string_to_key },

    { ENCTYPE_DES_CBC_RAW,
      "des-cbc-raw", "DES cbc mode raw",
      &krb5_enc_des, NULL,
      krb5_raw_encrypt_length, krb5_raw_encrypt, krb5_raw_decrypt,
      krb5_des_string_to_key },
    { ENCTYPE_DES3_CBC_RAW,
      "des3-cbc-raw", "Triple DES cbc mode raw",
      &krb5_enc_des3, NULL,
      krb5_raw_encrypt_length, krb5_raw_encrypt, krb5_raw_decrypt,
      krb5_dk_string_to_key },

    { ENCTYPE_LOCAL_DES3_HMAC_SHA1,
      "des3-marc-hmac-sha1", "Triple DES with HMAC/sha1 (marc's code)",
      &krb5_enc_des3, &krb5_hash_sha1,
      krb5_dk_encrypt_length, krb5_dk_encrypt, krb5_dk_decrypt,
      krb5_dk_string_to_key },
    { ENCTYPE_DES3_HMAC_SHA1,
      "des3-hmac-sha1", "Triple DES with HMAC/sha1 (as yet unspecified code)",
      &krb5_enc_des3, &krb5_hash_sha1,
      krb5_dk_encrypt_length, krb5_dk_encrypt, krb5_dk_decrypt,
      krb5_dk_string_to_key },
    { ENCTYPE_DES_HMAC_SHA1,
      "des3-hmac-sha1", "Triple DES with HMAC/sha1",
      &krb5_enc_des3, &krb5_hash_sha1,
      krb5_dk_encrypt_length, krb5_dk_encrypt, krb5_dk_decrypt,
      krb5_dk_string_to_key },
};

int krb5_enctypes_length =
sizeof(krb5_enctypes_list)/sizeof(struct krb5_keytypes);
