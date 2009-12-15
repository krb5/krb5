/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*

  ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
  This cipher is widely believed and has been tested to be equivalent
  with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
  of RSA Data Security)

*/
#include "k5-int.h"
#include "arcfour-int.h"
#include "hash_provider/hash_provider.h"

const char l40[] = "fortybits";

krb5_keyusage
krb5int_arcfour_translate_usage(krb5_keyusage usage)
{
    switch (usage) {
    case 1:  return 1;   /* AS-REQ PA-ENC-TIMESTAMP padata timestamp,  */
    case 2:  return 2;   /* ticket from kdc */
    case 3:  return 8;   /* as-rep encrypted part */
    case 4:  return 4;   /* tgs-req authz data */
    case 5:  return 5;   /* tgs-req authz data in subkey */
    case 6:  return 6;   /* tgs-req authenticator cksum */
    case 7:  return 7;   /* tgs-req authenticator */
    case 8:  return 8;
    case 9:  return 9;   /* tgs-rep encrypted with subkey */
    case 10: return 10;  /* ap-rep authentication cksum (never used by MS) */
    case 11: return 11;  /* app-req authenticator */
    case 12: return 12;  /* app-rep encrypted part */
    case 23: return 13;  /* sign wrap token*/
    default: return usage;
    }
}

/* Derive a usage key from a session key and krb5 usage constant. */
krb5_error_code
krb5int_arcfour_usage_key(const struct krb5_enc_provider *enc,
                          const struct krb5_hash_provider *hash,
                          const krb5_keyblock *session_keyblock,
                          krb5_keyusage usage,
                          krb5_keyblock *out)
{
    char salt_buf[14];
    unsigned int salt_len;
    krb5_data out_data = make_data(out->contents, out->length);
    krb5_crypto_iov iov;
    krb5_keyusage ms_usage;

    /* Generate the salt. */
    ms_usage = krb5int_arcfour_translate_usage(usage);
    if (session_keyblock->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
        memcpy(salt_buf, l40, 10);
        store_32_le(ms_usage, salt_buf + 10);
        salt_len = 14;
    } else {
        store_32_le(ms_usage, salt_buf);
        salt_len = 4;
    }

    /* Compute HMAC(key, salt) to produce the usage key. */
    iov.flags = KRB5_CRYPTO_TYPE_DATA;
    iov.data = make_data(salt_buf, salt_len);
    return krb5int_hmac_keyblock(hash, session_keyblock, &iov, 1, &out_data);
}

/* Derive an encryption key from a usage key and (typically) checksum. */
krb5_error_code
krb5int_arcfour_enc_key(const struct krb5_enc_provider *enc,
                        const struct krb5_hash_provider *hash,
                        const krb5_keyblock *usage_keyblock,
                        const krb5_data *checksum, krb5_keyblock *out)
{
    krb5_keyblock *trunc_keyblock = NULL;
    krb5_data out_data = make_data(out->contents, out->length);
    krb5_crypto_iov iov;
    krb5_error_code ret;

    /* Copy usage_keyblock to trunc_keyblock and truncate if exportable. */
    ret = krb5int_c_copy_keyblock(NULL, usage_keyblock, &trunc_keyblock);
    if (ret != 0)
        return ret;
    if (trunc_keyblock->enctype == ENCTYPE_ARCFOUR_HMAC_EXP)
        memset(trunc_keyblock->contents + 7, 0xab, 9);

    /* Compute HMAC(trunc_key, checksum) to produce the encryption key. */
    iov.flags = KRB5_CRYPTO_TYPE_DATA;
    iov.data = *checksum;
    ret = krb5int_hmac_keyblock(hash, trunc_keyblock, &iov, 1, &out_data);
    krb5int_c_free_keyblock(NULL, trunc_keyblock);
    return ret;
}
