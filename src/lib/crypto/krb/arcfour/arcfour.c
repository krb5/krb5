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

void
krb5int_arcfour_encrypt_length(const struct krb5_enc_provider *enc,
                               const struct krb5_hash_provider *hash,
                               size_t inputlen, size_t *length)
{
    /* checksum + (confounder + inputlen, in even blocksize) */
    *length = hash->hashsize + krb5_roundup(8 + inputlen, enc->block_size);
}

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
    krb5_data out_data = make_data(out->contents, out->length);
    krb5_data salt = make_data(salt_buf, sizeof(salt_buf));
    krb5_keyusage ms_usage;

    /* Generate the salt. */
    ms_usage = krb5int_arcfour_translate_usage(usage);
    if (session_keyblock->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
        memcpy(salt_buf, l40, 10);
        store_32_le(ms_usage, salt_buf + 10);
    } else {
        salt.length=4;
        store_32_le(ms_usage, salt_buf);
    }

    /* Compute HMAC(key, salt) to produce the usage key. */
    return krb5int_hmac_keyblock(hash, session_keyblock, 1, &salt, &out_data);
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
    krb5_error_code ret;

    /* Copy usage_keyblock to trunc_keyblock and truncate if exportable. */
    ret = krb5int_c_copy_keyblock(NULL, usage_keyblock, &trunc_keyblock);
    if (ret != 0)
        return ret;
    if (trunc_keyblock->enctype == ENCTYPE_ARCFOUR_HMAC_EXP)
        memset(trunc_keyblock->contents + 7, 0xab, 9);

    /* Compute HMAC(trunc_key, checksum) to produce the encryption key. */
    ret = krb5int_hmac_keyblock(hash, trunc_keyblock, 1, checksum, &out_data);
    krb5int_c_free_keyblock(NULL, trunc_keyblock);
    return ret;
}

krb5_error_code
krb5int_arcfour_encrypt(const struct krb5_enc_provider *enc,
                        const struct krb5_hash_provider *hash,
                        krb5_key key, krb5_keyusage usage,
                        const krb5_data *ivec, const krb5_data *input,
                        krb5_data *output)
{
    krb5_keyblock *usage_keyblock = NULL, *enc_keyblock = NULL;
    krb5_key enc_key;
    krb5_data plaintext = empty_data();
    krb5_data checksum, ciphertext, confounder;
    krb5_error_code ret;
    unsigned int plainlen;

    /* Allocate buffers. */
    plainlen = krb5_roundup(input->length + CONFOUNDERLENGTH, enc->block_size);
    ret = alloc_data(&plaintext, plainlen);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_c_init_keyblock(NULL, key->keyblock.enctype, enc->keybytes,
                                  &usage_keyblock);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_c_init_keyblock(NULL, key->keyblock.enctype, enc->keybytes,
                                  &enc_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Set up subsets of output and plaintext. */
    checksum = make_data(output->data, hash->hashsize);
    ciphertext = make_data(output->data + hash->hashsize, plainlen);
    confounder = make_data(plaintext.data, CONFOUNDERLENGTH);

    /* Derive a usage key from the session key and usage. */
    ret = krb5int_arcfour_usage_key(enc, hash, &key->keyblock, usage,
                                    usage_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Compose a confounder with the input data to form the plaintext. */
    ret = krb5_c_random_make_octets(NULL, &confounder);
    memcpy(plaintext.data + confounder.length, input->data, input->length);
    if (ret)
        goto cleanup;

    /* Compute HMAC(usage key, plaintext) to get the checksum. */
    ret = krb5int_hmac_keyblock(hash, usage_keyblock, 1, &plaintext,
                                &checksum);
    if (ret)
        goto cleanup;

    /* Derive the encryption key from the usage key and checksum. */
    ret = krb5int_arcfour_enc_key(enc, hash, usage_keyblock, &checksum,
                                  enc_keyblock);
    if (ret)
        goto cleanup;

    /* Encrypt the plaintext. */
    ret = krb5_k_create_key(NULL, enc_keyblock, &enc_key);
    if (ret)
        goto cleanup;
    ret = (*enc->encrypt)(enc_key, ivec, &plaintext, &ciphertext);
    krb5_k_free_key(NULL, enc_key);
    if (ret)
        goto cleanup;

    output->length = plainlen + hash->hashsize;

cleanup:
    krb5int_c_free_keyblock(NULL, usage_keyblock);
    krb5int_c_free_keyblock(NULL, enc_keyblock);
    zapfree(plaintext.data, plaintext.length);
    return ret;
}

krb5_error_code
krb5int_arcfour_decrypt(const struct krb5_enc_provider *enc,
                        const struct krb5_hash_provider *hash,
                        krb5_key key, krb5_keyusage usage,
                        const krb5_data *ivec, const krb5_data *input,
                        krb5_data *output)
{
    krb5_keyblock *usage_keyblock = NULL, *enc_keyblock = NULL;
    krb5_data plaintext = empty_data(), comp_checksum = empty_data();
    krb5_data checksum, ciphertext;
    krb5_key enc_key;
    krb5_error_code ret;

    /* Set up subsets of input. */
    checksum = make_data(input->data, hash->hashsize);
    ciphertext = make_data(input->data + hash->hashsize,
                           input->length - hash->hashsize);

    /* Allocate buffers. */
    ret = alloc_data(&plaintext, ciphertext.length);
    if (ret != 0)
        goto cleanup;
    ret = alloc_data(&comp_checksum, hash->hashsize);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_c_init_keyblock(NULL, key->keyblock.enctype, enc->keybytes,
                                  &usage_keyblock);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_c_init_keyblock(NULL, key->keyblock.enctype, enc->keybytes,
                                  &enc_keyblock);
    if (ret != 0)
        goto cleanup;

    /* We may have to try two usage values; see below. */
    do {
        /* Derive a usage key from the session key and usage. */
        ret = krb5int_arcfour_usage_key(enc, hash, &key->keyblock, usage,
                                        usage_keyblock);
        if (ret != 0)
            goto cleanup;

        /* Derive the encryption key from the usage key and checksum. */
        ret = krb5int_arcfour_enc_key(enc, hash, usage_keyblock, &checksum,
                                      enc_keyblock);
        if (ret)
            goto cleanup;

        /* Decrypt the ciphertext. */
        ret = krb5_k_create_key(NULL, enc_keyblock, &enc_key);
        if (ret)
            goto cleanup;
        ret = (*enc->decrypt)(enc_key, ivec, &ciphertext, &plaintext);
        krb5_k_free_key(NULL, enc_key);
        if (ret)
            goto cleanup;

        /* Compute HMAC(usage key, plaintext) to get the checksum. */
        ret = krb5int_hmac_keyblock(hash, usage_keyblock, 1, &plaintext,
                                    &comp_checksum);
        if (ret)
            goto cleanup;

        if (memcmp(checksum.data, comp_checksum.data, hash->hashsize) != 0) {
            if (usage == 9) {
                /*
                 * RFC 4757 specifies usage 8 for TGS-REP encrypted
                 * parts encrypted in a subkey, but the value used by MS
                 * is actually 9.  We now use 9 to start with, but fall
                 * back to 8 on failure in case we are communicating
                 * with a KDC using the value from the RFC.
                 */
                usage = 8;
                continue;
            }
            ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
            goto cleanup;
        }

        break;
    } while (1);

    /* Remove the confounder from the plaintext to get the output. */
    memcpy(output->data, plaintext.data + CONFOUNDERLENGTH,
           plaintext.length - CONFOUNDERLENGTH);
    output->length = plaintext.length - CONFOUNDERLENGTH;

cleanup:
    krb5int_c_free_keyblock(NULL, usage_keyblock);
    krb5int_c_free_keyblock(NULL, enc_keyblock);
    zapfree(plaintext.data, plaintext.length);
    zapfree(comp_checksum.data, comp_checksum.length);
    return ret;
}

/* Encrypt or decrypt data for a GSSAPI token. */
krb5_error_code
krb5int_arcfour_gsscrypt(const krb5_keyblock *keyblock, krb5_keyusage usage,
                         const krb5_data *kd_data, const krb5_data *input,
                         krb5_data *output)
{
    const struct krb5_enc_provider *enc = &krb5int_enc_arcfour;
    const struct krb5_hash_provider *hash = &krb5int_hash_md5;
    krb5_keyblock *usage_keyblock = NULL, *enc_keyblock = NULL;
    krb5_key enc_key;
    krb5_error_code ret;

    ret = krb5int_c_init_keyblock(NULL, keyblock->enctype, enc->keybytes,
                                  &usage_keyblock);
    if (ret != 0)
        goto cleanup;
    ret = krb5int_c_init_keyblock(NULL, keyblock->enctype, enc->keybytes,
                                  &enc_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Derive a usage key from the session key and usage. */
    ret = krb5int_arcfour_usage_key(enc, hash, keyblock, usage,
                                    usage_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Derive the encryption key from the usage key and kd_data. */
    ret = krb5int_arcfour_enc_key(enc, hash, usage_keyblock, kd_data,
                                  enc_keyblock);
    if (ret != 0)
        goto cleanup;

    /* Encrypt or decrypt (encrypt works for both) the input. */
    ret = krb5_k_create_key(NULL, enc_keyblock, &enc_key);
    if (ret != 0)
        goto cleanup;
    ret = (*enc->encrypt)(enc_key, 0, input, output);
    krb5_k_free_key(NULL, enc_key);

cleanup:
    krb5int_c_free_keyblock(NULL, usage_keyblock);
    krb5int_c_free_keyblock(NULL, enc_keyblock);
    return ret;
}
