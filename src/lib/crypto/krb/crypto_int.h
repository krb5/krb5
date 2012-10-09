/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/krb/crypto_int.h - Master libk5crypto internal header */
/*
 * Copyright (C) 2011 by the Massachusetts Institute of Technology.
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

/* This header is the entry point for libk5crypto sources, and also documents
 * requirements for crypto modules and PRNG modules.  */

#ifndef CRYPTO_INT_H
#define CRYPTO_INT_H

#include <k5-int.h>

/* Enc providers and hash providers specify well-known ciphers and hashes to be
 * implemented by the crypto module. */

struct krb5_enc_provider {
    /* keybytes is the input size to make_key;
       keylength is the output size */
    size_t block_size, keybytes, keylength;

    krb5_error_code (*encrypt)(krb5_key key, const krb5_data *cipher_state,
                               krb5_crypto_iov *data, size_t num_data);

    krb5_error_code (*decrypt)(krb5_key key, const krb5_data *cipher_state,
                               krb5_crypto_iov *data, size_t num_data);

    /* May be NULL if the cipher is not used for a cbc-mac checksum. */
    krb5_error_code (*cbc_mac)(krb5_key key, const krb5_crypto_iov *data,
                               size_t num_data, const krb5_data *ivec,
                               krb5_data *output);

    krb5_error_code (*init_state)(const krb5_keyblock *key,
                                  krb5_keyusage keyusage,
                                  krb5_data *out_state);
    void (*free_state)(krb5_data *state);

    /* May be NULL if there is no key-derived data cached.  */
    void (*key_cleanup)(krb5_key key);
};

struct krb5_hash_provider {
    char hash_name[8];
    size_t hashsize, blocksize;

    krb5_error_code (*hash)(const krb5_crypto_iov *data, size_t num_data,
                            krb5_data *output);
};

/*** RFC 3961 enctypes table ***/

#define MAX_ETYPE_ALIASES 2

struct krb5_keytypes;

typedef unsigned int (*crypto_length_func)(const struct krb5_keytypes *ktp,
                                           krb5_cryptotype type);

typedef krb5_error_code (*crypt_func)(const struct krb5_keytypes *ktp,
                                      krb5_key key, krb5_keyusage keyusage,
                                      const krb5_data *ivec,
                                      krb5_crypto_iov *data, size_t num_data);

typedef krb5_error_code (*str2key_func)(const struct krb5_keytypes *ktp,
                                        const krb5_data *string,
                                        const krb5_data *salt,
                                        const krb5_data *parm,
                                        krb5_keyblock *key);

typedef krb5_error_code (*rand2key_func)(const krb5_data *randombits,
                                         krb5_keyblock *key);

typedef krb5_error_code (*prf_func)(const struct krb5_keytypes *ktp,
                                    krb5_key key,
                                    const krb5_data *in, krb5_data *out);

struct krb5_keytypes {
    krb5_enctype etype;
    char *name;
    char *aliases[MAX_ETYPE_ALIASES];
    char *out_string;
    const struct krb5_enc_provider *enc;
    const struct krb5_hash_provider *hash;
    size_t prf_length;
    crypto_length_func crypto_length;
    crypt_func encrypt;
    crypt_func decrypt;
    str2key_func str2key;
    rand2key_func rand2key;
    prf_func prf;
    krb5_cksumtype required_ctype;
    krb5_flags flags;
};

#define ETYPE_WEAK 1

extern const struct krb5_keytypes krb5int_enctypes_list[];
extern const int krb5int_enctypes_length;

/*** RFC 3961 checksum types table ***/

struct krb5_cksumtypes;

/*
 * Compute a checksum over the header, data, padding, and sign-only fields of
 * the iov array data (of size num_data).  The output buffer will already be
 * allocated with ctp->compute_size bytes available; the handler just needs to
 * fill in the contents.  If ctp->enc is not NULL, the handler can assume that
 * key is a valid-length key of an enctype which uses that enc provider.
 */
typedef krb5_error_code (*checksum_func)(const struct krb5_cksumtypes *ctp,
                                         krb5_key key, krb5_keyusage usage,
                                         const krb5_crypto_iov *data,
                                         size_t num_data,
                                         krb5_data *output);

/*
 * Verify a checksum over the header, data, padding, and sign-only fields of
 * the iov array data (of size num_data), and store the boolean result in
 * *valid.  The handler can assume that hash has length ctp->output_size.  If
 * ctp->enc is not NULL, the handler can assume that key a valid-length key of
 * an enctype which uses that enc provider.
 */
typedef krb5_error_code (*verify_func)(const struct krb5_cksumtypes *ctp,
                                       krb5_key key, krb5_keyusage usage,
                                       const krb5_crypto_iov *data,
                                       size_t num_data,
                                       const krb5_data *input,
                                       krb5_boolean *valid);

struct krb5_cksumtypes {
    krb5_cksumtype ctype;
    char *name;
    char *aliases[2];
    char *out_string;
    const struct krb5_enc_provider *enc;
    const struct krb5_hash_provider *hash;
    checksum_func checksum;
    verify_func verify;         /* NULL means recompute checksum and compare */
    unsigned int compute_size;  /* Allocation size for checksum computation */
    unsigned int output_size;   /* Possibly truncated output size */
    krb5_flags flags;
};

#define CKSUM_UNKEYED          0x0001
#define CKSUM_NOT_COLL_PROOF   0x0002

extern const struct krb5_cksumtypes krb5int_cksumtypes_list[];
extern const size_t krb5int_cksumtypes_length;

/*** Prototypes for enctype table functions ***/

/* Length */
unsigned int krb5int_old_crypto_length(const struct krb5_keytypes *ktp,
                                       krb5_cryptotype type);
unsigned int krb5int_raw_crypto_length(const struct krb5_keytypes *ktp,
                                       krb5_cryptotype type);
unsigned int krb5int_arcfour_crypto_length(const struct krb5_keytypes *ktp,
                                           krb5_cryptotype type);
unsigned int krb5int_dk_crypto_length(const struct krb5_keytypes *ktp,
                                      krb5_cryptotype type);
unsigned int krb5int_aes_crypto_length(const struct krb5_keytypes *ktp,
                                       krb5_cryptotype type);
unsigned int krb5int_camellia_crypto_length(const struct krb5_keytypes *ktp,
                                            krb5_cryptotype type);

/* Encrypt */
krb5_error_code krb5int_old_encrypt(const struct krb5_keytypes *ktp,
                                    krb5_key key, krb5_keyusage usage,
                                    const krb5_data *ivec,
                                    krb5_crypto_iov *data, size_t num_data);
krb5_error_code krb5int_raw_encrypt(const struct krb5_keytypes *ktp,
                                    krb5_key key, krb5_keyusage usage,
                                    const krb5_data *ivec,
                                    krb5_crypto_iov *data, size_t num_data);
krb5_error_code krb5int_arcfour_encrypt(const struct krb5_keytypes *ktp,
                                        krb5_key key, krb5_keyusage usage,
                                        const krb5_data *ivec,
                                        krb5_crypto_iov *data,
                                        size_t num_data);
krb5_error_code krb5int_dk_encrypt(const struct krb5_keytypes *ktp,
                                   krb5_key key, krb5_keyusage usage,
                                   const krb5_data *ivec,
                                   krb5_crypto_iov *data, size_t num_data);
krb5_error_code krb5int_dk_cmac_encrypt(const struct krb5_keytypes *ktp,
                                        krb5_key key, krb5_keyusage usage,
                                        const krb5_data *ivec,
                                        krb5_crypto_iov *data,
                                        size_t num_data);

/* Decrypt */
krb5_error_code krb5int_old_decrypt(const struct krb5_keytypes *ktp,
                                    krb5_key key, krb5_keyusage usage,
                                    const krb5_data *ivec,
                                    krb5_crypto_iov *data, size_t num_data);
krb5_error_code krb5int_raw_decrypt(const struct krb5_keytypes *ktp,
                                    krb5_key key, krb5_keyusage usage,
                                    const krb5_data *ivec,
                                    krb5_crypto_iov *data, size_t num_data);
krb5_error_code krb5int_arcfour_decrypt(const struct krb5_keytypes *ktp,
                                        krb5_key key, krb5_keyusage usage,
                                        const krb5_data *ivec,
                                        krb5_crypto_iov *data,
                                        size_t num_data);
krb5_error_code krb5int_dk_decrypt(const struct krb5_keytypes *ktp,
                                   krb5_key key, krb5_keyusage usage,
                                   const krb5_data *ivec,
                                   krb5_crypto_iov *data, size_t num_data);
krb5_error_code krb5int_dk_cmac_decrypt(const struct krb5_keytypes *ktp,
                                        krb5_key key, krb5_keyusage usage,
                                        const krb5_data *ivec,
                                        krb5_crypto_iov *data,
                                        size_t num_data);

/* String to key */
krb5_error_code krb5int_des_string_to_key(const struct krb5_keytypes *ktp,
                                          const krb5_data *string,
                                          const krb5_data *salt,
                                          const krb5_data *params,
                                          krb5_keyblock *key);
krb5_error_code krb5int_arcfour_string_to_key(const struct krb5_keytypes *ktp,
                                              const krb5_data *string,
                                              const krb5_data *salt,
                                              const krb5_data *params,
                                              krb5_keyblock *key);
krb5_error_code krb5int_dk_string_to_key(const struct krb5_keytypes *enc,
                                         const krb5_data *string,
                                         const krb5_data *salt,
                                         const krb5_data *params,
                                         krb5_keyblock *key);
krb5_error_code krb5int_aes_string_to_key(const struct krb5_keytypes *enc,
                                          const krb5_data *string,
                                          const krb5_data *salt,
                                          const krb5_data *params,
                                          krb5_keyblock *key);
krb5_error_code krb5int_camellia_string_to_key(const struct krb5_keytypes *enc,
                                               const krb5_data *string,
                                               const krb5_data *salt,
                                               const krb5_data *params,
                                               krb5_keyblock *key);

/* Random to key */
krb5_error_code k5_rand2key_direct(const krb5_data *randombits,
                                   krb5_keyblock *keyblock);
krb5_error_code k5_rand2key_des(const krb5_data *randombits,
                                krb5_keyblock *keyblock);
krb5_error_code k5_rand2key_des3(const krb5_data *randombits,
                                 krb5_keyblock *keyblock);

/* Pseudo-random function */
krb5_error_code krb5int_des_prf(const struct krb5_keytypes *ktp,
                                krb5_key key, const krb5_data *in,
                                krb5_data *out);
krb5_error_code krb5int_arcfour_prf(const struct krb5_keytypes *ktp,
                                    krb5_key key, const krb5_data *in,
                                    krb5_data *out);
krb5_error_code krb5int_dk_prf(const struct krb5_keytypes *ktp, krb5_key key,
                               const krb5_data *in, krb5_data *out);
krb5_error_code krb5int_dk_cmac_prf(const struct krb5_keytypes *ktp,
                                    krb5_key key, const krb5_data *in,
                                    krb5_data *out);

/*** Prototypes for cksumtype handler functions ***/

krb5_error_code krb5int_unkeyed_checksum(const struct krb5_cksumtypes *ctp,
                                         krb5_key key, krb5_keyusage usage,
                                         const krb5_crypto_iov *data,
                                         size_t num_data,
                                         krb5_data *output);
krb5_error_code krb5int_cbc_checksum(const struct krb5_cksumtypes *ctp,
                                     krb5_key key, krb5_keyusage usage,
                                     const krb5_crypto_iov *data,
                                     size_t num_data,
                                     krb5_data *output);
krb5_error_code krb5int_hmacmd5_checksum(const struct krb5_cksumtypes *ctp,
                                         krb5_key key, krb5_keyusage usage,
                                         const krb5_crypto_iov *data,
                                         size_t num_data,
                                         krb5_data *output);
krb5_error_code krb5int_dk_checksum(const struct krb5_cksumtypes *ctp,
                                    krb5_key key, krb5_keyusage usage,
                                    const krb5_crypto_iov *data,
                                    size_t num_data, krb5_data *output);
krb5_error_code krb5int_dk_cmac_checksum(const struct krb5_cksumtypes *ctp,
                                         krb5_key key, krb5_keyusage usage,
                                         const krb5_crypto_iov *data,
                                         size_t num_data, krb5_data *output);
krb5_error_code krb5int_confounder_checksum(const struct krb5_cksumtypes *ctp,
                                            krb5_key key, krb5_keyusage usage,
                                            const krb5_crypto_iov *data,
                                            size_t num_data,
                                            krb5_data *output);
krb5_error_code krb5int_confounder_verify(const struct krb5_cksumtypes *ctp,
                                          krb5_key key, krb5_keyusage usage,
                                          const krb5_crypto_iov *data,
                                          size_t num_data,
                                          const krb5_data *input,
                                          krb5_boolean *valid);

/*** Key derivation functions ***/

enum deriv_alg {
    DERIVE_RFC3961,             /* RFC 3961 section 5.1 */
    DERIVE_SP800_108_CMAC       /* NIST SP 800-108 with CMAC as PRF */
};

krb5_error_code krb5int_derive_keyblock(const struct krb5_enc_provider *enc,
                                        krb5_key inkey, krb5_keyblock *outkey,
                                        const krb5_data *in_constant,
                                        enum deriv_alg alg);
krb5_error_code krb5int_derive_key(const struct krb5_enc_provider *enc,
                                   krb5_key inkey, krb5_key *outkey,
                                   const krb5_data *in_constant,
                                   enum deriv_alg alg);
krb5_error_code krb5int_derive_random(const struct krb5_enc_provider *enc,
                                      krb5_key inkey, krb5_data *outrnd,
                                      const krb5_data *in_constant,
                                      enum deriv_alg alg);

/*** Miscellaneous prototypes ***/

/* nfold algorithm from RFC 3961 */
void krb5int_nfold(unsigned int inbits, const unsigned char *in,
                   unsigned int outbits, unsigned char *out);

/* Compute a CMAC checksum over data. */
krb5_error_code krb5int_cmac_checksum(const struct krb5_enc_provider *enc,
                                      krb5_key key,
                                      const krb5_crypto_iov *data,
                                      size_t num_data,
                                      krb5_data *output);

/* Compute a CRC-32 checksum.  c is in-out to allow chaining; init to 0. */
#define CRC32_CKSUM_LENGTH 4
void mit_crc32(krb5_pointer in, size_t in_length, unsigned long *c);

/* Translate an RFC 3961 key usage to a Microsoft RC4 usage. */
krb5_keyusage krb5int_arcfour_translate_usage(krb5_keyusage usage);

/* Ensure library initialization has occurred. */
int krb5int_crypto_init(void);

/* DES default state initialization handler (used by module enc providers). */
krb5_error_code krb5int_des_init_state(const krb5_keyblock *key,
                                       krb5_keyusage keyusage,
                                       krb5_data *new_state);

/* Default state cleanup handler (used by module enc providers). */
void krb5int_default_free_state(krb5_data *state);

/*** Input/output vector processing declarations **/

#define ENCRYPT_CONF_IOV(_iov)  ((_iov)->flags == KRB5_CRYPTO_TYPE_HEADER)

#define ENCRYPT_DATA_IOV(_iov)  ((_iov)->flags == KRB5_CRYPTO_TYPE_DATA || \
                                 (_iov)->flags == KRB5_CRYPTO_TYPE_PADDING)

#define ENCRYPT_IOV(_iov)       (ENCRYPT_CONF_IOV(_iov) || ENCRYPT_DATA_IOV(_iov))

#define SIGN_IOV(_iov)          (ENCRYPT_IOV(_iov) ||                   \
                                 (_iov)->flags == KRB5_CRYPTO_TYPE_SIGN_ONLY )

struct iov_block_state {
    size_t iov_pos;                     /* index into iov array */
    size_t data_pos;                    /* index into iov contents */
    unsigned int ignore_header : 1;     /* have/should we process HEADER */
    unsigned int include_sign_only : 1; /* should we process SIGN_ONLY blocks */
    unsigned int pad_to_boundary : 1;   /* should we zero fill blocks until next buffer */
};

#define IOV_BLOCK_STATE_INIT(_state)    ((_state)->iov_pos =            \
                                         (_state)->data_pos =           \
                                         (_state)->ignore_header =      \
                                         (_state)->include_sign_only =  \
                                         (_state)->pad_to_boundary = 0)

krb5_crypto_iov *krb5int_c_locate_iov(krb5_crypto_iov *data, size_t num_data,
                                      krb5_cryptotype type);

krb5_error_code krb5int_c_iov_decrypt_stream(const struct krb5_keytypes *ktp,
                                             krb5_key key,
                                             krb5_keyusage keyusage,
                                             const krb5_data *ivec,
                                             krb5_crypto_iov *data,
                                             size_t num_data);

unsigned int krb5int_c_padding_length(const struct krb5_keytypes *ktp,
                                      size_t data_length);

/*** Crypto module declarations ***/

/* Modules must implement the following enc_providers and hash_providers: */
extern const struct krb5_enc_provider krb5int_enc_des;
extern const struct krb5_enc_provider krb5int_enc_des3;
extern const struct krb5_enc_provider krb5int_enc_arcfour;
extern const struct krb5_enc_provider krb5int_enc_aes128;
extern const struct krb5_enc_provider krb5int_enc_aes256;
extern const struct krb5_enc_provider krb5int_enc_aes128_ctr;
extern const struct krb5_enc_provider krb5int_enc_aes256_ctr;
extern const struct krb5_enc_provider krb5int_enc_camellia128;
extern const struct krb5_enc_provider krb5int_enc_camellia256;

extern const struct krb5_hash_provider krb5int_hash_crc32;
extern const struct krb5_hash_provider krb5int_hash_md4;
extern const struct krb5_hash_provider krb5int_hash_md5;
extern const struct krb5_hash_provider krb5int_hash_sha1;

/* Modules must implement the following functions. */

/* Set the parity bits to the correct values in keybits. */
void k5_des_fixup_key_parity(unsigned char *keybits);

/* Return true if keybits is a weak or semi-weak DES key. */
krb5_boolean k5_des_is_weak_key(unsigned char *keybits);

/* Compute an HMAC using the provided hash function, key, and data, storing the
 * result into output (caller-allocated). */
krb5_error_code krb5int_hmac(const struct krb5_hash_provider *hash,
                             krb5_key key, const krb5_crypto_iov *data,
                             size_t num_data, krb5_data *output);

/* As above, using a keyblock as the key input. */
krb5_error_code krb5int_hmac_keyblock(const struct krb5_hash_provider *hash,
                                      const krb5_keyblock *keyblock,
                                      const krb5_crypto_iov *data,
                                      size_t num_data, krb5_data *output);

/*
 * Compute the PBKDF2 (see RFC 2898) of password and salt, with the specified
 * count, using HMAC-SHA-1 as the pseudorandom function, storing the result
 * into out (caller-allocated).
 */
krb5_error_code krb5int_pbkdf2_hmac_sha1(const krb5_data *out,
                                         unsigned long count,
                                         const krb5_data *password,
                                         const krb5_data *salt);

/* The following are used by test programs and are just handler functions from
 * the AES and Camellia enc providers. */
krb5_error_code krb5int_aes_encrypt(krb5_key key, const krb5_data *ivec,
                                    krb5_crypto_iov *data, size_t num_data);
krb5_error_code krb5int_aes_decrypt(krb5_key key, const krb5_data *ivec,
                                    krb5_crypto_iov *data, size_t num_data);
krb5_error_code krb5int_camellia_cbc_mac(krb5_key key,
                                         const krb5_crypto_iov *data,
                                         size_t num_data, const krb5_data *iv,
                                         krb5_data *output);

/* These can be used to safely set up and tear down module global state. */
int krb5int_crypto_impl_init(void);
void krb5int_crypto_impl_cleanup(void);

/*
 * Modules must provide a crypto_mod.h header at the top level.  To work with
 * the default PRNG module (prng_fortuna.c), crypto_mod.h must #define or
 * prototype the following symbols:
 *
 *   aes_ctx - Stack-allocatable type for an AES-128 or AES-256 key schedule
 *   krb5int_aes_enc_key(key, keybits, ctxptr) -- initialize a key schedule
 *   krb5int_aes_enc_blk(in, out, ctxptr) -- encrypt a block
 *   SHA256_CTX - Stack-allocatable type for a SHA-256 hash state
 *   k5_sha256_init(ctxptr) - Initialize a hash state
 *   k5_sha256_update(ctxptr, data, size) -- Hash some data
 *   k5_sha256_final(ctxptr, out) -- Finalize a state, writing hash into out
 *
 * These functions must never fail on valid inputs, and contexts must remain
 * valid across forks.  If the module cannot meet those constraints, then it
 * should provide its own PRNG module and the build system should ensure that
 * it is used; for an example, see how nss uses prng_nss.
 *
 * The function symbols named above are also in the library export list (so
 * they can be used by the t_fortuna.c test code), so even if the module
 * defines them away or doesn't work with Fortuna, the module must provide
 * stubs; see stubs.c in the openssl or nss modules for examples.
 */

#include <crypto_mod.h>

/*** PRNG module declarations ***/

/*
 * PRNG modules must implement the following APIs from krb5.h:
 *   krb5_c_random_add_entropy
 *   krb5_c_random_make_octets
 *
 * PRNG modules should implement these functions.  They are called from the
 * crypto library init and cleanup functions, and can be used to setup and tear
 * down static state without thread safety concerns.
 */
int k5_prng_init(void);
void k5_prng_cleanup(void);

/* Used by PRNG modules to gather OS entropy.  Returns true on success. */
krb5_boolean k5_get_os_entropy(unsigned char *buf, size_t len);

/*** Inline helper functions ***/

/* Find an enctype by number in the enctypes table. */
static inline const struct krb5_keytypes *
find_enctype(krb5_enctype enctype)
{
    int i;

    for (i = 0; i < krb5int_enctypes_length; i++) {
        if (krb5int_enctypes_list[i].etype == enctype)
            break;
    }

    if (i == krb5int_enctypes_length)
        return NULL;
    return &krb5int_enctypes_list[i];
}

/* Find a checksum type by number in the cksumtypes table. */
static inline const struct krb5_cksumtypes *
find_cksumtype(krb5_cksumtype ctype)
{
    size_t i;

    for (i = 0; i < krb5int_cksumtypes_length; i++) {
        if (krb5int_cksumtypes_list[i].ctype == ctype)
            break;
    }

    if (i == krb5int_cksumtypes_length)
        return NULL;
    return &krb5int_cksumtypes_list[i];
}

/* Verify that a key is appropriate for a checksum type. */
static inline krb5_error_code
verify_key(const struct krb5_cksumtypes *ctp, krb5_key key)
{
    const struct krb5_keytypes *ktp;

    ktp = key ? find_enctype(key->keyblock.enctype) : NULL;
    if (ctp->enc != NULL && (!ktp || ktp->enc != ctp->enc))
        return KRB5_BAD_ENCTYPE;
    if (key && (!ktp || key->keyblock.length != ktp->enc->keylength))
        return KRB5_BAD_KEYSIZE;
    return 0;
}

/* Encrypt one block of plaintext in place, for block ciphers. */
static inline krb5_error_code
encrypt_block(const struct krb5_enc_provider *enc, krb5_key key,
              krb5_data *block)
{
    krb5_crypto_iov iov;

    /* Verify that this is a block cipher and block is the right length. */
    if (block->length != enc->block_size || enc->block_size == 1)
        return EINVAL;
    iov.flags = KRB5_CRYPTO_TYPE_DATA;
    iov.data = *block;
    if (enc->cbc_mac != NULL)   /* One-block cbc-mac with no ivec. */
        return enc->cbc_mac(key, &iov, 1, NULL, block);
    else                        /* Assume cbc-mode encrypt. */
        return enc->encrypt(key, 0, &iov, 1);
}

/* Decide whether to process an IOV block. */
static inline int
process_block_p(const krb5_crypto_iov *data, size_t num_data,
                struct iov_block_state *iov_state, size_t i)
{
    const krb5_crypto_iov *iov = &data[i];
    int process_block;

    switch (iov->flags) {
    case KRB5_CRYPTO_TYPE_SIGN_ONLY:
        process_block = iov_state->include_sign_only;
        break;
    case KRB5_CRYPTO_TYPE_PADDING:
        process_block = (iov_state->pad_to_boundary == 0);
        break;
    case KRB5_CRYPTO_TYPE_HEADER:
        process_block = (iov_state->ignore_header == 0);
        break;
    case KRB5_CRYPTO_TYPE_DATA:
        process_block = 1;
        break;
    default:
        process_block = 0;
        break;
    }

    return process_block;
}

/*
 * Returns TRUE if, having reached the end of the current buffer,
 * we should pad the rest of the block with zeros.
 */
static inline int
pad_to_boundary_p(const krb5_crypto_iov *data,
                  size_t num_data,
                  struct iov_block_state *iov_state,
                  size_t i,
                  size_t j)
{
    /* If the pad_to_boundary flag is unset, return FALSE */
    if (iov_state->pad_to_boundary == 0)
        return 0;

    /* If we haven't got any data, we need to get some */
    if (j == 0)
        return 0;

    /* No boundary between adjacent buffers marked for processing */
    if (data[iov_state->iov_pos].flags == data[i].flags)
        return 0;

    return 1;
}

/*
 * Retrieve a block from the IOV. If p is non-NULL and the next block is
 * completely contained within the current buffer, then *p will contain an
 * alias into the buffer; otherwise, a copy will be made into storage.
 *
 * After calling this function, encrypt the returned block and then call
 * krb5int_c_iov_put_block_nocopy() (with a separate output cursor). If
 * p was non-NULL on the call to get_block(), then pass that pointer in.
 */
static inline krb5_boolean
krb5int_c_iov_get_block_nocopy(unsigned char *storage,
                               size_t block_size,
                               const krb5_crypto_iov *data,
                               size_t num_data,
                               struct iov_block_state *iov_state,
                               unsigned char **p)
{
    size_t i, j = 0;

    if (p != NULL)
        *p = storage;

    for (i = iov_state->iov_pos; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];
        size_t nbytes;

        if (!process_block_p(data, num_data, iov_state, i))
            continue;

        if (pad_to_boundary_p(data, num_data, iov_state, i, j))
            break;

        iov_state->iov_pos = i;

        nbytes = iov->data.length - iov_state->data_pos;
        if (nbytes > block_size - j)
            nbytes = block_size - j;

        /*
         * If we can return a pointer into a complete block, then do so.
         */
        if (p != NULL && j == 0 && nbytes == block_size) {
            *p = (unsigned char *)iov->data.data + iov_state->data_pos;
        } else {
            memcpy(storage + j, iov->data.data + iov_state->data_pos, nbytes);
        }

        iov_state->data_pos += nbytes;
        j += nbytes;

        assert(j <= block_size);

        if (j == block_size)
            break;

        assert(iov_state->data_pos == iov->data.length);

        iov_state->data_pos = 0;
    }

    iov_state->iov_pos = i;

    if (j == 0)
        return FALSE;
    else if (j != block_size)
        memset(storage + j, 0, block_size - j);

    return TRUE;
}

/*
 * Store a block retrieved with krb5int_c_iov_get_block_no_copy if
 * necessary, and advance the output cursor.
 */
static inline krb5_boolean
krb5int_c_iov_put_block_nocopy(const krb5_crypto_iov *data,
                               size_t num_data,
                               unsigned char *storage,
                               size_t block_size,
                               struct iov_block_state *iov_state,
                               unsigned char *p)
{
    size_t i, j = 0;

    assert(p != NULL);

    for (i = iov_state->iov_pos; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];
        size_t nbytes;

        if (!process_block_p(data, num_data, iov_state, i))
            continue;

        if (pad_to_boundary_p(data, num_data, iov_state, i, j))
            break;

        iov_state->iov_pos = i;

        nbytes = iov->data.length - iov_state->data_pos;
        if (nbytes > block_size - j)
            nbytes = block_size - j;

        /*
         * If we had previously returned a pointer into a complete block,
         * then no action is required.
         */
        if (p == storage) {
            memcpy(iov->data.data + iov_state->data_pos, storage + j, nbytes);
        } else {
            /* Ensure correctly paired with a call to get_block_nocopy(). */
            assert(j == 0);
            assert(nbytes == 0 || nbytes == block_size);
        }

        iov_state->data_pos += nbytes;
        j += nbytes;

        assert(j <= block_size);

        if (j == block_size)
            break;

        assert(iov_state->data_pos == iov->data.length);

        iov_state->data_pos = 0;
    }

    iov_state->iov_pos = i;

#ifdef DEBUG_IOV
    dump_block("put_block", i, j, p, block_size);
#endif

    return (iov_state->iov_pos < num_data);
}

/*
 * A wrapper for krb5int_c_iov_get_block_nocopy() that always makes
 * a copy.
 */
static inline krb5_boolean
krb5int_c_iov_get_block(unsigned char *block,
                        size_t block_size,
                        const krb5_crypto_iov *data,
                        size_t num_data,
                        struct iov_block_state *iov_state)
{
    return krb5int_c_iov_get_block_nocopy(block, block_size, data, num_data,
                                          iov_state, NULL);
}

/*
 * A wrapper for krb5int_c_iov_put_block_nocopy() that always copies
 * the block.
 */
static inline krb5_boolean
krb5int_c_iov_put_block(const krb5_crypto_iov *data,
                        size_t num_data,
                        unsigned char *block,
                        size_t block_size,
                        struct iov_block_state *iov_state)
{
    return krb5int_c_iov_put_block_nocopy(data, num_data, block, block_size,
                                          iov_state, block);
}

#endif /* CRYPTO_INT_H */
