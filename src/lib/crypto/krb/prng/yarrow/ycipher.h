/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef YCIPHER_H
#define YCIPHER_H

/* block cipher interface */

typedef struct
{
    krb5_key key;
} CIPHER_CTX;

/* We need to choose a cipher. To do this, choose an enc_provider.
 * Be sure to update the block size and key size constants below;
 * they are here because static data structures are sized based on
 * them so they must be known at compile time./  Thus we cannot
 * call the enc_provider function to get the info.
 */

#define yarrow_enc_provider krb5int_enc_aes256
#define yarrow_enc_type     ENCTYPE_AES256_CTS_HMAC_SHA1_96

#define CIPHER_BLOCK_SIZE 16
#define CIPHER_KEY_SIZE 32

#if defined( YARROW_NO_MATHLIB )
/* see macros at end for functions evaluated */
#define POW_CIPHER_KEY_SIZE    115792089237316195423570985008687907853269984665640564039457584007913129639936.0
#define POW_CIPHER_BLOCK_SIZE  340282366920938463463374607431768211456.0
#endif


int krb5int_yarrow_cipher_init (CIPHER_CTX *ctx, unsigned const char *key);
int krb5int_yarrow_cipher_encrypt_block
(CIPHER_CTX *ctx,  const unsigned char *in, unsigned char *out);
void krb5int_yarrow_cipher_final (CIPHER_CTX *ctx);

#if !defined( YARROW_NO_MATHLIB )
#define POW_CIPHER_KEY_SIZE pow(2.0, CIPHER_KEY_SIZE * 8 / 3.0)
#define POW_CIPHER_BLOCK_SIZE pow(2.0, CIPHER_BLOCK_SIZE * 8)
#endif

#endif /* YCIPHER_H */
