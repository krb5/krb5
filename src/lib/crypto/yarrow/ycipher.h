/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YCIPHER_H
#define YCIPHER_H

/* block cipher interface */

typedef struct 
{
    krb5_keyblock key;
} CIPHER_CTX;

/* We need to choose a cipher. To do this, choose an enc_provider.
 * Be sure to update the block size and key size constants below;
 * they are here because static data structures are sized based on
 * them so they must be known at compile time./  Thus we cannot
 * call the enc_provider function to get the info.
 */

#define yarrow_enc_provider krb5int_enc_des3

#define CIPHER_BLOCK_SIZE 8
#define CIPHER_KEY_SIZE 21

#if defined( YARROW_NO_MATHLIB )
/* see macros at end for functions evaluated */
#define POW_CIPHER_KEY_SIZE    72057594037927936.0
#define POW_CIPHER_BLOCK_SIZE  18446744073709551616.0
#endif


int krb5int_yarrow_cipher_init (CIPHER_CTX *ctx, unsigned const char *key);
int krb5int_yarrow_cipher_encrypt_block
(CIPHER_CTX *ctx,  const unsigned char *in, unsigned char *out);

#if !defined( YARROW_NO_MATHLIB )
#define POW_CIPHER_KEY_SIZE pow(2.0, CIPHER_KEY_SIZE * 8 / 3.0)
#define POW_CIPHER_BLOCK_SIZE pow(2.0, CIPHER_BLOCK_SIZE * 8)
#endif

#endif /* YCIPHER_H */
