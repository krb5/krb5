/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YCIPHER_H
#define YCIPHER_H

/* block cipher interface */

/* default to 3DES for yarrow 160 */

#if !defined(YARROW_CIPHER_3DES) && !defined(YARROW_CIPHER_BLOWFISH)
#   if !defined(YARROW_CIPHER_IDEA)
#       define YARROW_CIPHER_3DES
#   endif
#endif

#if defined(YARROW_CIPHER_3DES)

/* For yarrow160 use 3 key 3DES */

#include "openssl/des.h"

/* first deal with DES */

typedef struct { des_key_schedule ks; } DES_CTX;

#define DES_BLOCK_SIZE DES_KEY_SZ

#define DES_PARITY_KEY_SIZE DES_KEY_SZ
/* effective key size, sans parity */
#define DES_KEY_SIZE (DES_PARITY_KEY_SIZE-1) 

/*  key schedule needs to stretch 56 bit key to 64 bit key leaving
 *  slots for parity bits 
 */

#define DES_Init( ctx, key )                               \
do {                                                       \
    byte parity_key[ DES_PARITY_KEY_SIZE ];                \
    void* parity_keyp = (void*)parity_key;                 \
    parity_key[ 0 ] = (key)[ 0 ];                          \
    parity_key[ 1 ] = (key)[ 0 ] << 7 | (key)[ 1 ] >> 2;   \
    parity_key[ 2 ] = (key)[ 1 ] << 6 | (key)[ 2 ] >> 3;   \
    parity_key[ 3 ] = (key)[ 2 ] << 5 | (key)[ 3 ] >> 4;   \
    parity_key[ 4 ] = (key)[ 3 ] << 4 | (key)[ 4 ] >> 5;   \
    parity_key[ 5 ] = (key)[ 4 ] << 3 | (key)[ 5 ] >> 6;   \
    parity_key[ 6 ] = (key)[ 5 ] << 2 | (key)[ 6 ] >> 7;   \
    parity_key[ 7 ] = (key)[ 6 ] << 1;                     \
    des_key_sched( (des_cblock*) parity_keyp, (ctx)->ks ); \
} while (0)

typedef struct 
{
    DES_CTX ks1, ks2, ks3;
} CIPHER_CTX;

#define CIPHER_BLOCK_SIZE DES_BLOCK_SIZE
#define CIPHER_KEY_SIZE (DES_KEY_SIZE * 3)

#if defined( YARROW_NO_MATHLIB )
/* see macros at end for functions evaluated */
#define POW_CIPHER_KEY_SIZE    72057594037927936.0
#define POW_CIPHER_BLOCK_SIZE  18446744073709551616.0
#endif

#define CIPHER_Init(ctx, key)                      \
do {                                               \
    DES_Init( &(ctx)->ks1, key );                  \
    DES_Init( &(ctx)->ks2, key+DES_KEY_SIZE );     \
    DES_Init( &(ctx)->ks3, key+2*DES_KEY_SIZE );   \
} while (0)

#define CIPHER_Encrypt_Block(ctx, in, out)\
    des_ecb3_encrypt((des_cblock*) in, (des_cblock*) out,\
                     (ctx)->ks1.ks, (ctx)->ks2.ks, (ctx)->ks3.ks, 1)

#elif defined(YARROW_CIPHER_BLOWFISH)

/* macros to allow blowfish */

#include "openssl/blowfish.h"

typedef struct 
{
    BF_KEY ks;
} CIPHER_CTX;

#define CIPHER_BLOCK_SIZE BF_BLOCK
#define CIPHER_KEY_SIZE 16

#if defined( YARROW_NO_MATHLIB )
/* see macros at end for functions evaluated */
#define POW_CIPHER_KEY_SIZE    6981463658331.6
#define POW_CIPHER_BLOCK_SIZE  18446744073709551616.0
#endif

#define CIPHER_Init(ctx, key)\
    BF_set_key(&(ctx)->ks, CIPHER_KEY_SIZE, (void*)key)
#define CIPHER_Encrypt_Block(ctx, in, out)\
    BF_ecb_encrypt((void*) in, (void*) out, &(ctx)->ks, 1)

#elif defined(YARROW_CIPHER_IDEA)

/* macros to allow IDEA */

#include "openssl/idea.h"

typedef struct 
{
    IDEA_KEY_SCHEDULE ks;
} CIPHER_CTX;

#define CIPHER_BLOCK_SIZE IDEA_BLOCK
#define CIPHER_KEY_SIZE IDEA_KEY_LENGTH

#if defined( YARROW_NO_MATHLIB )
/* see macros at end for functions evaluated */
#define POW_CIPHER_KEY_SIZE    6981463658331.55909006437584655441
#define POW_CIPHER_BLOCK_SIZE  18446744073709551616.000000
#endif

#define CIPHER_Init(ctx, key)\
    idea_set_encrypt_key((void*) key, &(ctx)->ks)

#define CIPHER_Encrypt_Block(ctx, in, out)\
    idea_ecb_encrypt((void*)in, (void*)out, &(ctx)->ks)

#endif

#if !defined( YARROW_NO_MATHLIB )
#define POW_CIPHER_KEY_SIZE pow(2.0, CIPHER_KEY_SIZE * 8 / 3.0)
#define POW_CIPHER_BLOCK_SIZE pow(2.0, CIPHER_BLOCK_SIZE * 8)
#endif

#endif /* YCIPHER_H */
