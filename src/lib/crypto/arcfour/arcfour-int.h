/*

ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
This cipher is widely believed and has been tested to be equivalent
with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
of RSA Data Security)

*/
#ifndef ARCFOUR_INT_H
#define ARCFOUR_INT_H

#include "arcfour.h"

#define CONFOUNDERLENGTH 8

typedef struct
{
   unsigned int x;
   unsigned int y;
   unsigned char state[256];
} ArcfourContext;

/* gets the next byte from the PRNG */
static inline unsigned int k5_arcfour_byte(ArcfourContext *);

/* Initializes the context and sets the key. */
static krb5_error_code k5_arcfour_init(ArcfourContext *ctx, const unsigned char *key, 
		  unsigned int keylen);

/* Encrypts/decrypts data. */
static void k5_arcfour_crypt(ArcfourContext *ctx, unsigned char *dest, 
		     const unsigned char *src, unsigned int len);

/* Interface layer to kerb5 crypto layer */
static krb5_error_code
k5_arcfour_docrypt(krb5_const krb5_keyblock *, krb5_const krb5_data *,
		   krb5_const krb5_data *, krb5_data *);


/* The blocksize for the enctype */
static void k5_arcfour_blocksize(size_t *);

/* keysize for the enctype (number of bytes, and length of key (parity/etc) */
static void k5_arcfour_keysize(size_t *, size_t *);

/* from a random bitstrem, construct a key */
static krb5_error_code
k5_arcfour_make_key(krb5_const krb5_data *, krb5_keyblock *);

#endif /* ARCFOUR_INT_H */
