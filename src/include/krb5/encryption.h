/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Encryption interface-related declarations
 */

#include <krb5/copyright.h>

#ifndef __KRB5_ENCRYPTION__
#define __KRB5_ENCRYPTION__

typedef struct _krb5_keyblock {
    krb5_keytype keytype;
    int length;
    octet contents[1];			/* actually can be more, depending
					   on length */
} krb5_keyblock;

/* could be used in a table to find an etype and initialize a block */
typedef struct _krb5_cryptosystem_entry {
    int (*encrypt_func)(/* void *in, void *out, size_t length,
			   krb5_encrypt_block *block */);
    int (*decrypt_func)(/* void *in, void *out, size_t length,
			   krb5_encrypt_block *block */);
    int (*process_key)(/* krb5_encrypt_block *block, krb5_keyblock *key */);
    int (*finish_key)(/* krb5_encrypt_block *block */);
    int block_length;
    int pad_minimum;			/* needed for cksum size computation */
    int keysize;
} krb5_cryptosystem_entry;

typedef struct _krb5_encrypt_block {
    krb5_cryptosystem_entry *crypto_entry;
    krb5_keyblock *key;
    void *priv;				/* for private use, e.g. DES
					   key schedules */
} krb5_encrypt_block;

/* per Kerberos v5 protocol spec */
#define	KEYTYPE_NULL		0x0000
#define KEYTYPE_DES		0x0001	/* Data Encryption Standard,
					   FIPS 46,81 */
#define KEYTYPE_LUCIFER		0x0002	/* Lucifer */

#define	ETYPE_NULL		0x0000
#define	ETYPE_DES_CBC_CRC	0x0001	/* DES cbc mode with CRC-32 */
#define	ETYPE_LUCIFER_CRC	0x0002

#define	CKSUMTYPE_CRC32		0x0001
#define	CKSUMTYPE_XXX		0x0002
#define	CKSUMTYPE_XEROX		0x0003
#define	CKSUMTYPE_DESCBC	0x0004

/* macros to determine if a type is a local type */
#define KEYTYPE_IS_LOCAL(keytype) (keytype & 0x8000)
#define ETYPE_IS_LOCAL(etype) (etype & 0x8000)
#define CKSUMTYPE_IS_LOCAL(cksumtype) (cksumtype & 0x8000)

#endif /* __KRB5_ENCRYPTION__ */
