/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Encryption interface-related declarations
 */

#include <krb5/copyright.h>

#ifndef KRB5_ENCRYPTION__
#define KRB5_ENCRYPTION__

typedef struct _krb5_keyblock {
    krb5_keytype keytype;
    int length;
    krb5_octet *contents;
} krb5_keyblock;

typedef struct _krb5_checksum {
    krb5_cksumtype checksum_type;	/* checksum type */
    int length;
    krb5_octet *contents;
} krb5_checksum;

typedef struct _krb5_encrypt_block {
    struct _krb5_cryptosystem_entry *crypto_entry;
    krb5_keyblock *key;
    krb5_pointer priv;			/* for private use, e.g. DES
					   key schedules */
} krb5_encrypt_block;

/* could be used in a table to find an etype and initialize a block */
typedef struct _krb5_cryptosystem_entry {
    krb5_error_code (*encrypt_func) PROTOTYPE((const krb5_pointer /* in */,
					       krb5_pointer /* out */,
					       const size_t,
					       krb5_encrypt_block *));
    krb5_error_code (*decrypt_func) PROTOTYPE((const krb5_pointer /* in */,
					       krb5_pointer /* out */,
					       const size_t,
					       krb5_encrypt_block *));
    krb5_error_code (*process_key) PROTOTYPE((krb5_encrypt_block *,
					      const krb5_keyblock *));
    krb5_error_code (*finish_key) PROTOTYPE((krb5_encrypt_block *));
    krb5_error_code (*string_to_key) PROTOTYPE((const krb5_keytype,
						krb5_keyblock *,
						const krb5_data *,
						const krb5_principal));
    krb5_error_code  (*init_random_key) PROTOTYPE((const krb5_keyblock *,
						   krb5_pointer *));
    krb5_error_code  (*finish_random_key) PROTOTYPE((krb5_pointer *));
    krb5_error_code (*random_key) PROTOTYPE((krb5_pointer,
					     krb5_keyblock **));
    int block_length;
    int pad_minimum;			/* needed for cksum size computation */
    int keysize;
    krb5_enctype proto_enctype;		/* encryption type,
					   (assigned protocol number AND
					    table index) */
    krb5_keytype proto_keytype;		/* key type,
					   (assigned protocol number AND
					    table index) */
} krb5_cryptosystem_entry;

typedef struct _krb5_cs_table_entry {
    krb5_cryptosystem_entry *system;
    krb5_pointer random_sequence;	/* from init_random_key() */
} krb5_cs_table_entry;

/* could be used in a table to find a sumtype */
typedef struct _krb5_checksum_entry {
    krb5_error_code  (*sum_func) PROTOTYPE ((krb5_pointer /* in */,
					     krb5_pointer /* out */,
					     krb5_pointer /* seed */,
					     size_t /* in_length */,
					     size_t /* seed_length */,
					     krb5_checksum * /* out_cksum */));
    int checksum_length;		/* length of stuff returned by
					   sum_func */
} krb5_checksum_entry;

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

#ifndef krb5_roundup
/* round x up to nearest multiple of y */
#define krb5_roundup(x, y) ((((x) + (y) - 1)/(y))*(y))
#endif /* roundup */

/* macro function definitions to help clean up code */
#define	krb5_encrypt_size(length, crypto) \
     krb5_roundup((length)+(crypto)->pad_minimum, (crypto)->block_length)

/* This array is indexed by encryption type */
extern krb5_cs_table_entry *krb5_csarray[];
extern int krb5_max_cryptosystem;		/* max entry in array */

/* This array is indexed by key type, and has (should have) pointers to
   the same entries as krb5_csarray */
/* XXX what if a given keytype works for several etypes? */
extern krb5_cs_table_entry *krb5_keytype_array[];
extern int krb5_max_keytype;		/* max entry in array */

/* This array is indexed by checksum type */
extern krb5_checksum_entry *krb5_cksumarray[];
extern int krb5_max_cksum;		/* max entry in array */

#define valid_etype(etype)     ((etype <= krb5_max_cryptosystem) && (etype > 0) && krb5_csarray[etype])

#define valid_keytype(ktype)     ((ktype <= krb5_max_keytype) && (ktype > 0) && krb5_keytype_array[ktype])

#define valid_cksumtype(cktype)     ((cktype <= krb5_max_cksum) && (cktype > 0) && krb5_cksumarray[cktype])


#endif /* KRB5_ENCRYPTION__ */
