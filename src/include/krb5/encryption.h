/*
 * include/krb5/encryption.h
 *
 * Copyright 1989,1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Encryption interface-related declarations
 */


#ifndef KRB5_ENCRYPTION__
#define KRB5_ENCRYPTION__

typedef struct _krb5_keyblock {
    krb5_magic magic;
    krb5_keytype keytype;
    krb5_enctype etype;	/* hint of what encryption type to use */
    int length;
    krb5_octet *contents;
} krb5_keyblock;

typedef struct _krb5_checksum {
    krb5_magic magic;
    krb5_cksumtype checksum_type;	/* checksum type */
    int length;
    krb5_octet *contents;
} krb5_checksum;

typedef struct _krb5_encrypt_block {
    krb5_magic magic;
    struct _krb5_cryptosystem_entry *crypto_entry;
    krb5_keyblock *key;
    krb5_pointer priv;			/* for private use, e.g. DES
					   key schedules */
} krb5_encrypt_block;

typedef struct _krb5_enc_data {
    krb5_magic magic;
    krb5_enctype etype;
    krb5_kvno kvno;
    krb5_data ciphertext;
} krb5_enc_data;

/* could be used in a table to find an etype and initialize a block */
typedef struct _krb5_cryptosystem_entry {
    krb5_magic magic;
    krb5_error_code (*encrypt_func) NPROTOTYPE(( krb5_const_pointer /* in */,
					       krb5_pointer /* out */,
					       const size_t,
					       krb5_encrypt_block *,
					       krb5_pointer));
    krb5_error_code (*decrypt_func) NPROTOTYPE(( krb5_const_pointer /* in */,
					       krb5_pointer /* out */,
					       const size_t,
					       krb5_encrypt_block *,
					       krb5_pointer));
    krb5_error_code (*process_key) NPROTOTYPE(( krb5_encrypt_block *,
					      const krb5_keyblock *));
    krb5_error_code (*finish_key) NPROTOTYPE(( krb5_encrypt_block *));
    krb5_error_code (*string_to_key) NPROTOTYPE(( const krb5_encrypt_block *,
						 const krb5_keytype,
						krb5_keyblock *,
						const krb5_data *,
 	                                        const krb5_data *));
    krb5_error_code  (*init_random_key) NPROTOTYPE(( const krb5_keyblock *,
						   krb5_pointer *));
    krb5_error_code  (*finish_random_key) NPROTOTYPE(( krb5_pointer *));
    krb5_error_code (*random_key) NPROTOTYPE(( const krb5_encrypt_block *,
					      krb5_pointer,
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
    krb5_magic magic;
    krb5_cryptosystem_entry *system;
    krb5_pointer random_sequence;	/* from init_random_key() */
} krb5_cs_table_entry;

/* could be used in a table to find a sumtype */
typedef struct _krb5_checksum_entry {
    krb5_magic magic;
    krb5_error_code  (*sum_func) NPROTOTYPE (( krb5_pointer /* in */,
					     size_t /* in_length */,
					     krb5_pointer /* key/seed */,
					     size_t /* key/seed size */,
					     krb5_checksum * /* out_cksum */));
    int checksum_length;		/* length of stuff returned by
					   sum_func */
    unsigned int is_collision_proof:1;
    unsigned int uses_key:1;
} krb5_checksum_entry;

/* per Kerberos v5 protocol spec */
#define	KEYTYPE_NULL		0x0000
#define KEYTYPE_DES		0x0001	/* Data Encryption Standard,
					   FIPS 46,81 */

#define	ETYPE_NULL		0x0000
#define	ETYPE_DES_CBC_CRC	0x0001	/* DES cbc mode with CRC-32 */
#define	ETYPE_DES_CBC_MD4	0x0002	/* DES cbc mode with RSA-MD4 */
#define	ETYPE_DES_CBC_MD5	0x0003	/* DES cbc mode with RSA-MD5 */
#define	ETYPE_RAW_DES_CBC       0x0004  /* Raw DES cbc mode */

#define ETYPE_UNKNOWN		0x1FF 	/* Reserved local value */

#define	CKSUMTYPE_CRC32		0x0001
#define	CKSUMTYPE_RSA_MD4	0x0002
#define	CKSUMTYPE_RSA_MD4_DES	0x0003
#define	CKSUMTYPE_DESCBC	0x0004
/* des-mac-k */
/* rsa-md4-des-k */
#define	CKSUMTYPE_RSA_MD5	0x0007
#define	CKSUMTYPE_RSA_MD5_DES	0x0008

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

#define valid_etype(etype)     ((((int) etype) <= krb5_max_cryptosystem) && (etype > 0) && krb5_csarray[etype])

#define valid_keytype(ktype)     ((((int) ktype) <= krb5_max_keytype) && (ktype > 0) && krb5_keytype_array[ktype])

#define valid_cksumtype(cktype)     ((((int) cktype) <= krb5_max_cksum) && (cktype > 0) && krb5_cksumarray[cktype])

#define is_coll_proof_cksum(cktype) (krb5_cksumarray[cktype]->is_collision_proof)
#define is_keyed_cksum(cktype) (krb5_cksumarray[cktype]->uses_key)

/* set up *eblockp to use etype */
#define krb5_use_cstype(context, eblockp, etype) (eblockp)->crypto_entry = krb5_csarray[(etype)]->system
/* ...or keytype */
#define krb5_use_keytype(context, eblockp, keytype) (eblockp)->crypto_entry = krb5_keytype_array[(keytype)]->system

#define krb5_encrypt(context, inptr, outptr, size, eblock, ivec) (*(eblock)->crypto_entry->encrypt_func)(inptr, outptr, size, eblock, ivec)
#define krb5_decrypt(context, inptr, outptr, size, eblock, ivec) (*(eblock)->crypto_entry->decrypt_func)(inptr, outptr, size, eblock, ivec)
#define krb5_process_key(context, eblock, key) (*(eblock)->crypto_entry->process_key)(eblock, key)
#define krb5_finish_key(context, eblock) (*(eblock)->crypto_entry->finish_key)(eblock)
#define krb5_string_to_key(context, eblock, keytype, keyblock, data, princ) (*(eblock)->crypto_entry->string_to_key)(eblock, keytype, keyblock, data, princ)
#define krb5_init_random_key(context, eblock, keyblock, ptr) (*(eblock)->crypto_entry->init_random_key)(keyblock, ptr)
#define krb5_finish_random_key(context, eblock, ptr) (*(eblock)->crypto_entry->finish_random_key)(ptr)
#define krb5_random_key(context, eblock, ptr, keyblock) (*(eblock)->crypto_entry->random_key)(eblock, ptr, keyblock)

#define krb5_eblock_keytype(context, eblockp) ((eblockp)->crypto_entry->proto_keytype)
#define krb5_eblock_enctype(context, eblockp) ((eblockp)->crypto_entry->proto_enctype)

/*
 * Here's the stuff for the checksum switch:
 */
#define krb5_checksum_size(context, ctype)  (krb5_cksumarray[ctype]->checksum_length)
#define krb5_calculate_checksum(context, ctype, in, in_length, seed, seed_length, outcksum) ((*krb5_cksumarray[ctype]->sum_func)(in, in_length, seed, seed_length, outcksum))

#endif /* KRB5_ENCRYPTION__ */
