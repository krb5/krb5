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
 * MIT Data Encryption Standard software implementation declarations.
 */

#include <krb5/copyright.h>

#ifndef KRB5_MIT_DES__
#define KRB5_MIT_DES__

typedef krb5_octet des_cblock[8];	/* crypto-block size */

/* Key schedule--used internally by DES routines to gain some speed */
typedef struct des_ks_struct { des_cblock _; } des_key_schedule[16];

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

typedef struct des_ran_key_seed {
    krb5_octet sequence_number[8];
    des_key_schedule random_sequence_key;
} des_random_key_seed;

/* the first byte of the key is already in the keyblock */
#define DES_KEYBLOCK_SZ	(sizeof(krb5_keyblock)+sizeof(des_cblock)-sizeof(krb5_octet))

#define DES_BLOCK_LENGTH 		(8*sizeof(krb5_octet))
#define	DES_CBC_CRC_PAD_MINIMUM		CRC32_CKSUM_LENGTH
#define DES_KEYSIZE		 	(8*sizeof(krb5_octet))

#define DES_CBC_CKSUM_LENGTH		(4*sizeof(krb5_octet)) /* XXX ? */

/* cryptosystem entry descriptor for MIT's DES encryption library */
extern krb5_cryptosystem_entry  mit_des_cryptosystem_entry;
extern krb5_checksum_entry	des_cbc_cksumtable_entry;

#endif /* KRB5_MIT_DES__ */
