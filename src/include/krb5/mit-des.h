/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * MIT Data Encryption Standard software implementation declarations.
 */


#ifndef KRB5_MIT_DES__
#define KRB5_MIT_DES__

typedef krb5_octet mit_des_cblock[8];	/* crypto-block size */

/* Key schedule--used internally by DES routines to gain some speed */
typedef struct mit_des_ks_struct {
    mit_des_cblock _;
} mit_des_key_schedule[16];

#define MIT_DES_ENCRYPT	1
#define MIT_DES_DECRYPT	0

typedef struct mit_des_ran_key_seed {
    krb5_octet sequence_number[8];
    mit_des_key_schedule random_sequence_key;
} mit_des_random_key_seed;

/* the first byte of the key is already in the keyblock */

#define MIT_DES_BLOCK_LENGTH 		(8*sizeof(krb5_octet))
#define	MIT_DES_CBC_CRC_PAD_MINIMUM	CRC32_CKSUM_LENGTH
#define MIT_DES_KEYSIZE		 	(8*sizeof(krb5_octet))

#define MIT_DES_CBC_CKSUM_LENGTH	(4*sizeof(krb5_octet))

/* cryptosystem entry descriptor for MIT's DES encryption library */
extern krb5_cryptosystem_entry  mit_des_cryptosystem_entry;
extern krb5_checksum_entry	mit_des_cbc_cksumtable_entry;

#endif /* KRB5_MIT_DES__ */
