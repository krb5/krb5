/*
 * lib/crypto/des/des_int.h
 *
 * Copyright 1987, 1988, 1990 by the Massachusetts Institute of Technology.
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
 * Private include file for the Data Encryption Standard library.
 */

/* only do the whole thing once	 */
#ifndef DES_INTERNAL_DEFS
#define DES_INTERNAL_DEFS

/*
 * Begin "mit-des.h"
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
/* This used to be 8*sizeof(krb5_octet) */
#define MIT_DES_KEYSIZE		 	8

#define MIT_DES_CBC_CKSUM_LENGTH	(4*sizeof(krb5_octet))

/* cryptosystem entry descriptor for MIT's DES encryption library */
extern krb5_cs_table_entry krb5_raw_des_cst_entry;
extern krb5_cs_table_entry krb5_des_crc_cst_entry;
extern krb5_cs_table_entry krb5_des_md5_cst_entry;
extern krb5_checksum_entry	krb5_des_cbc_cksumtable_entry;

/*
 * Check if k5-int.h has been included before us.  If so, then check to see
 * that our view of the DES key size is the same as k5-int.h's.
 */
#ifdef	KRB5_MIT_DES_KEYSIZE
#if	MIT_DES_KEYSIZE != KRB5_MIT_DES_KEYSIZE
error(MIT_DES_KEYSIZE does not equal KRB5_MIT_DES_KEYSIZE)
#endif	/* MIT_DES_KEYSIZE != KRB5_MIT_DES_KEYSIZE */
#endif	/* KRB5_MIT_DES_KEYSIZE */
#endif /* KRB5_MIT_DES__ */
/*
 * End "mit-des.h"
 */

/* cbc_cksum.c */
extern krb5_error_code mit_des_cbc_checksum
    PROTOTYPE((krb5_pointer, size_t,krb5_pointer,size_t, krb5_checksum FAR * ));

extern krb5_error_code mit_des_cbc_verf_cksum
    PROTOTYPE ((krb5_checksum FAR *, krb5_pointer, size_t, krb5_pointer,
                size_t ));


/* f_cksum.c */
extern unsigned long mit_des_cbc_cksum
    PROTOTYPE((krb5_octet FAR *, krb5_octet FAR *, long , mit_des_key_schedule ,
	       krb5_octet FAR *));

/* f_ecb.c */
extern int mit_des_ecb_encrypt
    PROTOTYPE((mit_des_cblock FAR *, mit_des_cblock FAR *, mit_des_key_schedule , int ));

/* f_cbc.c */
extern int mit_des_cbc_encrypt
    PROTOTYPE((const mit_des_cblock FAR *in, mit_des_cblock FAR *out, long length,
	       mit_des_key_schedule schedule, mit_des_cblock ivec,
	       int encrypt));
    
/* fin_rndkey.c */
extern krb5_error_code mit_des_finish_random_key
    PROTOTYPE(( krb5_pointer FAR *));

/* finish_key.c */
extern krb5_error_code mit_des_finish_key
    PROTOTYPE(( krb5_encrypt_block FAR *));

/* init_rkey.c */
extern krb5_error_code mit_des_init_random_key
    PROTOTYPE(( const krb5_keyblock FAR *,  krb5_pointer FAR *));

/* key_parity.c */
extern void mit_des_fixup_key_parity PROTOTYPE((mit_des_cblock ));
extern int mit_des_check_key_parity PROTOTYPE((mit_des_cblock ));

/* key_sched.c */
extern int mit_des_key_sched
    PROTOTYPE((mit_des_cblock , mit_des_key_schedule ));

/* new_rnd_key.c */
extern int mit_des_new_random_key
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed FAR *));
extern void mit_des_init_random_number_generator
    PROTOTYPE((mit_des_cblock, mit_des_random_key_seed FAR *));
extern void mit_des_set_random_generator_seed
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed FAR *));
extern void mit_des_set_sequence_number
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed FAR *));
extern void mit_des_generate_random_block
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed FAR *));

/* process_ky.c */
extern krb5_error_code mit_des_process_key
    PROTOTYPE(( krb5_encrypt_block FAR *,  const krb5_keyblock FAR *));

/* random_key.c */
extern krb5_error_code mit_des_random_key
    PROTOTYPE(( const krb5_encrypt_block FAR *, krb5_pointer ,
                krb5_keyblock FAR * FAR *));

/* string2key.c */
extern krb5_error_code mit_des_string_to_key
    PROTOTYPE(( const krb5_encrypt_block FAR *, const krb5_keytype,
	       krb5_keyblock FAR *, const krb5_data FAR *, const krb5_data FAR *));

/* weak_key.c */
extern int mit_des_is_weak_key PROTOTYPE((mit_des_cblock ));

/* cmb_keys.c */
krb5_error_code mit_des_combine_subkeys
    PROTOTYPE((const krb5_keyblock FAR *, const krb5_keyblock FAR *,
	       krb5_keyblock FAR * FAR *));

/* f_pcbc.c */
int mit_des_pcbc_encrypt ();

/* f_sched.c */
int make_key_sched PROTOTYPE((mit_des_cblock, mit_des_key_schedule));


/* misc.c */
extern void swap_bits PROTOTYPE((char FAR *));
extern unsigned long long_swap_bits PROTOTYPE((unsigned long ));
extern unsigned long swap_six_bits_to_ansi PROTOTYPE((unsigned long ));
extern unsigned long swap_four_bits_to_ansi PROTOTYPE((unsigned long ));
extern unsigned long swap_bit_pos_1 PROTOTYPE((unsigned long ));
extern unsigned long swap_bit_pos_0 PROTOTYPE((unsigned long ));
extern unsigned long swap_bit_pos_0_to_ansi PROTOTYPE((unsigned long ));
extern unsigned long rev_swap_bit_pos_0 PROTOTYPE((unsigned long ));
extern unsigned long swap_byte_bits PROTOTYPE((unsigned long ));
extern unsigned long swap_long_bytes_bit_number PROTOTYPE((unsigned long ));
#ifdef FILE
/* XXX depends on FILE being a #define! */
extern void test_set PROTOTYPE((FILE *, const char *, int, const char *, int));
#endif

#endif	/*DES_INTERNAL_DEFS*/
