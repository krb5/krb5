/*
 * lib/crypto/des/des_int.h
 *
 * Copyright 1987, 1988, 1990, 2002 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Private include file for the Data Encryption Standard library.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* only do the whole thing once	 */
#ifndef DES_INTERNAL_DEFS
#define DES_INTERNAL_DEFS

#include "k5-int.h"
/*
 * Begin "mit-des.h"
 */
#ifndef KRB5_MIT_DES__
#define KRB5_MIT_DES__

#define KRB5INT_CRYPTO_DES_INT	/* skip krb4-specific DES stuff */
#include "kerberosIV/des.h"	/* for des_key_schedule, etc. */
#undef KRB5INT_CRYPTO_DES_INT	/* don't screw other inclusions of des.h */

typedef des_cblock mit_des_cblock;
typedef des_key_schedule mit_des_key_schedule;

/* Triple-DES structures */
typedef mit_des_cblock		mit_des3_cblock[3];
typedef mit_des_key_schedule	mit_des3_key_schedule[3];

#define MIT_DES_ENCRYPT	1
#define MIT_DES_DECRYPT	0

typedef struct mit_des_ran_key_seed {
    krb5_encrypt_block eblock;
    krb5_data sequence;
} mit_des_random_state;

/* the first byte of the key is already in the keyblock */

#define MIT_DES_BLOCK_LENGTH 		(8*sizeof(krb5_octet))
#define	MIT_DES_CBC_CRC_PAD_MINIMUM	CRC32_CKSUM_LENGTH
/* This used to be 8*sizeof(krb5_octet) */
#define MIT_DES_KEYSIZE		 	8

#define MIT_DES_CBC_CKSUM_LENGTH	(4*sizeof(krb5_octet))

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

/* afsstring2key.c */
extern krb5_error_code mit_afs_string_to_key
	(krb5_keyblock *keyblock,
		   const krb5_data *data,
		   const krb5_data *salt);
extern char *mit_afs_crypt
    (const char *pw, const char *salt, char *iobuf);

/* f_cksum.c */
extern unsigned long mit_des_cbc_cksum
    (const krb5_octet *, krb5_octet *, unsigned long ,
     const mit_des_key_schedule, const krb5_octet *);

/* f_ecb.c */
extern int mit_des_ecb_encrypt
    (const mit_des_cblock *, mit_des_cblock *, mit_des_key_schedule , int );

/* f_cbc.c */
extern int mit_des_cbc_encrypt (const mit_des_cblock *in,
				mit_des_cblock *out,
				unsigned long length,
				const mit_des_key_schedule schedule,
				const mit_des_cblock ivec, int enc);
    
/* fin_rndkey.c */
extern krb5_error_code mit_des_finish_random_key
    ( const krb5_encrypt_block *,
		krb5_pointer *);

/* finish_key.c */
extern krb5_error_code mit_des_finish_key
    ( krb5_encrypt_block *);

/* init_rkey.c */
extern krb5_error_code mit_des_init_random_key
    ( const krb5_encrypt_block *,
		const krb5_keyblock *,
		krb5_pointer *);

/* key_parity.c */
extern void mit_des_fixup_key_parity (mit_des_cblock );
extern int mit_des_check_key_parity (mit_des_cblock );

/* key_sched.c */
extern int mit_des_key_sched
    (mit_des_cblock , mit_des_key_schedule );

/* process_ky.c */
extern krb5_error_code mit_des_process_key
    ( krb5_encrypt_block *,  const krb5_keyblock *);

/* random_key.c */
extern krb5_error_code mit_des_random_key
    ( const krb5_encrypt_block *, krb5_pointer ,
                krb5_keyblock **);

/* string2key.c */
extern krb5_error_code mit_des_string_to_key
    ( const krb5_encrypt_block *, 
	       krb5_keyblock *, const krb5_data *, const krb5_data *);
extern krb5_error_code mit_des_string_to_key_int
	(krb5_keyblock *, const krb5_data *, const krb5_data *);

/* weak_key.c */
extern int mit_des_is_weak_key (mit_des_cblock );

/* cmb_keys.c */
krb5_error_code mit_des_combine_subkeys
    (const krb5_keyblock *, const krb5_keyblock *,
	       krb5_keyblock **);

/* f_pcbc.c */
int mit_des_pcbc_encrypt ();

/* f_sched.c */
int mit_des_make_key_sched(mit_des_cblock, mit_des_key_schedule);


/* misc.c */
extern void swap_bits (char *);
extern unsigned long long_swap_bits (unsigned long );
extern unsigned long swap_six_bits_to_ansi (unsigned long );
extern unsigned long swap_four_bits_to_ansi (unsigned long );
extern unsigned long swap_bit_pos_1 (unsigned long );
extern unsigned long swap_bit_pos_0 (unsigned long );
extern unsigned long swap_bit_pos_0_to_ansi (unsigned long );
extern unsigned long rev_swap_bit_pos_0 (unsigned long );
extern unsigned long swap_byte_bits (unsigned long );
extern unsigned long swap_long_bytes_bit_number (unsigned long );
#ifdef FILE
/* XXX depends on FILE being a #define! */
extern void test_set (FILE *, const char *, int, const char *, int);
#endif

/* d3_ecb.c */
extern int mit_des3_ecb_encrypt
	(const mit_des_cblock *in,
		   mit_des_cblock *out,
		   mit_des_key_schedule sched1,
		   mit_des_key_schedule sched2,
		   mit_des_key_schedule sched3,
		   int enc);

/* d3_cbc.c */
extern int mit_des3_cbc_encrypt
	(const mit_des_cblock *in,
	 mit_des_cblock *out,
	 unsigned long length,
	 const mit_des_key_schedule ks1,
	 const mit_des_key_schedule ks2,
	 const mit_des_key_schedule ks3,
	 const mit_des_cblock ivec,
	 int enc);

/* d3_procky.c */
extern krb5_error_code mit_des3_process_key
	(krb5_encrypt_block * eblock,
		   const krb5_keyblock * keyblock);

/* d3_kysched.c */
extern int mit_des3_key_sched
	(mit_des3_cblock key,
		   mit_des3_key_schedule schedule);

/* d3_str2ky.c */
extern krb5_error_code mit_des3_string_to_key
	(const krb5_encrypt_block * eblock,
		   krb5_keyblock * keyblock,
		   const krb5_data * data,
		   const krb5_data * salt);

/* u_nfold.c */
extern krb5_error_code mit_des_n_fold
	(const krb5_octet * input,
		   const size_t in_len,
		   krb5_octet * output,
		   const size_t out_len);

/* u_rn_key.c */
extern int mit_des_is_weak_keyblock
	(krb5_keyblock *keyblock);

extern void mit_des_fixup_keyblock_parity
	(krb5_keyblock *keyblock);

extern krb5_error_code mit_des_set_random_generator_seed
	(const krb5_data * seed,
		   krb5_pointer random_state);

extern krb5_error_code mit_des_set_random_sequence_number
	(const krb5_data * sequence,
		   krb5_pointer random_state);

#endif	/*DES_INTERNAL_DEFS*/
