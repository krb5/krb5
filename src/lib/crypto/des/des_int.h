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

#include "mit-des.h"		/* From include/krb5 */

/* cbc_cksum.c */
extern krb5_error_code INTERFACE mit_des_cbc_checksum
    PROTOTYPE((krb5_pointer, size_t,krb5_pointer,size_t, krb5_checksum FAR * ));

/* cksum.c */
extern long INTERFACE mit_des_cbc_cksum
    PROTOTYPE((krb5_octet *, krb5_octet *, long , mit_des_key_schedule ,
	       krb5_octet *));
/* des.c */
extern int INTERFACE mit_des_ecb_encrypt
    PROTOTYPE((unsigned long *, unsigned long *, mit_des_key_schedule , int ));

/* f_cbc.c */
extern int INTERFACE mit_des_cbc_encrypt
    PROTOTYPE((const mit_des_cblock *in, mit_des_cblock *out, long length,
	       mit_des_key_schedule schedule, mit_des_cblock ivec,
	       int encrypt));
    
/* fin_rndkey.c */
extern krb5_error_code INTERFACE mit_des_finish_random_key
    PROTOTYPE(( krb5_pointer *));

/* finish_key.c */
extern krb5_error_code INTERFACE mit_des_finish_key
    PROTOTYPE(( krb5_encrypt_block FAR *));

/* init_rkey.c */
extern krb5_error_code INTERFACE mit_des_init_random_key
    PROTOTYPE(( const krb5_keyblock *,  krb5_pointer *));

/* key_parity.c */
extern void INTERFACE mit_des_fixup_key_parity PROTOTYPE((mit_des_cblock ));
extern int INTERFACE mit_des_check_key_parity PROTOTYPE((mit_des_cblock ));

/* key_sched.c */
extern int INTERFACE mit_des_key_sched
    PROTOTYPE((mit_des_cblock , mit_des_key_schedule ));

/* new_rnd_key.c */
extern int INTERFACE mit_des_new_random_key
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed *));
extern void INTERFACE mit_des_init_random_number_generator
    PROTOTYPE((mit_des_cblock, mit_des_random_key_seed *));
extern void INTERFACE mit_des_set_random_generator_seed
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed *));
extern void INTERFACE mit_des_set_sequence_number
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed *));
extern void INTERFACE mit_des_generate_random_block
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed *));

/* process_ky.c */
extern krb5_error_code INTERFACE mit_des_process_key
    PROTOTYPE(( krb5_encrypt_block *,  const krb5_keyblock *));

/* random_key.c */
extern krb5_error_code INTERFACE mit_des_random_key
    PROTOTYPE(( const krb5_encrypt_block *, krb5_pointer ,  krb5_keyblock **));

/* string2key.c */
extern krb5_error_code INTERFACE mit_des_string_to_key
    PROTOTYPE(( const krb5_encrypt_block *, const krb5_keytype,
	       krb5_keyblock *, const krb5_data *, const krb5_data *));

/* weak_key.c */
extern int INTERFACE mit_des_is_weak_key PROTOTYPE((mit_des_cblock ));

/* cmb_keys.c */
krb5_error_code mit_des_combine_subkeys
    PROTOTYPE((const krb5_keyblock *, const krb5_keyblock *,
	       krb5_keyblock **));

/* f_pcbc.c */
int INTERFACE mit_des_pcbc_encrypt ();

/* f_sched.c */
int INTERFACE make_key_sched PROTOTYPE((mit_des_cblock, mit_des_key_schedule));


/* misc.c */
extern void swap_bits PROTOTYPE((char *));
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
