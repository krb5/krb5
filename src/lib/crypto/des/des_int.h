/*
 * $Source$
 * $Author$
 * $Id$ 
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Private include file for the Data Encryption Standard library.
 */

/* only do the whole thing once	 */
#ifndef DES_INTERNAL_DEFS
#define DES_INTERNAL_DEFS

#include <krb5/config.h>
#include <krb5/osconf.h>

/*
 * number of iterations of the inner
 * loop of the DES algorithm.  The
 * standard is 16, but in case that is
 * too slow, we might do less.  Of
 * course, less also means less
 * security.
 */
#define	 AUTH_DES_ITER   16

#ifdef  BITS32
/* these are for 32 bit machines */

typedef struct {
    unsigned b0:6;
    unsigned b1:6;
    unsigned b2:6;
    unsigned b3:6;
    unsigned b4:6;
    unsigned b5:2;
}       sbox_in_a;

typedef struct {
    unsigned b5:4;
    unsigned b6:6;
    unsigned b7:6;
}       sbox_in_b;

typedef struct {
    unsigned b0:4;
    unsigned b1:4;
    unsigned b2:4;
    unsigned b3:4;
    unsigned b4:4;
    unsigned b5:4;
    unsigned b6:4;
    unsigned b7:4;
}       sbox_out;

#else	/*BITS32*/
/* for sixteen bit machines */

typedef struct {
    unsigned b0:6;
    unsigned b1:6;
    unsigned b2:4;
}       sbox_in_16_a;

typedef struct {
    unsigned b2:2;
    unsigned b3:6;
    unsigned b4:6;
    unsigned b5:2;
}       sbox_in_16_b;

typedef struct {
    unsigned b5:4;
    unsigned b6:6;
    unsigned b7:6;
}       sbox_in_16_c;

typedef struct {
    unsigned b0:4;
    unsigned b1:4;
    unsigned b2:4;
    unsigned b3:4;
    unsigned b4:4;
    unsigned b5:4;
    unsigned b6:4;
    unsigned b7:4;
}       sbox_out;
#endif	/*BITS32*/


/* cbc_cksum.c */
krb5_error_code mit_des_cbc_checksum
    PROTOTYPE((krb5_pointer, size_t,krb5_pointer,size_t, krb5_checksum * ));

/* cksum.c */
void mit_des_cbc_cksum
    PROTOTYPE((krb5_octet *, krb5_octet *, long , mit_des_key_schedule ,
	       krb5_octet *));
/* des.c */
int des_ecb_encrypt
    PROTOTYPE((unsigned long *, unsigned long *, des_key_schedule , int ));

/* enc_dec.c */
krb5_error_code mit_des_encrypt_func
    PROTOTYPE(( krb5_pointer, krb5_pointer, size_t, krb5_encrypt_block *,
	       krb5_pointer ));
krb5_error_code mit_des_decrypt_func
    PROTOTYPE(( krb5_pointer, krb5_pointer, size_t, krb5_encrypt_block *,
	       krb5_pointer ));
krb5_error_code mit_des_cbc_encrypt
    PROTOTYPE((krb5_octet *, krb5_octet *, long, mit_des_key_schedule,
	       krb5_octet *, int));

/* fin_rndkey.c */
krb5_error_code mit_des_finish_random_key
    PROTOTYPE(( krb5_pointer *));

/* finish_key.c */
krb5_error_code mit_des_finish_key
    PROTOTYPE(( krb5_encrypt_block *));

/* init_rkey.c */
krb5_error_code mit_des_init_random_key
    PROTOTYPE(( krb5_keyblock *,  krb5_pointer *));

/* key_parity.c */
void mit_des_fixup_key_parity PROTOTYPE((mit_des_cblock ));
int mit_des_check_key_parity PROTOTYPE((mit_des_cblock ));

/* key_sched.c */
int mit_des_key_sched PROTOTYPE((mit_des_cblock , mit_des_key_schedule ));

/* new_rnd_key.c */
int mit_des_new_random_key PROTOTYPE((mit_des_cblock , mit_des_random_key_seed *));
void mit_des_init_random_number_generator
    PROTOTYPE((mit_des_cblock, mit_des_random_key_seed));
void mit_des_set_random_generator_seed
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed *));
void mit_des_set_sequence_number
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed *));
void mit_des_generate_random_block
    PROTOTYPE((mit_des_cblock , mit_des_random_key_seed *));

/* process_ky.c */
krb5_error_code mit_des_process_key
    PROTOTYPE(( krb5_encrypt_block *,  krb5_keyblock *));

/* random_key.c */
krb5_error_code mit_des_random_key
    PROTOTYPE(( krb5_pointer ,  krb5_keyblock **));

/* string2key.c */
krb5_error_code mit_des_string_to_key
    PROTOTYPE((krb5_keytype, krb5_keyblock *, krb5_data *, krb5_principal ));

/* weak_key.c */
int mit_des_is_weak_key PROTOTYPE((mit_des_cblock ));

#undef P
#endif	/*DES_INTERNAL_DEFS*/
