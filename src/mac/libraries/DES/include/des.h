/*
 * des.h
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h> (Except for those files which contain other copyright information).
 *
 * Include file for the Data Encryption Standard library.
 */

/* only do the whole thing once	 */
#ifndef DES_DEFS
#define DES_DEFS

#include "mit-copyright.h"
#include <stdio.h>

#ifndef DES_INT32
#define DES_INT32 SInt32
#endif
#ifndef DES_UINT32
#define DES_UINT32 UInt32
#endif

/* There are some declarations in the system-specific header files which
   can't be done until DES_INT32 is defined.  So they are in a macro,
   which we expand here if defined.  */

#ifdef	DECL_THAT_NEEDS_DES_INT32
DECL_THAT_NEEDS_DES_INT32
#endif

typedef unsigned char des_cblock[8];	/* crypto-block size */
/* Key schedule */
typedef struct des_ks_struct { union { DES_INT32 pad; des_cblock _;} __; } des_key_schedule[16];

#define DES_KEY_SZ 	(sizeof(des_cblock))
#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#ifndef NCOMPAT
#define C_Block des_cblock
#define Key_schedule des_key_schedule
#define ENCRYPT DES_ENCRYPT
#define DECRYPT DES_DECRYPT
#define KEY_SZ DES_KEY_SZ
#define string_to_key des_string_to_key
#define read_pw_string des_read_pw_string
#define random_key des_random_key
#define pcbc_encrypt des_pcbc_encrypt
#define key_sched des_key_sched
#define cbc_encrypt des_cbc_encrypt
#define cbc_cksum des_cbc_cksum
#define C_Block_print des_cblock_print
#define quad_cksum des_quad_cksum
typedef struct des_ks_struct bit_64;
#endif

#define des_cblock_print(x) des_cblock_print_file(x, stdout)

/* Function declarations */

/*	This is CFM magic that has to be done in order for the library to work under CFM-68K */
#if defined(__CFM68K__) && !defined(__USING_STATIC_LIBS__)
#	pragma import on
#endif

#if !GENERATINGCFM
#   pragma d0_pointers on
#endif

int des_cbc_encrypt(des_cblock *in, 
                    des_cblock *out, 
                    long length, 
                    des_key_schedule schedule, 
                    des_cblock ivec, 
                    int encrypt);

void des_3cbc_encrypt(des_cblock *input,
                      des_cblock *output,
                      long length,
                      des_key_schedule schedule1, 
                      des_cblock ivec1,
                      des_key_schedule schedule2, 
                      des_cblock ivec2,
                      des_key_schedule schedule3, 
                      des_cblock ivec3, 
                      int encrypt);
                    
unsigned long des_cbc_cksum(des_cblock *in, 
                            des_cblock *out, 
                            long length, 
                            des_key_schedule schedule, 
                            des_cblock *ivec);

int des_ecb_encrypt(des_cblock *in, 
                    des_cblock *out, 
                    des_key_schedule schedule, 
                    int encrypt);
                      
void des_fixup_key_parity(register des_cblock key);
int des_check_key_parity(register des_cblock key);

int des_pcbc_encrypt(des_cblock *in, 
                     des_cblock *out, 
                     long length, 
                     des_key_schedule schedule, 
                     des_cblock ivec, 
                     int encrypt);

void des_3pcbc_encrypt(des_cblock *input,
                       des_cblock *output,
                       long length,
                       des_key_schedule schedule1, 
                       des_cblock ivec1,
                       des_key_schedule schedule2, 
                       des_cblock ivec2,
                       des_key_schedule schedule3, 
                       des_cblock ivec3, 
                       int encrypt);

int make_key_sched(des_cblock *key, des_key_schedule schedule);

int des_key_sched(des_cblock k, des_key_schedule schedule);

int des_new_random_key(des_cblock key);
void des_init_random_number_generator(des_cblock key);
void des_set_random_generator_seed(des_cblock key);
void des_set_sequence_number(des_cblock new_sequence_number);
void des_generate_random_block(des_cblock block);

unsigned long des_quad_cksum(unsigned char *in,
                             unsigned long *out,
                             long length,
                             int out_count,
                             des_cblock *c_seed);

int des_random_key(des_cblock *key);

int des_read_password(des_cblock *k, char *prompt, int verify);
int des_read_pw_string(char *s, int max, char *prompt, int verify);

int des_string_to_key(char *str, des_cblock key);

void des_cblock_print_file(des_cblock *x, FILE *fp);

int des_is_weak_key(des_cblock key);

char *des_crypt(const char *buf, const char *salt);
char *des_fcrypt(const char *buf, const char *salt, char *ret);

int des_set_key(des_cblock *key, des_key_schedule schedule);

#if !GENERATINGCFM
#   pragma d0_pointers reset
#endif

/*	CFM magic again */	
#if defined(__CFM68K__) && !defined(__USING_STATIC_LIBS__)
#	pragma import reset
#endif

#endif /* DES_DEFS */
