/*
 * lib/crypto/raw-des.c
 *
 * Copyright 1994, 1995 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"
#include "des_int.h"

krb5_error_code mit_raw_des_encrypt_func
    PROTOTYPE(( krb5_const_pointer, krb5_pointer, const size_t,
               krb5_encrypt_block *, krb5_pointer ));

krb5_error_code mit_raw_des_decrypt_func
    PROTOTYPE(( krb5_const_pointer, krb5_pointer, const size_t,
               krb5_encrypt_block *, krb5_pointer ));

static krb5_cryptosystem_entry mit_raw_des_cryptosystem_entry = {
    0,
    mit_raw_des_encrypt_func,
    mit_raw_des_decrypt_func,
    mit_des_process_key,
    mit_des_finish_key,
    mit_des_string_to_key,
    mit_des_init_random_key,
    mit_des_finish_random_key,
    mit_des_random_key,
    sizeof(mit_des_cblock),
    0,
    sizeof(mit_des_cblock),
    ENCTYPE_DES_CBC_RAW
    };

krb5_cs_table_entry krb5_raw_des_cst_entry = {
    0,
    &mit_raw_des_cryptosystem_entry,
    0
    };

krb5_error_code
mit_raw_des_decrypt_func(in, out, size, key, ivec)
    krb5_const_pointer in;
    krb5_pointer out;
    const size_t size;
    krb5_encrypt_block * key;
    krb5_pointer ivec;
{
    return (mit_des_cbc_encrypt (in, 
				 out, 
				 size, 
				 (struct mit_des_ks_struct *)key->priv, 
				 ivec ? ivec : (krb5_pointer)key->key->contents,
				 MIT_DES_DECRYPT));
}

krb5_error_code
mit_raw_des_encrypt_func(in, out, size, key, ivec)
    krb5_const_pointer in;
    krb5_pointer out;
    const size_t size;
    krb5_encrypt_block * key;
    krb5_pointer ivec;
{
   int sumsize;

   /* round up to des block size */

   sumsize =  krb5_roundup(size, sizeof(mit_des_cblock));

   /* assemble crypto input into the output area, then encrypt in place. */

   memset((char *)out, 0, sumsize);
   memcpy((char *)out, (char *)in, size);

    /* We depend here on the ability of this DES implementation to
       encrypt plaintext to ciphertext in-place. */
    return (mit_des_cbc_encrypt (out, 
				 out, 
				 sumsize, 
				 (struct mit_des_ks_struct *)key->priv, 
				 ivec ? ivec : (krb5_pointer)key->key->contents,
				 MIT_DES_ENCRYPT));
}
