/*
 * lib/crypto/des/cs_entry.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * DES encryption interface file
 */



#include <krb5/krb5.h>
#include <krb5/crc-32.h>

#include "des_int.h"

static krb5_cryptosystem_entry mit_raw_des_cryptosystem_entry = {
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
    ETYPE_RAW_DES_CBC,
    KEYTYPE_DES
    };

static krb5_cryptosystem_entry mit_des_cryptosystem_entry = {
    mit_des_encrypt_func,
    mit_des_decrypt_func, 
    mit_des_process_key,
    mit_des_finish_key,
    mit_des_string_to_key,
    mit_des_init_random_key,
    mit_des_finish_random_key,
    mit_des_random_key,
    sizeof(mit_des_cblock),
    CRC32_CKSUM_LENGTH+sizeof(mit_des_cblock),
    sizeof(mit_des_cblock),
    ETYPE_DES_CBC_CRC,
    KEYTYPE_DES
    };

krb5_cs_table_entry krb5_raw_des_cst_entry = {
    &mit_raw_des_cryptosystem_entry,
    0
    };

krb5_cs_table_entry krb5_des_cst_entry = {
    &mit_des_cryptosystem_entry,
    0
    };

extern krb5_error_code mit_des_cbc_checksum PROTOTYPE ((krb5_pointer ,
							size_t ,
							krb5_pointer ,
							size_t ,
							krb5_checksum * ));


krb5_checksum_entry krb5_des_cbc_cksumtable_entry = {
    mit_des_cbc_checksum,
    sizeof(mit_des_cblock),
    1,					/* is collision proof */
    1,					/* is keyed */
};
