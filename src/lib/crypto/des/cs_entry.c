/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * DES encryption interface file
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_cs_entry_c[] =
"$Id$";
#endif	/* !lint & !SABER */


#include <krb5/krb5.h>
#include <krb5/crc-32.h>

#include "des_int.h"

krb5_cryptosystem_entry mit_des_cryptosystem_entry = {
    mit_des_encrypt_func,
    mit_des_decrypt_func, 
    mit_des_process_key,
    mit_des_finish_key,
    mit_des_string_to_key,
    mit_des_init_random_key,
    mit_des_finish_random_key,
    mit_des_random_key,
    sizeof(mit_des_cblock),
    CRC32_CKSUM_LENGTH,
    sizeof(mit_des_cblock),
    ETYPE_DES_CBC_CRC,
    KEYTYPE_DES
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


krb5_checksum_entry mit_des_cbc_cksumtable_entry = {
    mit_des_cbc_checksum,
    sizeof(mit_des_cblock),
    1,					/* is collision proof */
    1,					/* is keyed */
};
