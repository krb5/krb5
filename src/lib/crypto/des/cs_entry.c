/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Wrapper for the V4 libdes for use with kerberos V5.
 */

#if !defined(lint) && !defined(SABER)
static char des_cs_ent_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <sys/errno.h>

#include <krb5/krb5.h>
#include <krb5/des.h>
#include <krb5/ext-proto.h>

extern krb5_error_code encrypt_func PROTOTYPE((const krb5_pointer,
                                               krb5_pointer,
                                               const size_t,
                                               krb5_encrypt_block *,
					       krb5_pointer));
extern krb5_error_code decrypt_func PROTOTYPE((const krb5_pointer,
                                               krb5_pointer,
                                               const size_t,
                                               krb5_encrypt_block *,
					       krb5_pointer));
extern krb5_error_code process_key PROTOTYPE((krb5_encrypt_block *,
                                              const krb5_keyblock *));
extern krb5_error_code finish_key PROTOTYPE((krb5_encrypt_block *));
extern krb5_error_code string_to_key PROTOTYPE((const krb5_keytype, 
						krb5_keyblock *,
                                                const krb5_data *,
                                                const krb5_principal));
extern krb5_error_code init_random_key PROTOTYPE((const krb5_keyblock *,
						  krb5_pointer *));
extern krb5_error_code finish_random_key PROTOTYPE((krb5_pointer *));
extern krb5_error_code random_key PROTOTYPE((krb5_pointer,
					     krb5_keyblock **));

krb5_cryptosystem_entry mit_des_cryptosystem_entry = {
    encrypt_func,
    decrypt_func, 
    process_key,
    finish_key,
    string_to_key,
    init_random_key,
    finish_random_key ,
    random_key,
    sizeof(des_cblock),
    0,
    sizeof(des_cblock),
    ETYPE_DES_CBC_CRC,
    KEYTYPE_DES
    };

krb5_cs_table_entry krb5_des_cst_entry = {
    &mit_des_cryptosystem_entry,
    0
    };
extern krb5_error_code des_cbc_checksum PROTOTYPE ((krb5_pointer ,
						    size_t ,
						    krb5_pointer ,
						    size_t ,
						    krb5_checksum * ));


krb5_checksum_entry des_cbc_cksumtable_entry = {
    des_cbc_checksum,
    sizeof(des_cblock)
    };
