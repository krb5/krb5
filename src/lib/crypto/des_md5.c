/*
 * lib/crypto/des-md5.32
 *
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
#include "rsa-md5.h"
#include "des_int.h"

krb5_error_code mit_des_md5_encrypt_func
    PROTOTYPE(( krb5_const_pointer, krb5_pointer, const size_t,
               krb5_encrypt_block *, krb5_pointer ));

krb5_error_code mit_des_md5_decrypt_func
    PROTOTYPE(( krb5_const_pointer, krb5_pointer, const size_t,
               krb5_encrypt_block *, krb5_pointer ));

static mit_des_cblock zero_ivec = { 0 };

static krb5_cryptosystem_entry mit_des_md5_cryptosystem_entry = {
    0,
    mit_des_md5_encrypt_func,
    mit_des_md5_decrypt_func, 
    mit_des_process_key,
    mit_des_finish_key,
    mit_des_string_to_key,
    mit_des_init_random_key,
    mit_des_finish_random_key,
    mit_des_random_key,
    sizeof(mit_des_cblock),
    RSA_MD5_CKSUM_LENGTH+sizeof(mit_des_cblock),
    sizeof(mit_des_cblock),
    ENCTYPE_DES_CBC_MD5
    };

krb5_cs_table_entry krb5_des_md5_cst_entry = {
    0,
    &mit_des_md5_cryptosystem_entry,
    0
    };


krb5_error_code
mit_des_md5_encrypt_func(in, out, size, key, ivec)
    krb5_const_pointer in;
    krb5_pointer out;
    const size_t size;
    krb5_encrypt_block * key;
    krb5_pointer ivec;
{
    krb5_checksum cksum;
    krb5_octet 	contents[RSA_MD5_CKSUM_LENGTH];
    int sumsize;
    krb5_error_code retval;

/*    if ( size < sizeof(mit_des_cblock) )
	return KRB5_BAD_MSIZE; */

    /* caller passes data size, and saves room for the padding. */
    /* format of ciphertext, per RFC is:
      +-----------+----------+-------------+-----+
      |confounder |   check  |   msg-seq   | pad |
      +-----------+----------+-------------+-----+
      
      our confounder is 8 bytes (one cblock);
      our checksum is RSA_MD5_CKSUM_LENGTH
     */
    sumsize =  krb5_roundup(size+RSA_MD5_CKSUM_LENGTH+sizeof(mit_des_cblock),
			    sizeof(mit_des_cblock));

    /* assemble crypto input into the output area, then encrypt in place. */

    memset((char *)out, 0, sumsize);

    /* put in the confounder */
    if ((retval = krb5_random_confounder(sizeof(mit_des_cblock), out)))
	return retval;

    memcpy((char *)out+sizeof(mit_des_cblock)+RSA_MD5_CKSUM_LENGTH, (char *)in,
	   size);

    cksum.contents = contents; 

    /* This is equivalent to krb5_calculate_checksum(CKSUMTYPE_MD5,...)
       but avoids use of the cryptosystem config table which can not be
       referenced here if this object is to be included in a shared library.  */
    if ((retval = rsa_md5_cksumtable_entry.sum_func((krb5_pointer) out,
						    sumsize,
						    (krb5_pointer)key->key->contents,
						    sizeof(mit_des_cblock),
						    &cksum)))
	return retval;

    memcpy((char *)out+sizeof(mit_des_cblock), (char *)contents,
	   RSA_MD5_CKSUM_LENGTH);

    /* We depend here on the ability of this DES implementation to
       encrypt plaintext to ciphertext in-place. */
    return (mit_des_cbc_encrypt(out, 
				out,
				sumsize, 
				(struct mit_des_ks_struct *) key->priv, 
				ivec ? ivec : (krb5_pointer)zero_ivec,
				MIT_DES_ENCRYPT));
    
}

krb5_error_code
mit_des_md5_decrypt_func(in, out, size, key, ivec)
    krb5_const_pointer in;
    krb5_pointer out;
    const size_t size;
    krb5_encrypt_block * key;
    krb5_pointer ivec;
{
    krb5_checksum cksum;
    krb5_octet 	contents_prd[RSA_MD5_CKSUM_LENGTH];
    krb5_octet  contents_get[RSA_MD5_CKSUM_LENGTH];
    char 	*p;
    krb5_error_code   retval;

    if ( size < 2*sizeof(mit_des_cblock) )
	return KRB5_BAD_MSIZE;

    retval = mit_des_cbc_encrypt((const mit_des_cblock *) in,
				 out,
				 size,
				 (struct mit_des_ks_struct *) key->priv,
				 ivec ? ivec : (krb5_pointer)zero_ivec,
				 MIT_DES_DECRYPT);
    if (retval)
	return retval;

    cksum.contents = contents_prd;
    p = (char *)out + sizeof(mit_des_cblock);
    memcpy((char *)contents_get, p, RSA_MD5_CKSUM_LENGTH);
    memset(p, 0, RSA_MD5_CKSUM_LENGTH);

    if ((retval = rsa_md5_cksumtable_entry.sum_func(out, size,
						    (krb5_pointer)key->key->contents,
						    sizeof(mit_des_cblock),
						    &cksum)))
	return retval;

    if (memcmp((char *)contents_get, (char *)contents_prd, RSA_MD5_CKSUM_LENGTH) )
        return KRB5KRB_AP_ERR_BAD_INTEGRITY;
    memmove((char *)out, (char *)out +
	   sizeof(mit_des_cblock) + RSA_MD5_CKSUM_LENGTH,
	   size - sizeof(mit_des_cblock) - RSA_MD5_CKSUM_LENGTH);
    return 0;
}
