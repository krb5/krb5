/*
 * lib/crypto/des/krb_glue.c
 *
 * Copyright 1985, 1986, 1987, 1988, 1990, 1991 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 * These routines perform encryption and decryption using the DES
 * private key algorithm, or else a subset of it -- fewer inner loops.
 * (AUTH_DES_ITER defaults to 16, may be less.)
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 *
 * These routines form the library interface to the DES facilities.
 *
 * Originally written 8/85 by Steve Miller, MIT Project Athena.
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
 */

/*
 * These routines were extracted out of enc_dec.c because they will
 * drag in the kerberos library, if someone references mit_des_cbc_encrypt,
 * even no kerberos routines are called
 */



#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/crc-32.h>

#include "des_int.h"

#ifdef DEBUG
#include <stdio.h>

extern int mit_des_debug;
#endif

/*
	encrypts "size" bytes at "in", storing result in "out".
	"eblock" points to an encrypt block which has been initialized
	by process_key().

	"out" must be preallocated by the caller to contain sufficient
	storage to hold the output; the macro krb5_encrypt_size() can
	be used to compute this size.
	
	returns: errors
*/
static krb5_error_code
mit_des_encrypt_f(DECLARG(krb5_const_pointer, in),
		  DECLARG(krb5_pointer, out),
		  DECLARG(const size_t, size),
		  DECLARG(krb5_encrypt_block *, key),
		  DECLARG(krb5_pointer, ivec))
OLDDECLARG(krb5_const_pointer, in)
OLDDECLARG(krb5_pointer, out)
OLDDECLARG(const size_t, size)
OLDDECLARG(krb5_encrypt_block *, key)
OLDDECLARG(krb5_pointer, ivec)
{
    krb5_octet	*iv;
    
    if ( ivec == 0 )
	iv = key->key->contents;
    else
	iv = (krb5_octet *)ivec;

    return (mit_des_cbc_encrypt((krb5_octet *)in, 
			    (krb5_octet *)out,
			    size, 
			    (struct mit_des_ks_struct *)key->priv, 
			    iv,
			    MIT_DES_ENCRYPT));
}    


/*

	decrypts "size" bytes at "in", storing result in "out".
	"eblock" points to an encrypt block which has been initialized
	by process_key().

	"out" must be preallocated by the caller to contain sufficient
	storage to hold the output; this is guaranteed to be no more than
	the input size.

	returns: errors

 */
static krb5_error_code
mit_des_decrypt_f(DECLARG(krb5_const_pointer, in),
		  DECLARG(krb5_pointer, out),
		  DECLARG(const size_t, size),
		  DECLARG(krb5_encrypt_block *, key),
		  DECLARG(krb5_pointer, ivec))
OLDDECLARG(krb5_const_pointer, in)
OLDDECLARG(krb5_pointer, out)
OLDDECLARG(const size_t, size)
OLDDECLARG(krb5_encrypt_block *, key)
OLDDECLARG(krb5_pointer, ivec)
{
    krb5_octet	*iv;

    if ( ivec == 0 )
	iv = key->key->contents;
    else
	iv = (krb5_octet *)ivec;

    return (mit_des_cbc_encrypt ((krb5_octet *)in, 
			     (krb5_octet *)out, 
			     size, 
			     (struct mit_des_ks_struct *)key->priv, 
			     iv,
			     MIT_DES_DECRYPT));
}    

krb5_error_code mit_raw_des_encrypt_func(DECLARG(krb5_const_pointer, in),
                                         DECLARG(krb5_pointer, out),
                                         DECLARG(const size_t, size),
                                         DECLARG(krb5_encrypt_block *, key),
                                         DECLARG(krb5_pointer, ivec))
OLDDECLARG(krb5_const_pointer, in)
OLDDECLARG(krb5_pointer, out)
OLDDECLARG(const size_t, size)
OLDDECLARG(krb5_encrypt_block *, key)
OLDDECLARG(krb5_pointer, ivec)
{
   int sumsize;

   /* round up to des block size */

   sumsize =  krb5_roundup(size, sizeof(mit_des_cblock));

   /* assemble crypto input into the output area, then encrypt in place. */

   memset((char *)out, 0, sumsize);
   memcpy((char *)out, (char *)in, size);

    /* We depend here on the ability of this DES implementation to
       encrypt plaintext to ciphertext in-place. */
    return (mit_des_encrypt_f(out, out, sumsize, key, ivec));
}

krb5_error_code mit_des_encrypt_func(DECLARG(krb5_const_pointer, in),
				     DECLARG(krb5_pointer, out),
				     DECLARG(const size_t, size),
				     DECLARG(krb5_encrypt_block *, key),
				     DECLARG(krb5_pointer, ivec))
OLDDECLARG(krb5_const_pointer, in)
OLDDECLARG(krb5_pointer, out)
OLDDECLARG(const size_t, size)
OLDDECLARG(krb5_encrypt_block *, key)
OLDDECLARG(krb5_pointer, ivec)
{
    krb5_checksum cksum;
    krb5_octet 	contents[CRC32_CKSUM_LENGTH];
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
      our checksum is CRC32_CKSUM_LENGTH
     */
    sumsize =  krb5_roundup(size+CRC32_CKSUM_LENGTH+sizeof(mit_des_cblock),
			    sizeof(mit_des_cblock));

    /* assemble crypto input into the output area, then encrypt in place. */

    memset((char *)out, 0, sumsize);

    /* put in the confounder */
    if (retval = krb5_random_confounder(sizeof(mit_des_cblock), out))
	return retval;

    memcpy((char *)out+sizeof(mit_des_cblock)+CRC32_CKSUM_LENGTH, (char *)in,
	   size);

    cksum.contents = contents; 

    /* This is equivalent to krb5_calculate_checksum(CKSUMTYPE_CRC32,...)
       but avoids use of the cryptosystem config table which can not be
       referenced here if this object is to be included in a shared library.  */
    if (retval = crc32_cksumtable_entry.sum_func((krb5_pointer) out,
						 sumsize,
						 (krb5_pointer)key->key->contents,
						 sizeof(mit_des_cblock),
						 &cksum))
	return retval;

    memcpy((char *)out+sizeof(mit_des_cblock), (char *)contents,
	   CRC32_CKSUM_LENGTH);

    /* We depend here on the ability of this DES implementation to
       encrypt plaintext to ciphertext in-place. */
    return (mit_des_encrypt_f(out, out, sumsize, key, ivec));
}

krb5_error_code mit_raw_des_decrypt_func(DECLARG(krb5_const_pointer, in),
                                         DECLARG(krb5_pointer, out),
                                         DECLARG(const size_t, size),
                                         DECLARG(krb5_encrypt_block *, key),
                                         DECLARG(krb5_pointer, ivec))
OLDDECLARG(krb5_const_pointer, in)
OLDDECLARG(krb5_pointer, out)
OLDDECLARG(const size_t, size)
OLDDECLARG(krb5_encrypt_block *, key)
OLDDECLARG(krb5_pointer, ivec)
{
   return(mit_des_decrypt_f(in, out, size, key, ivec));
}

krb5_error_code mit_des_decrypt_func(DECLARG(krb5_const_pointer, in),
				     DECLARG(krb5_pointer, out),
				     DECLARG(const size_t, size),
				     DECLARG(krb5_encrypt_block *, key),
				     DECLARG(krb5_pointer, ivec))
OLDDECLARG(krb5_const_pointer, in)
OLDDECLARG(krb5_pointer, out)
OLDDECLARG(const size_t, size)
OLDDECLARG(krb5_encrypt_block *, key)
OLDDECLARG(krb5_pointer, ivec)
{
    krb5_checksum cksum;
    krb5_octet 	contents_prd[CRC32_CKSUM_LENGTH];
    krb5_octet  contents_get[CRC32_CKSUM_LENGTH];
    char 	*p;
    krb5_error_code   retval;

    if ( size < 2*sizeof(mit_des_cblock) )
	return KRB5_BAD_MSIZE;

    if (retval = mit_des_decrypt_f(in, out, size, key, ivec))
	return retval;

    cksum.contents = contents_prd;
    p = (char *)out + sizeof(mit_des_cblock);
    memcpy((char *)contents_get, p, CRC32_CKSUM_LENGTH);
    memset(p, 0, CRC32_CKSUM_LENGTH);

    if (retval = crc32_cksumtable_entry.sum_func(out, size,
						 (krb5_pointer)key->key->contents,
						 sizeof(mit_des_cblock),
						 &cksum))
	return retval;

    if (memcmp((char *)contents_get, (char *)contents_prd, CRC32_CKSUM_LENGTH) )
        return KRB5KRB_AP_ERR_BAD_INTEGRITY;
    memmove((char *)out, (char *)out +
	   sizeof(mit_des_cblock) + CRC32_CKSUM_LENGTH,
	   size - sizeof(mit_des_cblock) - CRC32_CKSUM_LENGTH);
    return 0;
}

