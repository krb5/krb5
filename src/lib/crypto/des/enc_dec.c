/*
 * $Source$
 * $Author$
 *
 * Copyright 1985, 1986, 1987, 1988, 1990 by the Massachusetts Institute
 * of Technology.
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
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_enc_dec_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
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

    /* XXX should check that key sched is valid here? */
    return (mit_des_cbc_encrypt((krb5_octet *)in, 
			    (krb5_octet *)out,
			    size, 
			    (struct mit_des_ks_struct *)key->priv, 
			    iv,
			    MIT_DES_ENCRYPT));
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
    char 	*p, *endinput;
    int sumsize;
    krb5_error_code retval;

/*    if ( size < sizeof(mit_des_cblock) )
	return KRB5_BAD_MSIZE; */

    /* caller passes data size, and saves room for the padding. */
    /* we need to put the cksum in the end of the padding area */
    sumsize =  krb5_roundup(size+CRC32_CKSUM_LENGTH, sizeof(mit_des_cblock));

    p = (char *)in + sumsize - CRC32_CKSUM_LENGTH;
    endinput = (char *)in + size;
    bzero(endinput, sumsize - size);
    cksum.contents = contents; 

    if (retval = (*krb5_cksumarray[CKSUMTYPE_CRC32]->
                  sum_func)((krb5_pointer) in,
                            sumsize,
                            (krb5_pointer)key->key->contents,
                            sizeof(mit_des_cblock),
                            &cksum)) 
	return retval;
    
    memcpy(p, (char *)contents, CRC32_CKSUM_LENGTH);
 
    return (mit_des_encrypt_f(in, out, sumsize, key, ivec));
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

    /* XXX should check that key sched is valid here? */
    return (mit_des_cbc_encrypt ((krb5_octet *)in, 
			     (krb5_octet *)out, 
			     size, 
			     (struct mit_des_ks_struct *)key->priv, 
			     iv,
			     MIT_DES_DECRYPT));
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

    if ( size < sizeof(mit_des_cblock) )
	return KRB5_BAD_MSIZE;

    if (retval = mit_des_decrypt_f(in, out, size, key, ivec))
	return retval;

    cksum.contents = contents_prd;
    p = (char *)out + size - CRC32_CKSUM_LENGTH;
    memcpy((char *)contents_get, p, CRC32_CKSUM_LENGTH);
    bzero(p, CRC32_CKSUM_LENGTH);

    if (retval = (*krb5_cksumarray[CKSUMTYPE_CRC32]->
                  sum_func)(out,
                            size,
                            (krb5_pointer)key->key->contents,
                            sizeof(mit_des_cblock),
                            &cksum)) 
	return retval;

    if (memcmp((char *)contents_get, (char *)contents_prd, CRC32_CKSUM_LENGTH) )
        return KRB5KRB_AP_ERR_BAD_INTEGRITY;

    return 0;
}
/*
 * This routine performs DES cipher-block-chaining operation, either
 * encrypting from cleartext to ciphertext, if encrypt != 0 or
 * decrypting from ciphertext to cleartext, if encrypt == 0.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext.	The cleartext and ciphertext should be in host order.
 *
 * NOTE-- the output is ALWAYS an multiple of 8 bytes long.  If not
 * enough space was provided, your program will get trashed.
 *
 * For encryption, the cleartext string is null padded, at the end, to
 * an integral multiple of eight bytes.
 *
 * For decryption, the ciphertext will be used in integral multiples
 * of 8 bytes, but only the first "length" bytes returned into the
 * cleartext.
 */

krb5_error_code
mit_des_cbc_encrypt(in,out,length,key,iv,encrypt)
    krb5_octet   *in;		/* >= length bytes of input text */
    krb5_octet  *out;		/* >= length bytes of output text */
    register long length;	/* in bytes */
    mit_des_key_schedule key;		/* precomputed key schedule */
    krb5_octet *iv;		/* 8 bytes of ivec */
    int encrypt;		/* 0 ==> decrypt, else encrypt */
{
    int mit_des_ecb_encrypt();

    register unsigned long *input = (unsigned long *) in;
    register unsigned long *output = (unsigned long *) out;
    register unsigned long *ivec = (unsigned long *) iv;

    unsigned long i,j;
    unsigned long t_input[2];
    unsigned long t_output[2];
    unsigned char *t_in_p;
    unsigned long xor_0, xor_1;

    t_in_p = (unsigned char *) t_input;
    if (encrypt) {
#ifdef MUSTALIGN
	if ((long) ivec & 3) {
	    memcpy((char *)&t_output[0], (char *)ivec++, sizeof(t_output[0]));
	    memcpy((char *)&t_output[1], (char *)ivec, sizeof(t_output[1]));
	}
	else
#endif
	{
	    t_output[0] = *ivec++;
	    t_output[1] = *ivec;
	}

	for (i = 0; length > 0; i++, length -= 8) {
	    /* get input */
#ifdef MUSTALIGN
	    if ((long) input & 3) {
		memcpy((char *)&t_input[0],(char *)input++,sizeof(t_input[0]));
		memcpy((char *)&t_input[1],(char *)input++,sizeof(t_input[1]));
	    }
	    else
#endif
	    {
		t_input[0] = *input++;
		t_input[1] = *input++;
	    }

	    /* zero pad */
	    if (length < 8)
		for (j = length; j <= 7; j++)
		    *(t_in_p+j)= 0;

#ifdef DEBUG
	    if (mit_des_debug)
		mit_des_debug_print("clear",length,t_input[0],t_input[1]);
#endif
	    /* do the xor for cbc into the temp */
	    t_input[0] ^= t_output[0];
	    t_input[1] ^= t_output[1];
	    /* encrypt */
	    (void) mit_des_ecb_encrypt(t_input,t_output,key,encrypt);
	    /* copy temp output and save it for cbc */
#ifdef MUSTALIGN
	    if ((long) output & 3) {
		memcpy((char *)output++,(char *)&t_output[0],
		       sizeof(t_output[0]));
		memcpy((char *)output++,(char *)&t_output[1],
		       sizeof(t_output[1]));
	    }
	    else
#endif
	    {
		*output++ = t_output[0];
		*output++ = t_output[1];
	    }

#ifdef DEBUG
	    if (mit_des_debug) {
		mit_des_debug_print("xor'ed",i,t_input[0],t_input[1]);
		mit_des_debug_print("cipher",i,t_output[0],t_output[1]);
	    }
#endif
	}
	return 0;
    }

    else {
	/* decrypt */
#ifdef MUSTALIGN
	if ((long) ivec & 3) {
	    memcpy((char *)&xor_0,(char *)ivec++,sizeof(xor_0));
	    memcpy((char *)&xor_1,(char *)ivec,sizeof(xor_1));
	}
	else
#endif
	{
	    xor_0 = *ivec++;
	    xor_1 = *ivec;
	}

	for (i = 0; length > 0; i++, length -= 8) {
	    /* get input */
#ifdef MUSTALIGN
	    if ((long) input & 3) {
		memcpy((char *)&t_input[0],(char *)input++,sizeof(t_input[0]));
		memcpy((char *)&t_input[1],(char *)input++,sizeof(t_input[0]));
	    }
	    else
#endif
	    {
		t_input[0] = *input++;
		t_input[1] = *input++;
	    }

	    /* no padding for decrypt */
#ifdef DEBUG
	    if (mit_des_debug)
		mit_des_debug_print("cipher",i,t_input[0],t_input[1]);
#else
#ifdef lint
	    i = i;
#endif
#endif
	    /* encrypt */
	    (void) mit_des_ecb_encrypt(t_input,t_output,key,encrypt);
#ifdef DEBUG
	    if (mit_des_debug)
		mit_des_debug_print("out pre xor",i,t_output[0],t_output[1]);
#endif
	    /* do the xor for cbc into the output */
	    t_output[0] ^= xor_0;
	    t_output[1] ^= xor_1;
	    /* copy temp output */
#ifdef MUSTALIGN
	    if ((long) output & 3) {
		memcpy((char *)output++,(char *)&t_output[0],
		      sizeof(t_output[0]));
		memcpy((char *)output++,(char *)&t_output[1],
		      sizeof(t_output[1]));
	    }
	    else
#endif
	    {
		*output++ = t_output[0];
		*output++ = t_output[1];
	    }

	    /* save xor value for next round */
	    xor_0 = t_input[0];
	    xor_1 = t_input[1];
#ifdef DEBUG
	    if (mit_des_debug)
		mit_des_debug_print("clear",i,t_output[0],t_output[1]);
#endif
	}
	return 0;
    }
}
