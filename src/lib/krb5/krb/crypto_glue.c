/*
 * lib/krb5/krb/crypto_glue.c
 *
 * Copyright 1996 by the Massachusetts Institute of Technology.
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
 * Exported routines:
 *   krb5_use_enctype()
 *   krb5_checksum_size()
 *   krb5_encrypt_size()
 *   krb5_calculate_checksum()
 *   krb5_verify_checksum()
 *   krb5_encrypt()
 *   krb5_decrypt()
 *   krb5_process_key()
 *   krb5_finish_key()
 *   krb5_string_to_key()
 *   krb5_init_random_key()
 *   krb5_finish_random_key()
 *   krb5_random_key()
 *   krb5_eblock_enctype()
 *
 * Internal library routines:
 *   is_coll_proof_cksum()
 *   is_keyed_cksum()
 *   valid_cksumtype()
 *   valid_enctype()
 */

#include "k5-int.h"


KRB5_DLLIMP size_t KRB5_CALLCONV
krb5_encrypt_size(length, crypto)
    krb5_const size_t			length;
    krb5_const krb5_cryptosystem_entry	FAR * crypto;
{
    return krb5_roundup(length + crypto->pad_minimum, crypto->block_length);
}

krb5_boolean KRB5_CALLCONV
valid_enctype(ktype)
    krb5_const krb5_enctype	ktype;
{
    return ((ktype<=krb5_max_enctype) && (ktype>0) && krb5_enctype_array[ktype]);
}

krb5_boolean KRB5_CALLCONV
valid_cksumtype(cktype)
    krb5_const krb5_cksumtype	cktype;
{
    return ((cktype<=krb5_max_cksum) && (cktype>0) && krb5_cksumarray[cktype]);
}

krb5_boolean KRB5_CALLCONV
is_coll_proof_cksum(cktype)
    krb5_const krb5_cksumtype	cktype;
{
    return(krb5_cksumarray[cktype]->is_collision_proof);
}

krb5_boolean KRB5_CALLCONV
is_keyed_cksum(cktype)
    krb5_const krb5_cksumtype	cktype;
{
    return (krb5_cksumarray[cktype]->uses_key);
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_use_enctype(context, eblock, enctype)
    krb5_context		context;
    krb5_encrypt_block		FAR * eblock;
    krb5_const krb5_enctype	enctype;
{
    eblock->crypto_entry = krb5_enctype_array[(enctype)]->system;
    return 0;
}

KRB5_DLLIMP size_t KRB5_CALLCONV
krb5_checksum_size(context, cktype)
    krb5_context		context;
    krb5_const krb5_cksumtype	cktype;
{
    return krb5_cksumarray[cktype]->checksum_length;
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_calculate_checksum(context, cktype, in, in_length, seed, seed_length, outcksum)
    krb5_context		context;
    krb5_const krb5_cksumtype	cktype;
    krb5_pointer		in;
    krb5_const size_t		in_length;
    krb5_const krb5_pointer	seed;
    krb5_const size_t		seed_length;
    krb5_checksum	FAR *outcksum;
{
    return krb5_x(((*krb5_cksumarray[cktype]->sum_func)),
		  (in, in_length, seed, seed_length, outcksum));
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_verify_checksum(context, cktype, cksum, in, in_length, seed, seed_length)
    krb5_context		context;
    krb5_const krb5_cksumtype	cktype;
    krb5_const krb5_checksum	FAR *cksum;
    krb5_const krb5_pointer	in;
    krb5_const size_t		in_length;
    krb5_const krb5_pointer	seed;
    krb5_const size_t		seed_length;
{
    return krb5_x((*krb5_cksumarray[cktype]->sum_verf_func),
		  (cksum, in, in_length, seed, seed_length));
}

KRB5_DLLIMP krb5_enctype KRB5_CALLCONV
krb5_eblock_enctype(context, eblock)
    krb5_context			context;
    krb5_const krb5_encrypt_block	FAR * eblock;
{
    return eblock->crypto_entry->proto_enctype;
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_encrypt(context, inptr, outptr, size, eblock, ivec)
    krb5_context	context;
    krb5_const krb5_pointer	inptr;
    krb5_pointer		outptr;
    krb5_const size_t		size;
    krb5_encrypt_block		FAR * eblock;
    krb5_pointer		ivec;
{
    return krb5_x(eblock->crypto_entry->encrypt_func,
		  (inptr, outptr, size, eblock, ivec));
}


KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_decrypt(context, inptr, outptr, size, eblock, ivec)
    krb5_context		context;
    krb5_const krb5_pointer	inptr;
    krb5_pointer		outptr;
    krb5_const size_t		size;
    krb5_encrypt_block		FAR * eblock;
    krb5_pointer		ivec;
{
    return krb5_x(eblock->crypto_entry->decrypt_func,
		  (inptr, outptr, size, eblock, ivec));
}


KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_process_key(context, eblock, key)
    krb5_context		context;
    krb5_encrypt_block		FAR * eblock;
    krb5_const krb5_keyblock	FAR * key;
{
    return krb5_x(eblock->crypto_entry->process_key,
		  (eblock, key));
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_finish_key(context, eblock)
    krb5_context	context;
    krb5_encrypt_block	FAR * eblock;
{
    return krb5_x(eblock->crypto_entry->finish_key,(eblock));
}


KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_key(context, eblock, keyblock, data, princ)
    krb5_context			context;
    krb5_const krb5_encrypt_block	FAR * eblock;
    krb5_keyblock			FAR * keyblock;
    krb5_const krb5_data		FAR * data;
    krb5_const krb5_data		FAR * princ;
{
    return krb5_x(eblock->crypto_entry->string_to_key,
		  (eblock, keyblock, data, princ));
}


KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_init_random_key(context, eblock, keyblock, ptr)
    krb5_context			context;
    krb5_const krb5_encrypt_block	FAR * eblock;
    krb5_const krb5_keyblock		FAR * keyblock;
    krb5_pointer			FAR * ptr;
{
    return krb5_x(eblock->crypto_entry->init_random_key,
		  (eblock, keyblock, ptr));
}


KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_finish_random_key(context, eblock, ptr)
    krb5_context			context;
    krb5_const krb5_encrypt_block	FAR * eblock;
    krb5_pointer			FAR * ptr;
{
    return krb5_x(eblock->crypto_entry->finish_random_key,
		  (eblock, ptr));
}


KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_random_key(context, eblock, ptr, keyblock)
    krb5_context			context;
    krb5_const krb5_encrypt_block	FAR * eblock;
    krb5_pointer			ptr;
    krb5_keyblock			FAR * FAR * keyblock;
{
    return krb5_x(eblock->crypto_entry->random_key,
		  (eblock, ptr, keyblock));
}


