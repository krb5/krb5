/*
 * lib/crypto/openssldes/f_cbc.c
 *
 * Copyright (C) 1990 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * DES implementation donated by Dennis Ferguson
 */

/*
 * des_cbc_encrypt.c - an implementation of the DES cipher function in cbc mode
 */
#include "des_int.h"

/*
 * des_cbc_encrypt - {en,de}crypt a stream in CBC mode
 */

/*
 * This routine performs DES cipher-block-chaining operation, either
 * encrypting from cleartext to ciphertext, if encrypt != 0 or
 * decrypting from ciphertext to cleartext, if encrypt == 0.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext.  The cleartext and ciphertext should be in host order.
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

const mit_des_cblock mit_des_zeroblock /* = all zero */;

#undef mit_des_cbc_encrypt
int
mit_des_cbc_encrypt(const mit_des_cblock *in, mit_des_cblock *out,
		    unsigned long length, const mit_des_key_schedule schedule,
		    const mit_des_cblock ivec, int enc)
{
    /* Unsupported operation */
    return KRB5_CRYPTO_INTERNAL;
}
void
krb5int_des_cbc_encrypt(const mit_des_cblock *in,
			mit_des_cblock *out,
			unsigned long length,
			const mit_des_key_schedule schedule,
			const mit_des_cblock ivec)
{
    /* Unsupported operation */
    abort();
}

void
krb5int_des_cbc_decrypt(const mit_des_cblock *in,
			mit_des_cblock *out,
			unsigned long length,
			const mit_des_key_schedule schedule,
			const mit_des_cblock ivec)
{
    /* Unsupported operation */
    abort();
}

