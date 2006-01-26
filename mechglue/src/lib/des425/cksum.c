/*
 * lib/des425/cksum.c
 *
 * Copyright 1985, 1986, 1987, 1988, 1990 by the Massachusetts Institute
 * of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * These routines perform encryption and decryption using the DES
 * private key algorithm, or else a subset of it-- fewer inner loops.
 * (AUTH_DES_ITER defaults to 16, may be less.)
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 * 
 * These routines form the library interface to the DES facilities.
 *
 *	spm	8/85	MIT project athena
 */

#include "des_int.h"
#include "des.h"

/*
 * This routine performs DES cipher-block-chaining checksum operation,
 * a.k.a.  Message Authentication Code.  It ALWAYS encrypts from input
 * to a single 64 bit output MAC checksum.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext. The cleartext and ciphertext should be in host order.
 *
 * NOTE-- the output is ALWAYS 8 bytes long.  If not enough space was
 * provided, your program will get trashed.
 *
 * The input is null padded, at the end (highest addr), to an integral
 * multiple of eight bytes.
 */

unsigned long KRB5_CALLCONV
des_cbc_cksum(in,out,length,key,iv)
    const des_cblock  *in;		/* >= length bytes of inputtext */
    des_cblock  *out;			/* >= length bytes of outputtext */
    register unsigned long length;	/* in bytes */
    const mit_des_key_schedule key;	/* precomputed key schedule */
    const des_cblock  *iv;		/* 8 bytes of ivec */
{
    return mit_des_cbc_cksum((const krb5_octet *)in, (krb5_octet *)out,
			     length, key, (krb5_octet *)iv);
}
