/*
 * $Source$
 * $Author$
 *
 * Copyright 1985, 1986, 1987, 1988, 1990 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
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

#if !defined(lint) && !defined(SABER)
static char rcsid_cksum_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "des.h"
#include <krb5/ext-proto.h>

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

void
des_cbc_cksum(in,out,length,key,iv)
    krb5_octet  *in;		/* >= length bytes of inputtext */
    krb5_octet  *out;		/* >= length bytes of outputtext */
    register long length;	/* in bytes */
    mit_des_key_schedule key;		/* precomputed key schedule */
    krb5_octet  *iv;		/* 8 bytes of ivec */
{
	mit_des_cbc_cksum(in, out, length, key, iv);
}
