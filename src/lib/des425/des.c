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
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext.
 *
 * All registers labeled imply Vax using the Ultrix or 4.2bsd
 * compiler.
 *
 *
 *	NOTE:  bit and byte numbering:
 *			DES algorithm is defined in terms of bits of L
 *			followed by bits of R.
 *		bit 0  ==> lsb of L
 *		bit 63 ==> msb of R
 *
 * Always work in register pairs, FROM L1,R1 TO L2,R2 to make
 * bookkeeping easier.
 *
 * originally written by Steve Miller, MIT Project Athena
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_des_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "des.h"
#include <krb5/ext-proto.h>

int
des_ecb_encrypt(clear, cipher, schedule, encrypt)
    unsigned long *clear;
    unsigned long *cipher;
    int encrypt;		/* 0 ==> decrypt, else encrypt */
    register mit_des_key_schedule schedule; /* r11 */
{
	return (mit_des_ecb_encrypt(clear, cipher, schedule, encrypt));
}


