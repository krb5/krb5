/*
 * lib/des425/des.c
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
 * permission.  M.I.T. makes no representations about the suitability of
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


#include "des.h"

KRB5_DLLIMP int KRB5_CALLCONV
des_ecb_encrypt(clear, cipher, schedule, encrypt)
    unsigned long *clear;
    unsigned long *cipher;
    int encrypt;		/* 0 ==> decrypt, else encrypt */
    register mit_des_key_schedule schedule; /* r11 */
{
    static des_cblock iv;

    return (mit_des_cbc_encrypt((const des_cblock *) clear,
				(des_cblock *) cipher,
				8, schedule, iv, encrypt));
}
