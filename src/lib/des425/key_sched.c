/*
 * lib/des425/key_sched.c
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
 * This routine computes the DES key schedule given a key.  The
 * permutations and shifts have been done at compile time, resulting
 * in a direct one-step mapping from the input key to the key
 * schedule.
 *
 * Also checks parity and weak keys.
 *
 * Watch out for the subscripts -- most effectively start at 1 instead
 * of at zero.  Maybe some bugs in that area.
 *
 * DON'T change the data types for arrays and such, or it will either
 * break or run slower.  This was optimized for Uvax2.
 *
 * In case the user wants to cache the computed key schedule, it is
 * passed as an arg.  Also implies that caller has explicit control
 * over zeroing both the key schedule and the key.
 *
 * All registers labeled imply Vax using the Ultrix or 4.2bsd compiler.
 *
 * Originally written 6/85 by Steve Miller, MIT Project Athena.
 */


#include <stdio.h>
#include "des.h"

KRB5_DLLIMP int KRB5_CALLCONV
des_key_sched(k,schedule)
    register mit_des_cblock k;	/* r11 */
    mit_des_key_schedule schedule;
{
	return (mit_des_key_sched(k, schedule));
}
