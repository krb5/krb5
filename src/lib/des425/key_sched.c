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

#if !defined(lint) && !defined(SABER)
static char rcsid_key_sched_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <stdio.h>
#include "des.h"

typedef char key[64];

/* the following are really void but cc86 doesnt allow it */
static void make_key_sched PROTOTYPE((key, mit_des_key_schedule));

int
des_key_sched(k,schedule)
    register mit_des_cblock k;	/* r11 */
    mit_des_key_schedule schedule;
{
	return (mit_des_key_sched(k, schedule));
}
