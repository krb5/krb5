/*
 * lib/des425/key_parity.c
 *
 * Copyright 1989, 1990 by the Massachusetts Institute of Technology.
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
 */

#include "des_int.h"
#include "des.h"

/*
 * des_fixup_key_parity: Forces odd parity per byte; parity is bits
 *                       8,16,...64 in des order, implies 0, 8, 16, ...
 *                       vax order.
 */
void
des_fixup_key_parity(key)
     register mit_des_cblock key;
{
	mit_des_fixup_key_parity(key);
}

/*
 * des_check_key_parity: returns true iff key has the correct des parity.
 */
int
des_check_key_parity(key)
     register mit_des_cblock key;
{
	return(mit_des_check_key_parity(key));
}

