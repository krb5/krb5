/*
 * $Source$
 * $Author$
 *
 * Copyright 1989, 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * These routines check and fix parity of encryption keys for the DES
 * algorithm.
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 *
 * These routines form the library interface to the DES facilities.
 *
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_key_parity_c[] =
"$Id$";
#endif	/* !lint & !SABER */

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
 *                       See des_fix_key_parity for the definition of
 *                       correct des parity.
 */
int
des_check_key_parity(key)
     register mit_des_cblock key;
{
	return(mit_des_check_key_parity(key));
}

