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

#include <krb5/krb5.h>
#include "des_int.h"

#include "odd.h"          /* Load compile-time generated odd_parity table */

/*
 * des_fixup_key_parity: Forces odd parity per byte; parity is bits
 *                       8,16,...64 in des order, implies 0, 8, 16, ...
 *                       vax order.
 */
void
mit_des_fixup_key_parity(key)
     register mit_des_cblock key;
{
    int i;

    for (i=0; i<sizeof(mit_des_cblock); i++)
      key[i] = odd_parity[key[i]];

    return;
}

/*
 * des_check_key_parity: returns true iff key has the correct des parity.
 *                       See des_fix_key_parity for the definition of
 *                       correct des parity.
 */
int
mit_des_check_key_parity(key)
     register mit_des_cblock key;
{
    int i;

    for (i=0; i<sizeof(mit_des_cblock); i++)
      if (key[i] != odd_parity[key[i]])
	return(0);

    return(1);
}
