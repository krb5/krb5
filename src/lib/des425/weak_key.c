/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 *
 * These routines form the library interface to the DES facilities.
 *
 * Originally written 8/85 by Steve Miller, MIT Project Athena.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_weak_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "des.h"
#include <krb5/ext-proto.h>

/*
 * mit_des_is_weak_key: returns true iff key is a [semi-]weak des key.
 *
 * Requires: key has correct odd parity.
 */
int
des_is_weak_key(key)
     mit_des_cblock key;
{
	return (mit_des_is_weak_key(key));
}
