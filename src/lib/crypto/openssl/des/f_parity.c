/*
 * lib/crypto/openssl/des/f_parity.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
 */

#include "des_int.h"
#include <openssl/des.h>

void
mit_des_fixup_key_parity(mit_des_cblock key)
{
   DES_set_odd_parity(key);
}

/*
 * des_check_key_parity: returns true iff key has the correct des parity.
 *                       See des_fix_key_parity for the definition of
 *                       correct des parity.
 */
int
mit_des_check_key_parity(mit_des_cblock key)
{
    if (!DES_check_key_parity(key))
                return(0);
    return (1);
}

