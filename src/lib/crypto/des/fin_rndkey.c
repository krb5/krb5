/*
 * lib/crypto/des/fin_rndkey.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"
#include "des_int.h"

/*
        free any resources held by "seed" and assigned by init_random_key()
 */

krb5_error_code mit_des_finish_random_key (seed)
    krb5_pointer * seed;
{
    memset((char *)*seed, 0, sizeof(mit_des_random_key_seed) );
    krb5_xfree(*seed);
    *seed = 0;
    return 0;
}
