/* lib/crypto/openss/des/afsstring2key.c
 *
 * Copyright 2009 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 */

#include "k5-int.h"
#include "des_int.h"
#include <ctype.h>

krb5_error_code
mit_afs_string_to_key (krb5_keyblock *keyblock, const krb5_data *data,
		       const krb5_data *salt)
{
    return KRB5_CRYPTO_INTERNAL; 
}
char *
mit_afs_crypt(const char *pw, const char *salt,
                char *iobuf)
{
    /* Unsupported operation */
    return NULL;
}


