/*
 * lib/crypto/openssl/des/string2key.c
 *
 * Copyright 2009 by the Massachusetts Institute
 * of Technology.
 * All Rights Reserved.
 *
 */

#include "des_int.h"
#include <openssl/des.h>


krb5_error_code
mit_des_string_to_key_int (krb5_keyblock *key,
			   const krb5_data *pw, const krb5_data *salt)
{
    DES_cblock outkey;
    DES_string_to_key(pw->data, &outkey);
    if ( key->length <  sizeof(outkey))
        return KRB5_CRYPTO_INTERNAL;
    key->length = sizeof(outkey);
    memcpy(key->contents, outkey, key->length); 
    return 0;
}

