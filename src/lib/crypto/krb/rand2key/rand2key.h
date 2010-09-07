/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "k5-int.h"


krb5_error_code
krb5int_arcfour_make_key(const krb5_data *randombits, krb5_keyblock *key);

krb5_error_code
krb5int_des_make_key(const krb5_data *randombits, krb5_keyblock *key);

/* RFC 3961 */
krb5_error_code
krb5int_des3_make_key(const krb5_data *randombits, krb5_keyblock *key);

krb5_error_code
krb5int_aes_make_key(const krb5_data *randombits, krb5_keyblock *key);

krb5_error_code
krb5int_camellia_make_key(const krb5_data *randombits, krb5_keyblock *key);
