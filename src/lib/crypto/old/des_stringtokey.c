#include "k5-int.h"
#include "old.h"

krb5_error_code
krb5_des_string_to_key(enc, string, salt, key)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const krb5_data *string;
     krb5_const krb5_data *salt;
     krb5_keyblock *key;
{
    return(mit_des_string_to_key_int(key, string, salt));
}
