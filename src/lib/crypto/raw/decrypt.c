#include "k5-int.h"
#include "raw.h"

krb5_error_code
krb5_raw_decrypt(enc, hash, key, usage, ivec, input, output)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *ivec;
     krb5_const krb5_data *input;
     krb5_data *output;
{
    return((*(enc->decrypt))(key, ivec, input, output));
}
