#include "k5-int.h"
#include "raw.h"

void
krb5_raw_encrypt_length(enc, hash, inputlen, length)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     size_t inputlen;
     size_t *length;
{
    size_t blocksize;

    (*(enc->block_size))(&blocksize);

    *length = krb5_roundup(inputlen, blocksize);
}

krb5_error_code
krb5_raw_encrypt(enc, hash, key, usage, ivec, input, output)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *ivec;
     krb5_const krb5_data *input;
     krb5_data *output;
{
    return((*(enc->encrypt))(key, ivec, input, output));
}
