#include "k5-int.h"

void krb5_dk_encrypt_length
KRB5_PROTOTYPE((krb5_const struct krb5_enc_provider *enc,
		krb5_const struct krb5_hash_provider *hash,
		size_t input, size_t *length));

krb5_error_code krb5_dk_encrypt
KRB5_PROTOTYPE((krb5_const struct krb5_enc_provider *enc,
		krb5_const struct krb5_hash_provider *hash,
		krb5_const krb5_keyblock *key, krb5_keyusage usage,
		krb5_const krb5_data *ivec,
		krb5_const krb5_data *input, krb5_data *output));

krb5_error_code krb5_dk_decrypt
KRB5_PROTOTYPE((krb5_const struct krb5_enc_provider *enc,
		krb5_const struct krb5_hash_provider *hash,
		krb5_const krb5_keyblock *key, krb5_keyusage usage,
		krb5_const krb5_data *ivec, krb5_const krb5_data *input,
		krb5_data *arg_output));

krb5_error_code krb5_dk_string_to_key
KRB5_PROTOTYPE((krb5_const struct krb5_enc_provider *enc, 
		krb5_const krb5_data *string, krb5_const krb5_data *salt,
		krb5_keyblock *key));

krb5_error_code krb5_derive_key
KRB5_PROTOTYPE((krb5_const struct krb5_enc_provider *enc,
		krb5_const krb5_keyblock *inkey,
		krb5_keyblock *outkey, krb5_const krb5_data *in_constant));

krb5_error_code krb5_dk_make_checksum
KRB5_PROTOTYPE((krb5_const struct krb5_hash_provider *hash,
		krb5_const krb5_keyblock *key, krb5_keyusage usage,
		krb5_const krb5_data *input, krb5_data *output));
