#ifndef ARCFOUR_H
#define ARCFOUR_H

void
krb5_arcfour_encrypt_length(krb5_const struct krb5_enc_provider *,
			krb5_const struct krb5_hash_provider *,
			size_t,
			size_t *);

krb5_error_code krb5_arcfour_encrypt(krb5_const struct krb5_enc_provider *,
			krb5_const struct krb5_hash_provider *,
			krb5_const krb5_keyblock *,
			krb5_keyusage,
			krb5_const krb5_data *,
     			krb5_const krb5_data *,
			krb5_data *);

krb5_error_code krb5_arcfour_decrypt(krb5_const struct krb5_enc_provider *,
			krb5_const struct krb5_hash_provider *,
			krb5_const krb5_keyblock *,
			krb5_keyusage,
			krb5_const krb5_data *,
			krb5_const krb5_data *,
			krb5_data *);

krb5_error_code krb5_arcfour_string_to_key(
     krb5_const struct krb5_enc_provider *,
     krb5_const krb5_data *,
     krb5_const krb5_data *,
     krb5_keyblock *);

const struct krb5_enc_provider krb5int_enc_arcfour;
#endif /* ARCFOUR_H */
