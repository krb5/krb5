#ifndef ARCFOUR_H
#define ARCFOUR_H

extern void
krb5_arcfour_encrypt_length(const struct krb5_enc_provider *,
			const struct krb5_hash_provider *,
			size_t,
			size_t *);

extern 
krb5_error_code krb5_arcfour_encrypt(const struct krb5_enc_provider *,
			const struct krb5_hash_provider *,
			const krb5_keyblock *,
			krb5_keyusage,
			const krb5_data *,
     			const krb5_data *,
			krb5_data *);

extern 
krb5_error_code krb5_arcfour_decrypt(const struct krb5_enc_provider *,
			const struct krb5_hash_provider *,
			const krb5_keyblock *,
			krb5_keyusage,
			const krb5_data *,
			const krb5_data *,
			krb5_data *);

extern krb5_error_code krb5int_arcfour_string_to_key(
     const struct krb5_enc_provider *,
     const krb5_data *,
     const krb5_data *,
     const krb5_data *,
     krb5_keyblock *);

extern const struct krb5_enc_provider krb5int_enc_arcfour;
#endif /* ARCFOUR_H */
