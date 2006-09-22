krb5_error_code asn1_encode_sequence_of_keys (krb5_key_data *key_data,
		krb5_int16 n_key_data,
		krb5_int32 mkvno,
		krb5_data **code);

krb5_error_code asn1_decode_sequence_of_keys (krb5_data *in,
		krb5_key_data **out,
		krb5_int16 *n_key_data,
		int *mkvno);
