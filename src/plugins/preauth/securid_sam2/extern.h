 krb5_error_code sam_get_db_entry(krb5_context , krb5_principal,
                        int *, krb5_db_entry **);

krb5_error_code
securid_make_sam_challenge_2_and_cksum (krb5_context context,
		krb5_sam_challenge_2 *sc2, krb5_sam_challenge_2_body *sc2b,
					krb5_keyblock *cksum_key);
krb5_error_code get_securid_edata_2(krb5_context context,
				krb5_db_entry *client,
				krb5_sam_challenge_2_body *sc2b,
				    krb5_sam_challenge_2 *sc2);

krb5_error_code verify_securid_data_2(krb5_context context,
				      krb5_db_entry *client,
				      krb5_sam_response_2 *sr2,
				      krb5_enc_tkt_part *enc_tkt_reply,
				      krb5_pa_data *pa,
				      krb5_sam_challenge_2 **sc2_out);
