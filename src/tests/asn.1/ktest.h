#ifndef __KTEST_H__
#define __KTEST_H__

#include <krb5/krb5.h>

#define SAMPLE_USEC 123456
#define SAMPLE_TIME 771228197  /* Fri Jun 10  6:03:17 GMT 1994 */
#define SAMPLE_SEQ_NUMBER 17
#define SAMPLE_NONCE 42
#define SAMPLE_FLAGS 0xFEDCBA98
#define SAMPLE_ERROR 0x3C;
krb5_error_code ktest_make_sample_data
	PROTOTYPE((krb5_data *d));
krb5_error_code ktest_make_sample_authenticator
	PROTOTYPE((krb5_authenticator *a));
  krb5_error_code ktest_make_sample_principal
	PROTOTYPE((krb5_principal *p));
  krb5_error_code ktest_make_sample_checksum
	PROTOTYPE((krb5_checksum *cs));
  krb5_error_code ktest_make_sample_keyblock
	PROTOTYPE((krb5_keyblock *kb));
krb5_error_code ktest_make_sample_ticket
	PROTOTYPE((krb5_ticket *tkt));
  krb5_error_code ktest_make_sample_enc_data
	PROTOTYPE((krb5_enc_data *ed));
krb5_error_code ktest_make_sample_enc_tkt_part
	PROTOTYPE((krb5_enc_tkt_part *etp));
  krb5_error_code ktest_make_sample_transited
	PROTOTYPE((krb5_transited *t));
  krb5_error_code ktest_make_sample_ticket_times
	PROTOTYPE((krb5_ticket_times *tt));
  krb5_error_code ktest_make_sample_addresses
	PROTOTYPE((krb5_address ***caddrs));
  krb5_error_code ktest_make_sample_address
	PROTOTYPE((krb5_address *a));
  krb5_error_code ktest_make_sample_authorization_data
	PROTOTYPE((krb5_authdata ***ad));
  krb5_error_code ktest_make_sample_authdata
	PROTOTYPE((krb5_authdata *ad));
krb5_error_code ktest_make_sample_enc_kdc_rep_part
	PROTOTYPE((krb5_enc_kdc_rep_part *ekr));
krb5_error_code ktest_make_sample_kdc_req
	PROTOTYPE((krb5_kdc_req *kr));

  krb5_error_code ktest_make_sample_last_req
	PROTOTYPE((krb5_last_req_entry ***lr));
  krb5_error_code ktest_make_sample_last_req_entry
	PROTOTYPE((krb5_last_req_entry **lre));
krb5_error_code ktest_make_sample_kdc_rep
	PROTOTYPE((krb5_kdc_rep *kdcr));
  krb5_error_code ktest_make_sample_pa_data_array
	PROTOTYPE((krb5_pa_data ***pad));
  krb5_error_code ktest_make_sample_pa_data
	PROTOTYPE((krb5_pa_data *pad));
krb5_error_code ktest_make_sample_ap_req
	PROTOTYPE((krb5_ap_req *ar));
krb5_error_code ktest_make_sample_ap_rep
	PROTOTYPE((krb5_ap_rep *ar));
krb5_error_code ktest_make_sample_ap_rep_enc_part
	PROTOTYPE((krb5_ap_rep_enc_part *arep));
krb5_error_code ktest_make_sample_kdc_req_body
	PROTOTYPE((krb5_kdc_req *krb));
krb5_error_code ktest_make_sample_safe
	PROTOTYPE((krb5_safe *s));
krb5_error_code ktest_make_sample_priv
	PROTOTYPE((krb5_priv *p));
krb5_error_code ktest_make_sample_priv_enc_part
	PROTOTYPE((krb5_priv_enc_part *pep));
krb5_error_code ktest_make_sample_cred
	PROTOTYPE((krb5_cred *c));
krb5_error_code ktest_make_sample_cred_enc_part
	PROTOTYPE((krb5_cred_enc_part *cep));
  krb5_error_code ktest_make_sample_sequence_of_ticket
	PROTOTYPE((krb5_ticket ***sot));
krb5_error_code ktest_make_sample_error
	PROTOTYPE((krb5_error *kerr));
krb5_error_code ktest_make_sequence_of_cred_info
	PROTOTYPE((krb5_cred_info ***soci));
  krb5_error_code ktest_make_sample_cred_info
	PROTOTYPE((krb5_cred_info *ci));
krb5_error_code ktest_make_sample_passwd_phrase_element
	PROTOTYPE((passwd_phrase_element *ppe));
krb5_error_code ktest_make_sample_krb5_pwd_data
	PROTOTYPE((krb5_pwd_data *pd));

/*----------------------------------------------------------------------*/

void ktest_empty_authorization_data
	PROTOTYPE((krb5_authdata **ad));
void ktest_destroy_authorization_data
	PROTOTYPE((krb5_authdata ***ad));
  void ktest_destroy_authorization_data
	PROTOTYPE((krb5_authdata ***ad));
void ktest_empty_addresses
	PROTOTYPE((krb5_address **a));
void ktest_destroy_addresses
	PROTOTYPE((krb5_address ***a));
  void ktest_destroy_address
	PROTOTYPE((krb5_address **a));
void ktest_empty_pa_data_array
	PROTOTYPE((krb5_pa_data **pad));
void ktest_destroy_pa_data_array
	PROTOTYPE((krb5_pa_data ***pad));
  void ktest_destroy_pa_data
	PROTOTYPE((krb5_pa_data **pad));

void ktest_destroy_data
	PROTOTYPE((krb5_data **d));
void ktest_empty_data
	PROTOTYPE((krb5_data *d));
void ktest_destroy_principal
	PROTOTYPE((krb5_principal *p));
void ktest_destroy_checksum
	PROTOTYPE((krb5_checksum **cs));
void ktest_destroy_keyblock
	PROTOTYPE((krb5_keyblock **kb));
void ktest_destroy_authdata
	PROTOTYPE((krb5_authdata **ad));
void ktest_destroy_sequence_of_integer
	PROTOTYPE((long **soi));
void ktest_destroy_sequence_of_enctype
	PROTOTYPE((krb5_enctype **soi));
void ktest_destroy_sequence_of_ticket
	PROTOTYPE((krb5_ticket ***sot));
  void ktest_destroy_ticket
	PROTOTYPE((krb5_ticket **tkt));
void ktest_destroy_enc_data
	PROTOTYPE((krb5_enc_data *ed));

#endif
