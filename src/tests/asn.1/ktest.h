#ifndef __KTEST_H__
#define __KTEST_H__

#include "k5-int.h"

#define SAMPLE_USEC 123456
#define SAMPLE_TIME 771228197  /* Fri Jun 10  6:03:17 GMT 1994 */
#define SAMPLE_SEQ_NUMBER 17
#define SAMPLE_NONCE 42
#define SAMPLE_FLAGS 0xFEDCBA98
#define SAMPLE_ERROR 0x3C;
krb5_error_code ktest_make_sample_data
	KRB5_PROTOTYPE((krb5_data *d));
krb5_error_code ktest_make_sample_authenticator
	KRB5_PROTOTYPE((krb5_authenticator *a));
  krb5_error_code ktest_make_sample_principal
	KRB5_PROTOTYPE((krb5_principal *p));
  krb5_error_code ktest_make_sample_checksum
	KRB5_PROTOTYPE((krb5_checksum *cs));
  krb5_error_code ktest_make_sample_keyblock
	KRB5_PROTOTYPE((krb5_keyblock *kb));
krb5_error_code ktest_make_sample_ticket
	KRB5_PROTOTYPE((krb5_ticket *tkt));
  krb5_error_code ktest_make_sample_enc_data
	KRB5_PROTOTYPE((krb5_enc_data *ed));
krb5_error_code ktest_make_sample_enc_tkt_part
	KRB5_PROTOTYPE((krb5_enc_tkt_part *etp));
  krb5_error_code ktest_make_sample_transited
	KRB5_PROTOTYPE((krb5_transited *t));
  krb5_error_code ktest_make_sample_ticket_times
	KRB5_PROTOTYPE((krb5_ticket_times *tt));
  krb5_error_code ktest_make_sample_addresses
	KRB5_PROTOTYPE((krb5_address ***caddrs));
  krb5_error_code ktest_make_sample_address
	KRB5_PROTOTYPE((krb5_address *a));
  krb5_error_code ktest_make_sample_authorization_data
	KRB5_PROTOTYPE((krb5_authdata ***ad));
  krb5_error_code ktest_make_sample_authdata
	KRB5_PROTOTYPE((krb5_authdata *ad));
krb5_error_code ktest_make_sample_enc_kdc_rep_part
	KRB5_PROTOTYPE((krb5_enc_kdc_rep_part *ekr));
krb5_error_code ktest_make_sample_kdc_req
	KRB5_PROTOTYPE((krb5_kdc_req *kr));

  krb5_error_code ktest_make_sample_last_req
	KRB5_PROTOTYPE((krb5_last_req_entry ***lr));
  krb5_error_code ktest_make_sample_last_req_entry
	KRB5_PROTOTYPE((krb5_last_req_entry **lre));
krb5_error_code ktest_make_sample_kdc_rep
	KRB5_PROTOTYPE((krb5_kdc_rep *kdcr));
  krb5_error_code ktest_make_sample_pa_data_array
	KRB5_PROTOTYPE((krb5_pa_data ***pad));
  krb5_error_code ktest_make_sample_empty_pa_data_array
	KRB5_PROTOTYPE((krb5_pa_data ***pad));
  krb5_error_code ktest_make_sample_pa_data
	KRB5_PROTOTYPE((krb5_pa_data *pad));
krb5_error_code ktest_make_sample_ap_req
	KRB5_PROTOTYPE((krb5_ap_req *ar));
krb5_error_code ktest_make_sample_ap_rep
	KRB5_PROTOTYPE((krb5_ap_rep *ar));
krb5_error_code ktest_make_sample_ap_rep_enc_part
	KRB5_PROTOTYPE((krb5_ap_rep_enc_part *arep));
krb5_error_code ktest_make_sample_kdc_req_body
	KRB5_PROTOTYPE((krb5_kdc_req *krb));
krb5_error_code ktest_make_sample_safe
	KRB5_PROTOTYPE((krb5_safe *s));
krb5_error_code ktest_make_sample_priv
	KRB5_PROTOTYPE((krb5_priv *p));
krb5_error_code ktest_make_sample_priv_enc_part
	KRB5_PROTOTYPE((krb5_priv_enc_part *pep));
krb5_error_code ktest_make_sample_cred
	KRB5_PROTOTYPE((krb5_cred *c));
krb5_error_code ktest_make_sample_cred_enc_part
	KRB5_PROTOTYPE((krb5_cred_enc_part *cep));
  krb5_error_code ktest_make_sample_sequence_of_ticket
	KRB5_PROTOTYPE((krb5_ticket ***sot));
krb5_error_code ktest_make_sample_error
	KRB5_PROTOTYPE((krb5_error *kerr));
krb5_error_code ktest_make_sequence_of_cred_info
	KRB5_PROTOTYPE((krb5_cred_info ***soci));
  krb5_error_code ktest_make_sample_cred_info
	KRB5_PROTOTYPE((krb5_cred_info *ci));
krb5_error_code ktest_make_sample_passwd_phrase_element
	KRB5_PROTOTYPE((passwd_phrase_element *ppe));
krb5_error_code ktest_make_sample_krb5_pwd_data
	KRB5_PROTOTYPE((krb5_pwd_data *pd));
krb5_error_code ktest_make_sample_alt_method
	KRB5_PROTOTYPE((krb5_alt_method *am));

krb5_error_code ktest_make_sample_etype_info
    KRB5_PROTOTYPE((krb5_etype_info_entry *** p));
krb5_error_code ktest_make_sample_pa_enc_ts
	KRB5_PROTOTYPE((krb5_pa_enc_ts *am));
krb5_error_code ktest_make_sample_sam_challenge
	KRB5_PROTOTYPE((krb5_sam_challenge * p));
krb5_error_code ktest_make_sample_sam_response
	KRB5_PROTOTYPE((krb5_sam_response * p));

/*----------------------------------------------------------------------*/

void ktest_empty_authorization_data
	KRB5_PROTOTYPE((krb5_authdata **ad));
void ktest_destroy_authorization_data
	KRB5_PROTOTYPE((krb5_authdata ***ad));
  void ktest_destroy_authorization_data
	KRB5_PROTOTYPE((krb5_authdata ***ad));
void ktest_empty_addresses
	KRB5_PROTOTYPE((krb5_address **a));
void ktest_destroy_addresses
	KRB5_PROTOTYPE((krb5_address ***a));
  void ktest_destroy_address
	KRB5_PROTOTYPE((krb5_address **a));
void ktest_empty_pa_data_array
	KRB5_PROTOTYPE((krb5_pa_data **pad));
void ktest_destroy_pa_data_array
	KRB5_PROTOTYPE((krb5_pa_data ***pad));
  void ktest_destroy_pa_data
	KRB5_PROTOTYPE((krb5_pa_data **pad));

void ktest_destroy_data
	KRB5_PROTOTYPE((krb5_data **d));
void ktest_empty_data
	KRB5_PROTOTYPE((krb5_data *d));
void ktest_destroy_principal
	KRB5_PROTOTYPE((krb5_principal *p));
void ktest_destroy_checksum
	KRB5_PROTOTYPE((krb5_checksum **cs));
void ktest_destroy_keyblock
	KRB5_PROTOTYPE((krb5_keyblock **kb));
void ktest_destroy_authdata
	KRB5_PROTOTYPE((krb5_authdata **ad));
void ktest_destroy_sequence_of_integer
	KRB5_PROTOTYPE((long **soi));
void ktest_destroy_sequence_of_ticket
	KRB5_PROTOTYPE((krb5_ticket ***sot));
  void ktest_destroy_ticket
	KRB5_PROTOTYPE((krb5_ticket **tkt));
void ktest_destroy_enc_data
	KRB5_PROTOTYPE((krb5_enc_data *ed));

void ktest_destroy_etype_info_entry
	KRB5_PROTOTYPE((krb5_etype_info_entry *i));
void ktest_destroy_etype_info
	KRB5_PROTOTYPE((krb5_etype_info_entry **info));

extern krb5_context test_context;
extern char *sample_principal_name;

#endif
