#ifndef __KTEST_H__
#define __KTEST_H__

#include "k5-int.h"
#include "kdb.h"

#define SAMPLE_USEC 123456
#define SAMPLE_TIME 771228197  /* Fri Jun 10  6:03:17 GMT 1994 */
#define SAMPLE_SEQ_NUMBER 17
#define SAMPLE_NONCE 42
#define SAMPLE_FLAGS 0xFEDCBA98
#define SAMPLE_ERROR 0x3C;
krb5_error_code ktest_make_sample_data
	(krb5_data *d);
krb5_error_code ktest_make_sample_authenticator
	(krb5_authenticator *a);
  krb5_error_code ktest_make_sample_principal
	(krb5_principal *p);
  krb5_error_code ktest_make_sample_checksum
	(krb5_checksum *cs);
  krb5_error_code ktest_make_sample_keyblock
	(krb5_keyblock *kb);
krb5_error_code ktest_make_sample_ticket
	(krb5_ticket *tkt);
  krb5_error_code ktest_make_sample_enc_data
	(krb5_enc_data *ed);
krb5_error_code ktest_make_sample_enc_tkt_part
	(krb5_enc_tkt_part *etp);
  krb5_error_code ktest_make_sample_transited
	(krb5_transited *t);
  krb5_error_code ktest_make_sample_ticket_times
	(krb5_ticket_times *tt);
  krb5_error_code ktest_make_sample_addresses
	(krb5_address ***caddrs);
  krb5_error_code ktest_make_sample_address
	(krb5_address *a);
  krb5_error_code ktest_make_sample_authorization_data
	(krb5_authdata ***ad);
  krb5_error_code ktest_make_sample_authdata
	(krb5_authdata *ad);
krb5_error_code ktest_make_sample_enc_kdc_rep_part
	(krb5_enc_kdc_rep_part *ekr);
krb5_error_code ktest_make_sample_kdc_req
	(krb5_kdc_req *kr);

  krb5_error_code ktest_make_sample_last_req
	(krb5_last_req_entry ***lr);
  krb5_error_code ktest_make_sample_last_req_entry
	(krb5_last_req_entry **lre);
krb5_error_code ktest_make_sample_kdc_rep
	(krb5_kdc_rep *kdcr);
  krb5_error_code ktest_make_sample_pa_data_array
	(krb5_pa_data ***pad);
  krb5_error_code ktest_make_sample_empty_pa_data_array
	(krb5_pa_data ***pad);
  krb5_error_code ktest_make_sample_pa_data
	(krb5_pa_data *pad);
krb5_error_code ktest_make_sample_ap_req
	(krb5_ap_req *ar);
krb5_error_code ktest_make_sample_ap_rep
	(krb5_ap_rep *ar);
krb5_error_code ktest_make_sample_ap_rep_enc_part
	(krb5_ap_rep_enc_part *arep);
krb5_error_code ktest_make_sample_kdc_req_body
	(krb5_kdc_req *krb);
krb5_error_code ktest_make_sample_safe
	(krb5_safe *s);
krb5_error_code ktest_make_sample_priv
	(krb5_priv *p);
krb5_error_code ktest_make_sample_priv_enc_part
	(krb5_priv_enc_part *pep);
krb5_error_code ktest_make_sample_cred
	(krb5_cred *c);
krb5_error_code ktest_make_sample_cred_enc_part
	(krb5_cred_enc_part *cep);
  krb5_error_code ktest_make_sample_sequence_of_ticket
	(krb5_ticket ***sot);
krb5_error_code ktest_make_sample_error
	(krb5_error *kerr);
krb5_error_code ktest_make_sequence_of_cred_info
	(krb5_cred_info ***soci);
  krb5_error_code ktest_make_sample_cred_info
	(krb5_cred_info *ci);
krb5_error_code ktest_make_sample_passwd_phrase_element
	(passwd_phrase_element *ppe);
krb5_error_code ktest_make_sample_krb5_pwd_data
	(krb5_pwd_data *pd);
krb5_error_code ktest_make_sample_alt_method
	(krb5_alt_method *am);

krb5_error_code ktest_make_sample_etype_info
    (krb5_etype_info_entry *** p);
krb5_error_code ktest_make_sample_etype_info2
    (krb5_etype_info_entry *** p);
krb5_error_code ktest_make_sample_pa_enc_ts
	(krb5_pa_enc_ts *am);
krb5_error_code ktest_make_sample_sam_challenge
	(krb5_sam_challenge * p);
krb5_error_code ktest_make_sample_sam_response
	(krb5_sam_response * p);
krb5_error_code ktest_make_sample_sam_response_2
	(krb5_sam_response_2 * p);
krb5_error_code ktest_make_sample_sam_key(krb5_sam_key *p);
krb5_error_code ktest_make_sample_enc_sam_response_enc
	(krb5_enc_sam_response_enc *p);
krb5_error_code ktest_make_sample_predicted_sam_response(krb5_predicted_sam_response *p);
krb5_error_code ktest_make_sample_enc_sam_response_enc_2(krb5_enc_sam_response_enc_2 *p);
krb5_error_code ktest_make_sample_pa_s4u_x509_user(krb5_pa_s4u_x509_user *p);
krb5_error_code ktest_make_sample_ad_kdcissued(krb5_ad_kdcissued *p);
krb5_error_code ktest_make_sample_ad_signedpath_data(krb5_ad_signedpath_data *p);
krb5_error_code ktest_make_sample_ad_signedpath(krb5_ad_signedpath *p);
krb5_error_code ktest_make_sample_iakerb_header(krb5_iakerb_header *p);
krb5_error_code ktest_make_sample_iakerb_finished(krb5_iakerb_finished *p);

#ifdef ENABLE_LDAP
krb5_error_code ktest_make_sample_ldap_seqof_key_data(ldap_seqof_key_data * p);
#endif
/*----------------------------------------------------------------------*/

void ktest_empty_authorization_data
	(krb5_authdata **ad);
void ktest_destroy_authorization_data
	(krb5_authdata ***ad);
  void ktest_destroy_authorization_data
	(krb5_authdata ***ad);
void ktest_empty_addresses
	(krb5_address **a);
void ktest_destroy_addresses
	(krb5_address ***a);
  void ktest_destroy_address
	(krb5_address **a);
void ktest_empty_pa_data_array
	(krb5_pa_data **pad);
void ktest_destroy_pa_data_array
	(krb5_pa_data ***pad);
  void ktest_destroy_pa_data
	(krb5_pa_data **pad);

void ktest_destroy_data
	(krb5_data **d);
void ktest_empty_data
	(krb5_data *d);
void ktest_destroy_principal
	(krb5_principal *p);
void ktest_destroy_checksum
	(krb5_checksum **cs);
void ktest_empty_keyblock
	(krb5_keyblock *kb);
void ktest_destroy_keyblock
	(krb5_keyblock **kb);
void ktest_destroy_authdata
	(krb5_authdata **ad);
void ktest_destroy_sequence_of_integer
	(long **soi);
void ktest_destroy_sequence_of_ticket
	(krb5_ticket ***sot);
  void ktest_destroy_ticket
	(krb5_ticket **tkt);
void ktest_empty_ticket
	(krb5_ticket *tkt);
void ktest_destroy_enc_data
	(krb5_enc_data *ed);
void ktest_empty_error
        (krb5_error * kerr);
void ktest_destroy_etype_info_entry
	(krb5_etype_info_entry *i);
void ktest_destroy_etype_info
	(krb5_etype_info_entry **info);

void ktest_empty_kdc_req
        (krb5_kdc_req *kr);
void ktest_empty_kdc_rep
        (krb5_kdc_rep *kr);

void ktest_empty_authenticator
        (krb5_authenticator *a);
void ktest_empty_enc_tkt_part
        (krb5_enc_tkt_part * etp);
void ktest_destroy_enc_tkt_part
        (krb5_enc_tkt_part ** etp);
void ktest_empty_enc_kdc_rep_part
        (krb5_enc_kdc_rep_part * ekr);
void ktest_destroy_transited
        (krb5_transited * t);
void ktest_empty_ap_rep
        (krb5_ap_rep * ar);
void ktest_empty_ap_req
        (krb5_ap_req * ar);
void ktest_empty_cred_enc_part
        (krb5_cred_enc_part * cep);
void ktest_destroy_cred_info
        (krb5_cred_info ** ci);
void ktest_destroy_sequence_of_cred_info
        (krb5_cred_info *** soci);
void ktest_empty_safe
        (krb5_safe * s);
void ktest_empty_priv
        (krb5_priv * p);
void ktest_empty_priv_enc_part
        (krb5_priv_enc_part * pep);
void ktest_empty_cred
        (krb5_cred * c);
void ktest_destroy_last_req
        (krb5_last_req_entry *** lr);
void ktest_empty_ap_rep_enc_part
        (krb5_ap_rep_enc_part * arep);
void ktest_empty_passwd_phrase_element
        (passwd_phrase_element * ppe);
void ktest_empty_pwd_data
        (krb5_pwd_data * pd);
void ktest_empty_alt_method
	(krb5_alt_method *am);
void ktest_empty_sam_challenge
	(krb5_sam_challenge * p);
void ktest_empty_sam_response
	(krb5_sam_response * p);
void ktest_empty_sam_key(krb5_sam_key *p);
void ktest_empty_enc_sam_response_enc(krb5_enc_sam_response_enc *p);
void ktest_empty_predicted_sam_response(krb5_predicted_sam_response *p);
void ktest_empty_sam_response_2(krb5_sam_response_2 *p);
void ktest_empty_enc_sam_response_enc_2(krb5_enc_sam_response_enc_2 *p);
void ktest_empty_pa_s4u_x509_user(krb5_pa_s4u_x509_user *p);
void ktest_empty_ad_kdcissued(krb5_ad_kdcissued *p);
void ktest_empty_ad_signedpath_data(krb5_ad_signedpath_data *p);
void ktest_empty_ad_signedpath(krb5_ad_signedpath *p);
void ktest_empty_iakerb_header(krb5_iakerb_header *p);
void ktest_empty_iakerb_finished(krb5_iakerb_finished *p);

#ifdef ENABLE_LDAP
void ktest_empty_ldap_seqof_key_data(krb5_context, ldap_seqof_key_data *p);
#endif

extern krb5_context test_context;
extern char *sample_principal_name;

#endif
