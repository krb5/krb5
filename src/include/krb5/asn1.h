/*
 * include/krb5/asn1.h
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * meta-include file for KRB5 asn.1/ISODE stuff
 */

#ifndef KRB5_ASN1__
#define KRB5_ASN1__

/* ASN.1 encoding knowledge; KEEP IN SYNC WITH ASN.1 defs! */
/* here we use some knowledge of ASN.1 encodings */
/* 
  Ticket is APPLICATION 1.
  Authenticator is APPLICATION 2.
  AS_REQ is APPLICATION 10.
  AS_REP is APPLICATION 11.
  TGS_REQ is APPLICATION 12.
  TGS_REP is APPLICATION 13.
  AP_REQ is APPLICATION 14.
  AP_REP is APPLICATION 15.
  KRB_SAFE is APPLICATION 20.
  KRB_PRIV is APPLICATION 21.
  KRB_CRED is APPLICATION 22.
  EncASRepPart is APPLICATION 25.
  EncTGSRepPart is APPLICATION 26.
  EncAPRepPart is APPLICATION 27.
  EncKrbPrivPart is APPLICATION 28.
  EncKrbCredPart is APPLICATION 29.
  KRB_ERROR is APPLICATION 30.
 */
/* allow either constructed or primitive encoding, so check for bit 6
   set or reset */
#define krb5_is_krb_ticket(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x61 ||\
				    (dat)->data[0] == 0x41))
#define krb5_is_krb_authenticator(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x62 ||\
				    (dat)->data[0] == 0x42))
#define krb5_is_as_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6a ||\
				    (dat)->data[0] == 0x4a))
#define krb5_is_as_rep(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6b ||\
				    (dat)->data[0] == 0x4b))
#define krb5_is_tgs_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6c ||\
				    (dat)->data[0] == 0x4c))
#define krb5_is_tgs_rep(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6d ||\
				    (dat)->data[0] == 0x4d))
#define krb5_is_ap_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6e ||\
				    (dat)->data[0] == 0x4e))
#define krb5_is_ap_rep(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6f ||\
				    (dat)->data[0] == 0x4f))
#define krb5_is_krb_safe(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x74 ||\
				    (dat)->data[0] == 0x54))
#define krb5_is_krb_priv(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x75 ||\
				    (dat)->data[0] == 0x55))
#define krb5_is_krb_cred(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x76 ||\
				    (dat)->data[0] == 0x56))
#define krb5_is_krb_enc_as_rep_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x79 ||\
				    (dat)->data[0] == 0x59))
#define krb5_is_krb_enc_tgs_rep_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7a ||\
				    (dat)->data[0] == 0x5a))
#define krb5_is_krb_enc_ap_rep_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7b ||\
				    (dat)->data[0] == 0x5b))
#define krb5_is_krb_enc_krb_priv_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7c ||\
				    (dat)->data[0] == 0x5c))
#define krb5_is_krb_enc_krb_cred_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7d ||\
				    (dat)->data[0] == 0x5d))
#define krb5_is_krb_error(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x7e ||\
				    (dat)->data[0] == 0x5e))

/*************************************************************************
 * Prototypes for krb5_encode.c
 *************************************************************************/

/*
   krb5_error_code encode_krb5_structure(const krb5_structure *rep,
					 krb5_data **code);
   modifies  *code
   effects   Returns the ASN.1 encoding of *rep in **code.
             Returns ASN1_MISSING_FIELD if a required field is emtpy in *rep.
             Returns ENOMEM if memory runs out.
*/

krb5_error_code encode_krb5_authenticator
	KRB5_PROTOTYPE((const krb5_authenticator *rep, krb5_data **code));

krb5_error_code encode_krb5_ticket
	KRB5_PROTOTYPE((const krb5_ticket *rep, krb5_data **code));

krb5_error_code encode_krb5_encryption_key
	KRB5_PROTOTYPE((const krb5_keyblock *rep, krb5_data **code));

krb5_error_code encode_krb5_enc_tkt_part
	KRB5_PROTOTYPE((const krb5_enc_tkt_part *rep, krb5_data **code));

krb5_error_code encode_krb5_enc_kdc_rep_part
	KRB5_PROTOTYPE((const krb5_enc_kdc_rep_part *rep, krb5_data **code));

/* yes, the translation is identical to that used for KDC__REP */ 
krb5_error_code encode_krb5_as_rep
	KRB5_PROTOTYPE((const krb5_kdc_rep *rep, krb5_data **code));

/* yes, the translation is identical to that used for KDC__REP */ 
krb5_error_code encode_krb5_tgs_rep
	KRB5_PROTOTYPE((const krb5_kdc_rep *rep, krb5_data **code));

krb5_error_code encode_krb5_ap_req
	KRB5_PROTOTYPE((const krb5_ap_req *rep, krb5_data **code));

krb5_error_code encode_krb5_ap_rep
	KRB5_PROTOTYPE((const krb5_ap_rep *rep, krb5_data **code));

krb5_error_code encode_krb5_ap_rep_enc_part
	KRB5_PROTOTYPE((const krb5_ap_rep_enc_part *rep, krb5_data **code));

krb5_error_code encode_krb5_as_req
	KRB5_PROTOTYPE((const krb5_kdc_req *rep, krb5_data **code));

krb5_error_code encode_krb5_tgs_req
	KRB5_PROTOTYPE((const krb5_kdc_req *rep, krb5_data **code));

krb5_error_code encode_krb5_kdc_req_body
	KRB5_PROTOTYPE((const krb5_kdc_req *rep, krb5_data **code));

krb5_error_code encode_krb5_safe
	KRB5_PROTOTYPE((const krb5_safe *rep, krb5_data **code));

krb5_error_code encode_krb5_priv
	KRB5_PROTOTYPE((const krb5_priv *rep, krb5_data **code));

krb5_error_code encode_krb5_enc_priv_part
	KRB5_PROTOTYPE((const krb5_priv_enc_part *rep, krb5_data **code));

krb5_error_code encode_krb5_cred
	KRB5_PROTOTYPE((const krb5_cred *rep, krb5_data **code));

krb5_error_code encode_krb5_enc_cred_part
	KRB5_PROTOTYPE((const krb5_cred_enc_part *rep, krb5_data **code));

krb5_error_code encode_krb5_error
	KRB5_PROTOTYPE((const krb5_error *rep, krb5_data **code));

krb5_error_code encode_krb5_authdata
	KRB5_PROTOTYPE((const krb5_authdata **rep, krb5_data **code));

krb5_error_code encode_krb5_pwd_sequence
	KRB5_PROTOTYPE((const passwd_phrase_element *rep, krb5_data **code));

krb5_error_code encode_krb5_pwd_data
	KRB5_PROTOTYPE((const krb5_pwd_data *rep, krb5_data **code));

/*************************************************************************
 * End of prototypes for krb5_encode.c
 *************************************************************************/


/*************************************************************************
 * Prototypes for krb5_decode.c
 *************************************************************************/

/*
   krb5_error_code decode_krb5_structure(const krb5_data *code,
                                         krb5_structure **rep);
                                         
   requires  Expects **rep to not have been allocated;
              a new *rep is allocated regardless of the old value.
   effects   Decodes *code into **rep.
	     Returns ENOMEM if memory is exhausted.
             Returns asn1 and krb5 errors.
*/

krb5_error_code decode_krb5_authenticator
	KRB5_PROTOTYPE((const krb5_data *code, krb5_authenticator **rep));

krb5_error_code decode_krb5_ticket
	KRB5_PROTOTYPE((const krb5_data *code, krb5_ticket **rep));

krb5_error_code decode_krb5_encryption_key
	KRB5_PROTOTYPE((const krb5_data *output, krb5_keyblock **rep));

krb5_error_code decode_krb5_enc_tkt_part
	KRB5_PROTOTYPE((const krb5_data *output, krb5_enc_tkt_part **rep));

krb5_error_code decode_krb5_enc_kdc_rep_part
	KRB5_PROTOTYPE((const krb5_data *output, krb5_enc_kdc_rep_part **rep));

krb5_error_code decode_krb5_as_rep
	KRB5_PROTOTYPE((const krb5_data *output, krb5_kdc_rep **rep));

krb5_error_code decode_krb5_tgs_rep
	KRB5_PROTOTYPE((const krb5_data *output, krb5_kdc_rep **rep));

krb5_error_code decode_krb5_ap_req
	KRB5_PROTOTYPE((const krb5_data *output, krb5_ap_req **rep));

krb5_error_code decode_krb5_ap_rep
	KRB5_PROTOTYPE((const krb5_data *output, krb5_ap_rep **rep));

krb5_error_code decode_krb5_ap_rep_enc_part
	KRB5_PROTOTYPE((const krb5_data *output, krb5_ap_rep_enc_part **rep));

krb5_error_code decode_krb5_as_req
	KRB5_PROTOTYPE((const krb5_data *output, krb5_kdc_req **rep));

krb5_error_code decode_krb5_tgs_req
	KRB5_PROTOTYPE((const krb5_data *output, krb5_kdc_req **rep));

krb5_error_code decode_krb5_kdc_req_body
	KRB5_PROTOTYPE((const krb5_data *output, krb5_kdc_req **rep));

krb5_error_code decode_krb5_safe
	KRB5_PROTOTYPE((const krb5_data *output, krb5_safe **rep));

krb5_error_code decode_krb5_priv
	KRB5_PROTOTYPE((const krb5_data *output, krb5_priv **rep));

krb5_error_code decode_krb5_enc_priv_part
	KRB5_PROTOTYPE((const krb5_data *output, krb5_priv_enc_part **rep));

krb5_error_code decode_krb5_cred
	KRB5_PROTOTYPE((const krb5_data *output, krb5_cred **rep));

krb5_error_code decode_krb5_enc_cred_part
	KRB5_PROTOTYPE((const krb5_data *output, krb5_cred_enc_part **rep));

krb5_error_code decode_krb5_error
	KRB5_PROTOTYPE((const krb5_data *output, krb5_error **rep));

krb5_error_code decode_krb5_authdata
	KRB5_PROTOTYPE((const krb5_data *output, krb5_authdata ***rep));

krb5_error_code decode_krb5_pwd_sequence
	KRB5_PROTOTYPE((const krb5_data *output, passwd_phrase_element **rep));

krb5_error_code decode_krb5_pwd_data
	KRB5_PROTOTYPE((const krb5_data *output, krb5_pwd_data **rep));

/*************************************************************************
 * End of prototypes for krb5_decode.c
 *************************************************************************/

#endif /* KRB5_ASN1__ */
