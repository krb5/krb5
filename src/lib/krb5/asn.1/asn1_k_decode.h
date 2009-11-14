/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * src/lib/krb5/asn.1/asn1_k_decode.h
 *
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef __ASN1_DECODE_KRB5_H__
#define __ASN1_DECODE_KRB5_H__

#include "k5-int.h"
#include "krbasn1.h"
#include "asn1buf.h"

/* asn1_error_code asn1_decode_scalar_type(asn1buf *buf, krb5_scalar *val); */
/*
 * requires  *buf is allocated, *buf's current position points to the
 *            beginning of an encoding (<id> <len> <contents>),
 *            *val is allocated
 *
 * effects   Decodes the encoding in *buf, returning the result in *val.
 *
 *           Returns ASN1_BAD_ID if the encoded id does not indicate
 *           the proper type.
 *
 *           Returns ASN1_OVERRUN if the encoded length exceeds
 *           the bounds of *buf
 */


/*
 * asn1_error_code asn1_decode_structure_type(asn1buf *buf,
 *                                            krb5_structure *val);
 */
/*
 * requires  *buf is allocated, *buf's current position points to the
 *            beginning of an encoding (<id> <len> <contents>),
 *            *val is allocated
 *
 *           Assumes that *val is a freshly-allocated structure (i.e.
 *            does not attempt to clean up or free *val).
 * effects   Decodes the encoding in *buf, returning the result in *val.
 *
 *           Returns ASN1_BAD_ID if the encoded id does not indicate
 *           the proper type.
 *
 *           Returns ASN1_OVERRUN if the encoded length exceeds the
 *           bounds of *buf
 */

/* asn1_error_code asn1_decode_array_type(asn1buf *buf, krb5_scalar ***val); */
/*
 * requires  *buf is allocated, *buf's current position points to the
 *           beginning of an encoding (<id> <len> <contents>)
 *
 *           Assumes that *val is empty (i.e. does not attempt to
 *           clean up or free *val).
 *
 * effects   Decodes the encoding in *buf, returning the result in *val.
 *
 *           Returns ASN1_BAD_ID if the encoded id does not indicate
 *           the proper type.
 *
 *           Returns ASN1_OVERRUN if the encoded length exceeds the
 *           bounds of *buf
 */

/* scalars */
asn1_error_code asn1_decode_int(asn1buf *buf, int *val);
asn1_error_code asn1_decode_int32(asn1buf *buf, krb5_int32 *val);
asn1_error_code asn1_decode_kvno(asn1buf *buf, krb5_kvno *val);
asn1_error_code asn1_decode_enctype(asn1buf *buf, krb5_enctype *val);
asn1_error_code asn1_decode_msgtype(asn1buf *buf, krb5_msgtype *val);
asn1_error_code asn1_decode_cksumtype(asn1buf *buf, krb5_cksumtype *val);
asn1_error_code asn1_decode_octet(asn1buf *buf, krb5_octet *val);
asn1_error_code asn1_decode_addrtype(asn1buf *buf, krb5_addrtype *val);
asn1_error_code asn1_decode_authdatatype(asn1buf *buf, krb5_authdatatype *val);
asn1_error_code asn1_decode_ui_2(asn1buf *buf, krb5_ui_2 *val);
asn1_error_code asn1_decode_ui_4(asn1buf *buf, krb5_ui_4 *val);
asn1_error_code asn1_decode_seqnum(asn1buf *buf, krb5_ui_4 *val);
asn1_error_code asn1_decode_kerberos_time(asn1buf *buf, krb5_timestamp *val);
asn1_error_code asn1_decode_sam_flags(asn1buf *buf, krb5_flags *val);

/* structures */
asn1_error_code asn1_decode_realm(asn1buf *buf, krb5_principal *val);
asn1_error_code asn1_decode_principal_name(asn1buf *buf, krb5_principal *val);
asn1_error_code asn1_decode_checksum(asn1buf *buf, krb5_checksum *val);
asn1_error_code asn1_decode_checksum_ptr(asn1buf *buf, krb5_checksum **valptr);
asn1_error_code asn1_decode_encryption_key(asn1buf *buf, krb5_keyblock *val);
asn1_error_code asn1_decode_encryption_key_ptr(asn1buf *buf,
                                               krb5_keyblock **valptr);
asn1_error_code asn1_decode_encrypted_data(asn1buf *buf, krb5_enc_data *val);
asn1_error_code asn1_decode_ticket_flags(asn1buf *buf, krb5_flags *val);
asn1_error_code asn1_decode_transited_encoding(asn1buf *buf,
                                               krb5_transited *val);
asn1_error_code asn1_decode_enc_kdc_rep_part(asn1buf *buf,
                                             krb5_enc_kdc_rep_part *val);
asn1_error_code asn1_decode_krb5_flags(asn1buf *buf, krb5_flags *val);
asn1_error_code asn1_decode_ap_options(asn1buf *buf, krb5_flags *val);
asn1_error_code asn1_decode_kdc_options(asn1buf *buf, krb5_flags *val);
asn1_error_code asn1_decode_ticket(asn1buf *buf, krb5_ticket *val);
asn1_error_code asn1_decode_ticket_ptr(asn1buf *buf, krb5_ticket **valptr);
asn1_error_code asn1_decode_kdc_req(asn1buf *buf, krb5_kdc_req *val);
asn1_error_code asn1_decode_kdc_req_body(asn1buf *buf, krb5_kdc_req *val);
asn1_error_code asn1_decode_krb_safe_body(asn1buf *buf, krb5_safe *val);
asn1_error_code asn1_decode_host_address(asn1buf *buf, krb5_address *val);
asn1_error_code asn1_decode_host_address_ptr(asn1buf *buf,
                                             krb5_address **valptr);
asn1_error_code asn1_decode_kdc_rep(asn1buf *buf, krb5_kdc_rep *val);
asn1_error_code asn1_decode_last_req_entry(asn1buf *buf,
                                           krb5_last_req_entry *val);
asn1_error_code asn1_decode_last_req_entry_ptr(asn1buf *buf,
                                               krb5_last_req_entry **valptr);
asn1_error_code asn1_decode_authdata_elt(asn1buf *buf, krb5_authdata *val);
asn1_error_code asn1_decode_authdata_elt_ptr(asn1buf *buf,
                                             krb5_authdata **valptr);
asn1_error_code asn1_peek_authorization_data(asn1buf *buf,
                                             unsigned int *num,
                                             krb5_authdatatype **val);
asn1_error_code asn1_decode_krb_cred_info(asn1buf *buf, krb5_cred_info *val);
asn1_error_code asn1_decode_krb_cred_info_ptr(asn1buf *buf,
                                              krb5_cred_info **valptr);
asn1_error_code asn1_decode_pa_data(asn1buf *buf, krb5_pa_data *val);
asn1_error_code asn1_decode_pa_data_ptr(asn1buf *buf, krb5_pa_data **valptr);
asn1_error_code asn1_decode_passwdsequence(asn1buf *buf,
                                           passwd_phrase_element *val);
asn1_error_code asn1_decode_passwdsequence_ptr(asn1buf *buf,
                                               passwd_phrase_element **valptr);
asn1_error_code asn1_decode_sam_challenge(asn1buf *buf,
                                          krb5_sam_challenge *val);
asn1_error_code asn1_decode_sam_challenge_2(asn1buf *buf,
                                            krb5_sam_challenge_2 *val);
asn1_error_code
asn1_decode_sam_challenge_2_body(asn1buf *buf,
                                 krb5_sam_challenge_2_body *val);
asn1_error_code asn1_decode_enc_sam_key(asn1buf *buf, krb5_sam_key *val);
asn1_error_code
asn1_decode_enc_sam_response_enc(asn1buf *buf,
                                 krb5_enc_sam_response_enc *val);
asn1_error_code
asn1_decode_enc_sam_response_enc_2(asn1buf *buf,
                                   krb5_enc_sam_response_enc_2 *val);
asn1_error_code asn1_decode_sam_response(asn1buf *buf, krb5_sam_response *val);
asn1_error_code asn1_decode_sam_response_2(asn1buf *buf,
                                           krb5_sam_response_2 *val);
asn1_error_code
asn1_decode_predicted_sam_response(asn1buf *buf,
                                   krb5_predicted_sam_response *val);
asn1_error_code asn1_decode_external_principal_identifier(
    asn1buf *buf, krb5_external_principal_identifier *val);
asn1_error_code asn1_decode_external_principal_identifier_ptr(
    asn1buf *buf, krb5_external_principal_identifier **valptr);
asn1_error_code asn1_decode_pa_pk_as_req(asn1buf *buf, krb5_pa_pk_as_req *val);
asn1_error_code asn1_decode_trusted_ca(asn1buf *buf, krb5_trusted_ca *val);
asn1_error_code asn1_decode_trusted_ca_ptr(asn1buf *buf,
                                           krb5_trusted_ca **valptr);
asn1_error_code asn1_decode_pa_pk_as_req_draft9(asn1buf *buf,
                                                krb5_pa_pk_as_req_draft9 *val);
asn1_error_code asn1_decode_dh_rep_info(asn1buf *buf, krb5_dh_rep_info *val);
asn1_error_code asn1_decode_pk_authenticator(asn1buf *buf,
                                             krb5_pk_authenticator *val);
asn1_error_code
asn1_decode_pk_authenticator_draft9(asn1buf *buf,
                                    krb5_pk_authenticator_draft9 *val);
asn1_error_code asn1_decode_subject_pk_info(asn1buf *buf,
                                            krb5_subject_pk_info *val);
asn1_error_code
asn1_decode_algorithm_identifier(asn1buf *buf, krb5_algorithm_identifier *val);
asn1_error_code
asn1_decode_algorithm_identifier_ptr(asn1buf *buf,
                                     krb5_algorithm_identifier **valptr);
asn1_error_code asn1_decode_auth_pack(asn1buf *buf, krb5_auth_pack *val);
asn1_error_code asn1_decode_auth_pack_draft9(asn1buf *buf,
                                             krb5_auth_pack_draft9 *val);
asn1_error_code asn1_decode_pa_pk_as_rep(asn1buf *buf,
                                         krb5_pa_pk_as_rep *val);
asn1_error_code asn1_decode_pa_pk_as_rep_draft9(asn1buf *buf,
                                                krb5_pa_pk_as_rep_draft9 *val);
asn1_error_code asn1_decode_kdc_dh_key_info(asn1buf *buf,
                                            krb5_kdc_dh_key_info *val);
asn1_error_code asn1_decode_krb5_principal_name(asn1buf *buf,
                                                krb5_principal *val);
asn1_error_code asn1_decode_reply_key_pack(asn1buf *buf,
                                           krb5_reply_key_pack *val);
asn1_error_code
asn1_decode_reply_key_pack_draft9(asn1buf *buf,
                                  krb5_reply_key_pack_draft9 *val);
asn1_error_code
asn1_decode_sequence_of_typed_data(asn1buf *buf, krb5_typed_data ***val);
asn1_error_code asn1_decode_typed_data(asn1buf *buf, krb5_typed_data *val);
asn1_error_code asn1_decode_typed_data_ptr(asn1buf *buf,
                                           krb5_typed_data **valptr);

/* arrays */
asn1_error_code asn1_decode_authorization_data(asn1buf *buf,
                                               krb5_authdata ***val);
asn1_error_code asn1_decode_host_addresses(asn1buf *buf, krb5_address ***val);
asn1_error_code asn1_decode_sequence_of_ticket(asn1buf *buf,
                                               krb5_ticket ***val);
asn1_error_code asn1_decode_sequence_of_krb_cred_info(asn1buf *buf,
                                                      krb5_cred_info ***val);
asn1_error_code asn1_decode_sequence_of_pa_data(asn1buf *buf,
                                                krb5_pa_data ***val);
asn1_error_code asn1_decode_last_req(asn1buf *buf, krb5_last_req_entry ***val);

asn1_error_code asn1_decode_sequence_of_enctype(asn1buf *buf, int *num,
                                                krb5_enctype **val);

asn1_error_code asn1_decode_sequence_of_checksum(asn1buf *buf,
                                                 krb5_checksum ***val);

asn1_error_code asn1_decode_sequence_of_passwdsequence(asn1buf *buf,
                                                       passwd_phrase_element ***val);

asn1_error_code asn1_decode_etype_info(asn1buf *buf,
                                       krb5_etype_info_entry ***val);
asn1_error_code asn1_decode_etype_info2(asn1buf *buf,
                                        krb5_etype_info_entry ***val,
                                        krb5_boolean v1_3_behavior);
asn1_error_code asn1_decode_sequence_of_external_principal_identifier(
    asn1buf *buf, krb5_external_principal_identifier ***val);
asn1_error_code asn1_decode_sequence_of_trusted_ca(asn1buf *buf,
                                                   krb5_trusted_ca ***val);
asn1_error_code asn1_decode_sequence_of_algorithm_identifier(
    asn1buf *buf, krb5_algorithm_identifier ***val);

asn1_error_code asn1_decode_setpw_req(asn1buf *buf, krb5_data *rep,
                                      krb5_principal *principal);
asn1_error_code asn1_decode_pa_for_user(asn1buf *buf, krb5_pa_for_user *val);
asn1_error_code asn1_decode_s4u_userid(asn1buf *buf, krb5_s4u_userid *val);
asn1_error_code asn1_decode_pa_s4u_x509_user(asn1buf *buf,
                                             krb5_pa_s4u_x509_user *val);
asn1_error_code asn1_decode_pa_pac_req(asn1buf *buf, krb5_pa_pac_req *val);

asn1_error_code asn1_decode_fast_armor(asn1buf *buf, krb5_fast_armor *val);

asn1_error_code asn1_decode_fast_armor_ptr(asn1buf *buf,
                                           krb5_fast_armor **val);

asn1_error_code asn1_decode_fast_finished(asn1buf *buf,
                                          krb5_fast_finished *val);

asn1_error_code asn1_decode_fast_finished_ptr(asn1buf *buf,
                                              krb5_fast_finished **val);

asn1_error_code asn1_decode_ad_kdcissued(asn1buf *buf, krb5_ad_kdcissued *val);

asn1_error_code asn1_decode_ad_kdcissued_ptr(asn1buf *buf,
                                             krb5_ad_kdcissued **val);

asn1_error_code asn1_decode_ad_signedpath(asn1buf *buf,
                                          krb5_ad_signedpath *val);

#endif
