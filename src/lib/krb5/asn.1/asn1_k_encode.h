/*
 * src/lib/krb5/asn.1/asn1_k_encode.h
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef __ASN1_ENCODE_KRB5_H__
#define __ASN1_ENCODE_KRB5_H__

#include "k5-int.h"
#include <stdio.h>
#include "asn1buf.h"

/*
   Overview

     Encoding routines for various ASN.1 "substructures" as defined in
     the krb5 protocol.

   Operations

    asn1_encode_krb5_flags
    asn1_encode_ap_options
    asn1_encode_ticket_flags
    asn1_encode_kdc_options
    asn1_encode_kerberos_time

    asn1_encode_realm
    asn1_encode_principal_name
    asn1_encode_encrypted_data
    asn1_encode_authorization_data
    asn1_encode_krb5_authdata_elt
    asn1_encode_kdc_rep
    asn1_encode_ticket
    asn1_encode_encryption_key
    asn1_encode_checksum
    asn1_encode_host_address
    asn1_encode_transited_encoding
    asn1_encode_enc_kdc_rep_part
    asn1_encode_kdc_req
    asn1_encode_kdc_req_body
    asn1_encode_krb_safe_body
    asn1_encode_krb_cred_info
    asn1_encode_last_req_entry
    asn1_encode_pa_data

    asn1_encode_host_addresses
    asn1_encode_last_req
    asn1_encode_sequence_of_pa_data
    asn1_encode_sequence_of_ticket
    asn1_encode_sequence_of_keytype
    asn1_encode_sequence_of_krb_cred_info
*/

/*
**** for simple val's ****
asn1_error_code asn1_encode_asn1_type(asn1buf *buf,
                                      const krb5_type val,
				      int *retlen);
   requires  *buf is allocated
   effects   Inserts the encoding of val into *buf and
              returns the length of this encoding in *retlen.
	     Returns ASN1_MISSING_FIELD if a required field is empty in val.
	     Returns ENOMEM if memory runs out.

**** for struct val's ****
asn1_error_code asn1_encode_asn1_type(asn1buf *buf,
                                      const krb5_type *val,
				      int *retlen);
   requires  *buf is allocated
   effects   Inserts the encoding of *val into *buf and
              returns the length of this encoding in *retlen.
	     Returns ASN1_MISSING_FIELD if a required field is empty in val.
	     Returns ENOMEM if memory runs out.

**** for array val's ****
asn1_error_code asn1_encode_asn1_type(asn1buf *buf,
                                      const krb5_type **val,
				      int *retlen);
   requires  *buf is allocated, **val != NULL, *val[0] != NULL,
              **val is a NULL-terminated array of pointers to krb5_type
   effects   Inserts the encoding of **val into *buf and
              returns the length of this encoding in *retlen.
	     Returns ASN1_MISSING_FIELD if a required field is empty in val.
	     Returns ENOMEM if memory runs out.
*/

asn1_error_code asn1_encode_ui_4 PROTOTYPE((asn1buf *buf,
					    const krb5_ui_4 val,
					    int *retlen));

asn1_error_code asn1_encode_msgtype PROTOTYPE((asn1buf *buf,
					       const /*krb5_msgtype*/int val,
					       int *retlen));

asn1_error_code asn1_encode_realm
	PROTOTYPE((asn1buf *buf, const krb5_principal val, int *retlen));

asn1_error_code asn1_encode_principal_name
	PROTOTYPE((asn1buf *buf, const krb5_principal val, int *retlen));

asn1_error_code asn1_encode_encrypted_data
	PROTOTYPE((asn1buf *buf, const krb5_enc_data *val, int *retlen));

asn1_error_code asn1_encode_krb5_flags
	PROTOTYPE((asn1buf *buf, const krb5_flags val, int *retlen));

asn1_error_code asn1_encode_ap_options
	PROTOTYPE((asn1buf *buf, const krb5_flags val, int *retlen));

asn1_error_code asn1_encode_ticket_flags
	PROTOTYPE((asn1buf *buf, const krb5_flags val, int *retlen));

asn1_error_code asn1_encode_kdc_options
	PROTOTYPE((asn1buf *buf, const krb5_flags val, int *retlen));

asn1_error_code asn1_encode_authorization_data
	PROTOTYPE((asn1buf *buf, const krb5_authdata **val, int *retlen));

asn1_error_code asn1_encode_krb5_authdata_elt
	PROTOTYPE((asn1buf *buf, const krb5_authdata *val, int *retlen));

asn1_error_code asn1_encode_kdc_rep
	PROTOTYPE((int msg_type, asn1buf *buf, const krb5_kdc_rep *val,
		   int *retlen));

asn1_error_code asn1_encode_enc_kdc_rep_part
	PROTOTYPE((asn1buf *buf, const krb5_enc_kdc_rep_part *val,
		   int *retlen));

asn1_error_code asn1_encode_ticket
	PROTOTYPE((asn1buf *buf, const krb5_ticket *val, int *retlen));

asn1_error_code asn1_encode_encryption_key
	PROTOTYPE((asn1buf *buf, const krb5_keyblock *val, int *retlen));

asn1_error_code asn1_encode_kerberos_time
	PROTOTYPE((asn1buf *buf, const krb5_timestamp val, int *retlen));

asn1_error_code asn1_encode_checksum
	PROTOTYPE((asn1buf *buf, const krb5_checksum *val, int *retlen));

asn1_error_code asn1_encode_host_address
	PROTOTYPE((asn1buf *buf, const krb5_address *val, int *retlen));

asn1_error_code asn1_encode_host_addresses
	PROTOTYPE((asn1buf *buf, const krb5_address **val, int *retlen));

asn1_error_code asn1_encode_transited_encoding
	PROTOTYPE((asn1buf *buf, const krb5_transited *val, int *retlen));

asn1_error_code asn1_encode_last_req
	PROTOTYPE((asn1buf *buf, const krb5_last_req_entry **val,
		   int *retlen));

asn1_error_code asn1_encode_sequence_of_pa_data
	PROTOTYPE((asn1buf *buf, const krb5_pa_data **val, int *retlen));

asn1_error_code asn1_encode_sequence_of_ticket
	PROTOTYPE((asn1buf *buf, const krb5_ticket **val, int *retlen));

asn1_error_code asn1_encode_sequence_of_keytype
	PROTOTYPE((asn1buf *buf,
		   const int len, const krb5_keytype *val,
		   int *retlen));

asn1_error_code asn1_encode_kdc_req
	PROTOTYPE((int msg_type,
		   asn1buf *buf,
		   const krb5_kdc_req *val,
		   int *retlen));

asn1_error_code asn1_encode_kdc_req_body
	PROTOTYPE((asn1buf *buf, const krb5_kdc_req *val, int *retlen));

asn1_error_code asn1_encode_krb_safe_body
	PROTOTYPE((asn1buf *buf, const krb5_safe *val, int *retlen));

asn1_error_code asn1_encode_sequence_of_krb_cred_info
	PROTOTYPE((asn1buf *buf, const krb5_cred_info **val, int *retlen));

asn1_error_code asn1_encode_krb_cred_info
	PROTOTYPE((asn1buf *buf, const krb5_cred_info *val, int *retlen));

asn1_error_code asn1_encode_last_req_entry
	PROTOTYPE((asn1buf *buf, const krb5_last_req_entry *val,
		   int *retlen));

asn1_error_code asn1_encode_pa_data
	PROTOTYPE((asn1buf *buf, const krb5_pa_data *val, int *retlen));

asn1_error_code asn1_encode_alt_method
	PROTOTYPE((asn1buf *buf, const krb5_alt_method *val,
		   int *retlen));

asn1_error_code asn1_encode_etype_info_entry
	PROTOTYPE((asn1buf *buf, const krb5_etype_info_entry *val,
		   int *retlen));

asn1_error_code asn1_encode_etype_info
	PROTOTYPE((asn1buf *buf, const krb5_etype_info_entry **val,
		   int *retlen));

asn1_error_code asn1_encode_passwdsequence
	PROTOTYPE((asn1buf *buf, const passwd_phrase_element *val, int *retlen));

asn1_error_code asn1_encode_sequence_of_passwdsequence
	PROTOTYPE((asn1buf *buf, const passwd_phrase_element **val, int *retlen));

#endif
