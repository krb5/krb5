/*
 * src/lib/krb5/asn.1/krb5_decode.h
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

#ifndef __KRB5_DECODE_H__
#define __KRB5_DECODE_H__

#include <krb5/krb5.h>

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
	PROTOTYPE((const krb5_data *code, krb5_authenticator **rep));

krb5_error_code decode_krb5_ticket
	PROTOTYPE((const krb5_data *code, krb5_ticket **rep));

krb5_error_code decode_krb5_encryption_key
	PROTOTYPE((const krb5_data *output, krb5_keyblock **rep));

krb5_error_code decode_krb5_enc_tkt_part
	PROTOTYPE((const krb5_data *output, krb5_enc_tkt_part **rep));

krb5_error_code decode_krb5_enc_kdc_rep_part
	PROTOTYPE((const krb5_data *output, krb5_enc_kdc_rep_part **rep));

krb5_error_code decode_krb5_as_rep
	PROTOTYPE((const krb5_data *output, krb5_kdc_rep **rep));

krb5_error_code decode_krb5_tgs_rep
	PROTOTYPE((const krb5_data *output, krb5_kdc_rep **rep));

krb5_error_code decode_krb5_ap_req
	PROTOTYPE((const krb5_data *output, krb5_ap_req **rep));

krb5_error_code decode_krb5_ap_rep
	PROTOTYPE((const krb5_data *output, krb5_ap_rep **rep));

krb5_error_code decode_krb5_ap_rep_enc_part
	PROTOTYPE((const krb5_data *output, krb5_ap_rep_enc_part **rep));

krb5_error_code decode_krb5_as_req
	PROTOTYPE((const krb5_data *output, krb5_kdc_req **rep));

krb5_error_code decode_krb5_tgs_req
	PROTOTYPE((const krb5_data *output, krb5_kdc_req **rep));

krb5_error_code decode_krb5_kdc_req_body
	PROTOTYPE((const krb5_data *output, krb5_kdc_req **rep));

krb5_error_code decode_krb5_safe
	PROTOTYPE((const krb5_data *output, krb5_safe **rep));

krb5_error_code decode_krb5_priv
	PROTOTYPE((const krb5_data *output, krb5_priv **rep));

krb5_error_code decode_krb5_enc_priv_part
	PROTOTYPE((const krb5_data *output, krb5_priv_enc_part **rep));

krb5_error_code decode_krb5_cred
	PROTOTYPE((const krb5_data *output, krb5_cred **rep));

krb5_error_code decode_krb5_enc_cred_part
	PROTOTYPE((const krb5_data *output, krb5_cred_enc_part **rep));

krb5_error_code decode_krb5_error
	PROTOTYPE((const krb5_data *output, krb5_error **rep));

krb5_error_code decode_krb5_authdata
	PROTOTYPE((const krb5_data *output, krb5_authdata ***rep));

krb5_error_code decode_krb5_pwd_sequence
	PROTOTYPE((const krb5_data *output, passwd_phrase_element **rep));

krb5_error_code decode_krb5_pwd_data
	PROTOTYPE((const krb5_data *output, krb5_pwd_data **rep));

#endif
