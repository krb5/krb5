#ifndef __ASN1_DECODE_KRB5_H__
#define __ASN1_DECODE_KRB5_H__

#include <krb5/krb5.h>
#include "krbasn1.h"
#include "asn1buf.h"

/* asn1_error_code asn1_decode_scalar_type(asn1buf *buf, krb5_scalar *val); */
/* requires  *buf is allocated, *buf's current position points to the
              beginning of an encoding (<id> <len> <contents>),
	      *val is allocated
   effects   Decodes the encoding in *buf, returning the result in *val.
             Returns ASN1_BAD_ID if the encoded id does not
	      indicate the proper type.
             Returns ASN1_OVERRUN if the encoded length exceeds
	      the bounds of *buf */


/* asn1_error_code asn1_decode_structure_type(asn1buf *buf,
                                              krb5_structure *val); */
/* requires  *buf is allocated, *buf's current position points to the
              beginning of an encoding (<id> <len> <contents>),
	      *val is allocated
	     Assumes that *val is a freshly-allocated structure (i.e.
	      does not attempt to clean up or free *val).
   effects   Decodes the encoding in *buf, returning the result in *val.
             Returns ASN1_BAD_ID if the encoded id does not
	      indicate the proper type.
             Returns ASN1_OVERRUN if the encoded length exceeds
	      the bounds of *buf */

/* asn1_error_code asn1_decode_array_type(asn1buf *buf, krb5_scalar ***val); */
/* requires  *buf is allocated, *buf's current position points to the
              beginning of an encoding (<id> <len> <contents>)
	     Assumes that *val is empty (i.e. does not attempt to
	      clean up or free *val).
   effects   Decodes the encoding in *buf, returning the result in *val.
             Returns ASN1_BAD_ID if the encoded id does not
	      indicate the proper type.
             Returns ASN1_OVERRUN if the encoded length exceeds
	      the bounds of *buf */

/* scalars */
asn1_error_code asn1_decode_int
	PROTOTYPE((asn1buf *buf, int *val));
asn1_error_code asn1_decode_int32
	PROTOTYPE((asn1buf *buf, krb5_int32 *val));
asn1_error_code asn1_decode_kvno
	PROTOTYPE((asn1buf *buf, krb5_kvno *val));
asn1_error_code asn1_decode_keytype
	PROTOTYPE((asn1buf *buf, krb5_keytype *val));
asn1_error_code asn1_decode_msgtype
	PROTOTYPE((asn1buf *buf, krb5_msgtype *val));
asn1_error_code asn1_decode_cksumtype
	PROTOTYPE((asn1buf *buf, krb5_cksumtype *val));
asn1_error_code asn1_decode_enctype
	PROTOTYPE((asn1buf *buf, krb5_enctype *val));
asn1_error_code asn1_decode_kvno
	PROTOTYPE((asn1buf *buf, krb5_kvno *val));
asn1_error_code asn1_decode_octet
	PROTOTYPE((asn1buf *buf, krb5_octet *val));
asn1_error_code asn1_decode_addrtype
	PROTOTYPE((asn1buf *buf, krb5_addrtype *val));
asn1_error_code asn1_decode_authdatatype
	PROTOTYPE((asn1buf *buf, krb5_authdatatype *val));
asn1_error_code asn1_decode_ui_2
	PROTOTYPE((asn1buf *buf, krb5_ui_2 *val));
asn1_error_code asn1_decode_ui_4
	PROTOTYPE((asn1buf *buf, krb5_ui_4 *val));
asn1_error_code asn1_decode_kerberos_time
	PROTOTYPE((asn1buf *buf, krb5_timestamp *val));

/* structures */
asn1_error_code asn1_decode_realm
	PROTOTYPE((asn1buf *buf, krb5_principal *val));
asn1_error_code asn1_decode_principal_name
	PROTOTYPE((asn1buf *buf, krb5_principal *val));
asn1_error_code asn1_decode_checksum
	PROTOTYPE((asn1buf *buf, krb5_checksum *val));
asn1_error_code asn1_decode_encryption_key
	PROTOTYPE((asn1buf *buf, krb5_keyblock *val));
asn1_error_code asn1_decode_encrypted_data
	PROTOTYPE((asn1buf *buf, krb5_enc_data *val));
asn1_error_code asn1_decode_ticket_flags
	PROTOTYPE((asn1buf *buf, krb5_flags *val));
asn1_error_code asn1_decode_transited_encoding
	PROTOTYPE((asn1buf *buf, krb5_transited *val));
asn1_error_code asn1_decode_enc_kdc_rep_part
	PROTOTYPE((asn1buf *buf, krb5_enc_kdc_rep_part *val));
asn1_error_code asn1_decode_krb5_flags
	PROTOTYPE((asn1buf *buf, krb5_flags *val));
asn1_error_code asn1_decode_ap_options
	PROTOTYPE((asn1buf *buf, krb5_flags *val));
asn1_error_code asn1_decode_kdc_options
	PROTOTYPE((asn1buf *buf, krb5_flags *val));
asn1_error_code asn1_decode_ticket
	PROTOTYPE((asn1buf *buf, krb5_ticket *val));
asn1_error_code asn1_decode_kdc_req
	PROTOTYPE((asn1buf *buf, krb5_kdc_req *val));
asn1_error_code asn1_decode_kdc_req_body
	PROTOTYPE((asn1buf *buf, krb5_kdc_req *val));
asn1_error_code asn1_decode_krb_safe_body
	PROTOTYPE((asn1buf *buf, krb5_safe *val));
asn1_error_code asn1_decode_host_address
	PROTOTYPE((asn1buf *buf, krb5_address *val));
asn1_error_code asn1_decode_kdc_rep
	PROTOTYPE((asn1buf *buf, krb5_kdc_rep *val));
asn1_error_code asn1_decode_krb_safe_body
	PROTOTYPE((asn1buf *buf, krb5_safe *val));
asn1_error_code asn1_decode_last_req_entry
	PROTOTYPE((asn1buf *buf, krb5_last_req_entry *val));
asn1_error_code asn1_decode_authdata_elt
	PROTOTYPE((asn1buf *buf, krb5_authdata *val));
asn1_error_code asn1_decode_krb_cred_info
	PROTOTYPE((asn1buf *buf, krb5_cred_info *val));
asn1_error_code asn1_decode_pa_data
	PROTOTYPE((asn1buf *buf, krb5_pa_data *val));

/* arrays */
asn1_error_code asn1_decode_authorization_data
	PROTOTYPE((asn1buf *buf, krb5_authdata ***val));
asn1_error_code asn1_decode_host_addresses
	PROTOTYPE((asn1buf *buf, krb5_address ***val));
asn1_error_code asn1_decode_sequence_of_ticket
	PROTOTYPE((asn1buf *buf, krb5_ticket ***val));
asn1_error_code asn1_decode_sequence_of_krb_cred_info
	PROTOTYPE((asn1buf *buf, krb5_cred_info ***val));
asn1_error_code asn1_decode_sequence_of_pa_data
	PROTOTYPE((asn1buf *buf, krb5_pa_data ***val));
asn1_error_code asn1_decode_last_req
	PROTOTYPE((asn1buf *buf, krb5_last_req_entry ***val));

asn1_error_code asn1_decode_sequence_of_enctype
	PROTOTYPE((asn1buf *buf, int *num, krb5_enctype **val));

#endif
