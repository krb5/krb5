/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Function prototypes for Kerberos V5 library.
 */

#ifndef KRB5_FUNC_PROTO__
#define KRB5_FUNC_PROTO__


/* libkrb.spec */
krb5_error_code krb5_kdc_rep_decrypt_proc
	PROTOTYPE((const krb5_keyblock *,
		   krb5_const_pointer,
		   krb5_kdc_rep * ));
krb5_error_code krb5_encode_ticket
	PROTOTYPE((const krb5_ticket *,
		   krb5_data ** ));
krb5_error_code krb5_encrypt_tkt_part
	PROTOTYPE((const krb5_keyblock *,
		   krb5_ticket * ));
krb5_error_code krb5_decrypt_tkt_part
	PROTOTYPE((const krb5_keyblock *,
		   krb5_ticket * ));
krb5_error_code krb5_get_cred_from_kdc
	PROTOTYPE((krb5_ccache,		/* not const, as reading may save
					   state */
		   krb5_creds *,
		   krb5_creds *** ));
void krb5_free_tgt_creds
	PROTOTYPE((krb5_creds ** ));	/* XXX too hard to do with const */
krb5_error_code krb5_get_credentials
	PROTOTYPE((const krb5_flags,
		   krb5_ccache,
		   krb5_creds * ));
krb5_error_code krb5_mk_req
	PROTOTYPE((krb5_const_principal,
		   const krb5_flags,
		   const krb5_checksum *,
		   krb5_ccache,
		   krb5_data * ));
krb5_error_code krb5_mk_req_extended
	PROTOTYPE((const krb5_flags,
		   const krb5_checksum *,
		   const krb5_ticket_times *,
		   const krb5_flags,
		   krb5_int32,
		   krb5_keyblock **,
		   krb5_ccache,
		   krb5_creds *,
		   krb5_authenticator *,
		   krb5_data * ));
krb5_error_code krb5_rd_req_simple
	PROTOTYPE((const krb5_data *,
		   krb5_const_principal,
		   const krb5_address *,
		   krb5_tkt_authent ** ));
krb5_error_code krb5_mk_rep
	PROTOTYPE((const krb5_ap_rep_enc_part *,
		   const krb5_keyblock *,
		   krb5_data *));
krb5_error_code krb5_rd_rep
	PROTOTYPE((const krb5_data *,
		   const krb5_keyblock *,
		   krb5_ap_rep_enc_part **));
krb5_error_code krb5_mk_error
	PROTOTYPE((const krb5_error *,
		   krb5_data * ));
krb5_error_code krb5_rd_error
	PROTOTYPE((const krb5_data *,
		   krb5_error ** ));
krb5_error_code krb5_rd_safe
	PROTOTYPE((const krb5_data *,
		   const krb5_keyblock *,
		   const krb5_address *,
		   const krb5_address *,
		   krb5_int32, krb5_int32,
		   krb5_rcache,
		   krb5_data * ));
krb5_error_code krb5_rd_priv
	PROTOTYPE((const krb5_data *,
		   const krb5_keyblock *,
		   const krb5_address *,
		   const krb5_address *,
		   krb5_int32, krb5_int32,
		   krb5_pointer,
		   krb5_rcache,
		   krb5_data * ));
krb5_error_code krb5_parse_name
	PROTOTYPE((const char *,
		   krb5_principal * ));
krb5_error_code krb5_unparse_name
	PROTOTYPE((krb5_const_principal,
		   char ** ));
krb5_error_code krb5_unparse_name_ext
	PROTOTYPE((krb5_const_principal,
		   char **,
		   int *));
krb5_boolean krb5_address_search
	PROTOTYPE((const krb5_address *,
		   krb5_address * const *));
krb5_boolean krb5_address_compare
	PROTOTYPE((const krb5_address *,
		   const krb5_address *));
int krb5_address_order
	PROTOTYPE((const krb5_address *,
		   const krb5_address *));
krb5_boolean krb5_principal_compare
	PROTOTYPE((krb5_const_principal,
		   krb5_const_principal));
int krb5_fulladdr_order
	PROTOTYPE((const krb5_fulladdr *,
		   const krb5_fulladdr *));
krb5_error_code krb5_copy_keyblock
    PROTOTYPE((const krb5_keyblock *,
	       krb5_keyblock **));
krb5_error_code krb5_copy_keyblock_contents
    PROTOTYPE((const krb5_keyblock *,
	       krb5_keyblock *));
krb5_error_code krb5_copy_creds
    PROTOTYPE((const krb5_creds *,
	       krb5_creds **));
krb5_error_code krb5_copy_data
    PROTOTYPE((const krb5_data *,
	       krb5_data **));
krb5_error_code krb5_copy_principal
    PROTOTYPE((krb5_const_principal,
	       krb5_principal *));
krb5_error_code krb5_copy_addresses
    PROTOTYPE((krb5_address * const *,
	       krb5_address ***));
krb5_error_code krb5_copy_ticket
    PROTOTYPE((const krb5_ticket *, krb5_ticket **));
krb5_error_code krb5_copy_authdata
    PROTOTYPE((krb5_authdata * const *,
	       krb5_authdata ***));
krb5_error_code krb5_copy_authenticator
    PROTOTYPE((const krb5_authenticator *,
	       krb5_authenticator **));
krb5_error_code krb5_copy_checksum
    PROTOTYPE((const krb5_checksum *,
	       krb5_checksum **));
void krb5_init_ets PROTOTYPE((void));
krb5_error_code krb5_generate_subkey
    PROTOTYPE((const krb5_keyblock *, krb5_keyblock **));
krb5_error_code krb5_generate_seq_number
    PROTOTYPE((const krb5_keyblock *, krb5_int32 *));

/* libkt.spec */
krb5_error_code krb5_kt_register
	PROTOTYPE((krb5_kt_ops * ));
krb5_error_code krb5_kt_resolve
	PROTOTYPE((const char *,
		   krb5_keytab * ));
krb5_error_code krb5_kt_default_name
	PROTOTYPE((char *,
		   int ));
krb5_error_code krb5_kt_default
	PROTOTYPE((krb5_keytab * ));
krb5_error_code krb5_kt_free_entry
	PROTOTYPE((krb5_keytab_entry * ));
/* remove and add are functions, so that they can return NOWRITE
   if not a writable keytab */
krb5_error_code krb5_kt_remove_entry
	PROTOTYPE((krb5_keytab,
		   krb5_keytab_entry * ));
krb5_error_code krb5_kt_add_entry
	PROTOTYPE((krb5_keytab,
		   krb5_keytab_entry * ));
krb5_error_code krb5_principal2salt
	PROTOTYPE((krb5_const_principal, krb5_data *));

/* librc.spec--see rcache.h */

/* libcc.spec */
krb5_error_code krb5_cc_resolve
	PROTOTYPE((char *,
		   krb5_ccache * ));
krb5_error_code krb5_cc_generate_new
	PROTOTYPE((krb5_cc_ops *,
		   krb5_ccache * ));
char *krb5_cc_default_name
	PROTOTYPE((void ));
krb5_error_code krb5_cc_default
	PROTOTYPE((krb5_ccache *));


/* krb5_free.c */
void krb5_free_principal
	PROTOTYPE((krb5_principal ));
void krb5_free_authenticator
	PROTOTYPE((krb5_authenticator * ));
void krb5_free_address
	PROTOTYPE((krb5_address ** ));
void krb5_free_addr
	PROTOTYPE((krb5_address * ));
void krb5_free_authdata
	PROTOTYPE((krb5_authdata ** ));
void krb5_free_enc_tkt_part
	PROTOTYPE((krb5_enc_tkt_part * ));
void krb5_free_ticket
	PROTOTYPE((krb5_ticket * ));
void krb5_free_tickets
	PROTOTYPE((krb5_ticket ** ));
void krb5_free_kdc_req
	PROTOTYPE((krb5_kdc_req * ));
void krb5_free_kdc_rep
	PROTOTYPE((krb5_kdc_rep * ));
void krb5_free_last_req
	PROTOTYPE((krb5_last_req_entry ** ));
void krb5_free_enc_kdc_rep_part
	PROTOTYPE((krb5_enc_kdc_rep_part * ));
void krb5_free_error
	PROTOTYPE((krb5_error * ));
void krb5_free_ap_req
	PROTOTYPE((krb5_ap_req * ));
void krb5_free_ap_rep
	PROTOTYPE((krb5_ap_rep * ));
void krb5_free_safe
	PROTOTYPE((krb5_safe * ));
void krb5_free_priv
	PROTOTYPE((krb5_priv * ));
void krb5_free_priv_enc_part
	PROTOTYPE((krb5_priv_enc_part * ));
void krb5_free_kdc_req
	PROTOTYPE((krb5_kdc_req * ));
void krb5_free_creds
	PROTOTYPE((krb5_creds *));
void krb5_free_cred_contents
	PROTOTYPE((krb5_creds *));
void krb5_free_checksum
	PROTOTYPE((krb5_checksum *));
void krb5_free_keyblock
	PROTOTYPE((krb5_keyblock *));
void krb5_free_pa_data
	PROTOTYPE((krb5_pa_data **));
void krb5_free_ap_rep_enc_part
	PROTOTYPE((krb5_ap_rep_enc_part *));
void krb5_free_tkt_authent
	PROTOTYPE((krb5_tkt_authent *));

#include <krb5/widen.h>

/* Only put things which don't have pointers to the narrow types in this
   section */

krb5_error_code krb5_encode_kdc_rep
	PROTOTYPE((const krb5_msgtype,
		   const krb5_enc_kdc_rep_part *,
		   const krb5_keyblock *,
		   krb5_kdc_rep *,
		   krb5_data ** ));

krb5_error_code krb5_send_tgs
	PROTOTYPE((const krb5_flags,
		   const krb5_ticket_times *,
		   const krb5_enctype,
		   const krb5_cksumtype,
		   krb5_const_principal,
		   krb5_address * const *,
		   krb5_authdata * const *,
		   krb5_pa_data * const *,
		   const krb5_data *,
		   krb5_creds *,
		   krb5_response * ));

krb5_error_code krb5_get_in_tkt
	PROTOTYPE((const krb5_flags,
		   krb5_address * const *,
		   const krb5_enctype,
		   const krb5_keytype,
		   krb5_error_code (* )(const krb5_keytype,
                                        krb5_keyblock **,
                                        krb5_const_pointer,
                                        krb5_pa_data **),
		   krb5_const_pointer,
		   krb5_error_code (* )(const krb5_keyblock *,
					krb5_const_pointer,
					krb5_kdc_rep * ),
		   krb5_const_pointer,
		   krb5_creds *,
		   krb5_ccache ));
krb5_error_code krb5_get_in_tkt_with_password
	PROTOTYPE((const krb5_flags,
		   krb5_address * const *,
		   const krb5_enctype,
		   const krb5_keytype,
		   const char *,
		   krb5_ccache,
		   krb5_creds * ));
krb5_error_code krb5_get_in_tkt_with_skey
	PROTOTYPE((const krb5_flags,
		   krb5_address * const *,
		   const krb5_enctype,
		   const krb5_keyblock *,
		   krb5_ccache,
		   krb5_creds * ));

krb5_error_code krb5_decode_kdc_rep
	PROTOTYPE((krb5_data *,
		   const krb5_keyblock *,
		   const krb5_enctype,
		   krb5_kdc_rep ** ));

krb5_error_code krb5_rd_req
	PROTOTYPE((const krb5_data *,
		   krb5_const_principal,
		   const krb5_address *,
		   krb5_const_pointer,
		   krb5_error_code (* )(krb5_pointer,
					krb5_principal,
					krb5_kvno,
					krb5_keyblock ** ),
		   krb5_pointer,
		   krb5_rcache,
		   krb5_tkt_authent ** ));
krb5_error_code krb5_rd_req_decoded
	PROTOTYPE((const krb5_ap_req *,
		   krb5_const_principal,
		   const krb5_address *,
		   krb5_const_pointer,
		   krb5_error_code (* )(krb5_pointer,
					krb5_principal,
					krb5_kvno,
					krb5_keyblock ** ),
		   krb5_pointer,
		   krb5_rcache,
		   krb5_tkt_authent ** ));

krb5_error_code krb5_kt_read_service_key
	PROTOTYPE((krb5_pointer,
		   krb5_principal,
		   krb5_kvno,
		   krb5_keyblock **));
krb5_error_code krb5_mk_safe
	PROTOTYPE((const krb5_data *,
		   const krb5_cksumtype ,
		   const krb5_keyblock *,
		   const krb5_address *,
		   const krb5_address *,
		   krb5_int32, krb5_int32,
		   krb5_rcache,
		   krb5_data * ));
krb5_error_code krb5_mk_priv
	PROTOTYPE((const krb5_data *,
		   const krb5_enctype,
		   const krb5_keyblock *,
		   const krb5_address *,
		   const krb5_address *,
		   krb5_int32, krb5_int32,
		   krb5_rcache,
		   krb5_pointer,
		   krb5_data * ));
krb5_error_code krb5_cc_register
	PROTOTYPE((krb5_cc_ops *,
		   krb5_boolean ));

#include <krb5/narrow.h>

#endif /* KRB5_FUNC_PROTO__ */
