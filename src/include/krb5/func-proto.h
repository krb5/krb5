/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Function prototypes for Kerberos V5 library.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_FUNC_PROTO__
#define __KRB5_FUNC_PROTO__


/* libkrb.spec */
krb5_error_code krb5_encode_kdc_rep
	PROTOTYPE((int,			/* promotion rules require this */
		   krb5_kdc_rep *,
		   krb5_enc_kdc_rep_part *,
		   krb5_keyblock *,
		   krb5_data ** ));
krb5_error_code krb5_decode_kdc_rep
	PROTOTYPE((krb5_data *,
		   krb5_keyblock *,
		   int,			/* promotion rules require this */
		   krb5_kdc_rep ** ));
krb5_error_code krb5_encode_ticket
	PROTOTYPE((krb5_ticket *,
		   krb5_data ** ));
krb5_error_code krb5_decode_ticket
	PROTOTYPE((krb5_data *,
		   krb5_ticket ** ));
krb5_error_code krb5_encrypt_tkt_part
	PROTOTYPE((krb5_keyblock *,
		   krb5_ticket * ));
krb5_error_code krb5_decrypt_tkt_part
	PROTOTYPE((krb5_keyblock *,
		   krb5_ticket * ));
krb5_error_code krb5_send_tgs
	PROTOTYPE((krb5_flags,
		   krb5_ticket_times *,
		   krb5_enctype,
		   krb5_principal,
		   krb5_address **,
		   krb5_data *,
		   krb5_data *,
		   krb5_creds *,
		   krb5_response * ));
krb5_error_code krb5_sendto_kdc
	PROTOTYPE((krb5_data *,
		   krb5_data *,
		   krb5_data * ));
krb5_error_code krb5_get_cred_from_kdc
	PROTOTYPE((krb5_creds *,
		   krb5_creds *** ));
krb5_error_code krb5_free_tgt_creds
	PROTOTYPE((krb5_creds ** ));
krb5_error_code krb5_get_credentials
	PROTOTYPE((krb5_flags,
		   krb5_ccache,
		   krb5_creds * ));
krb5_error_code krb5_get_in_tkt
	PROTOTYPE((krb5_flags,
		   krb5_address **,
		   krb5_enctype,
		   krb5_keytype,
		   int (* )(krb5_keytype,
				    krb5_keyblock **,
				    krb5_pointer ),
		   krb5_pointer,
		   int (* )(krb5_data *,
					krb5_kdc_rep *,
					krb5_keyblock *,
					krb5_pointer ),
		   krb5_pointer,
		   krb5_creds * ));
krb5_error_code krb5_get_in_tkt_with_password
	PROTOTYPE((krb5_flags,
		   krb5_address **,
		   krb5_enctype,
		   krb5_keytype,
		   char *,
		   krb5_ccache,
		   krb5_creds *,
		   int ));
krb5_error_code krb5_get_in_tkt_with_skey
	PROTOTYPE((krb5_flags,
		   krb5_address **,
		   krb5_enctype,
		   krb5_keyblock *,
		   krb5_ccache,
		   krb5_creds * ));
krb5_error_code krb5_mk_req
	PROTOTYPE((krb5_principal,
		   krb5_flags,
		   krb5_checksum *,
		   krb5_ccache,
		   krb5_data * ));
krb5_error_code krb5_mk_req_extended
	PROTOTYPE((krb5_flags,
		   krb5_checksum *,
		   krb5_ticket_times *,
		   krb5_flags,
		   krb5_creds *,
		   krb5_data *,
		   int ));
krb5_error_code krb5_rd_req
	PROTOTYPE((krb5_data *,
		   krb5_principal,
		   krb5_address *,
		   krb5_pointer,
		   int (* )(krb5_pointer,
				   krb5_principal,
				   krb5_kvno,
				   krb5_keyblock ** ),
		   krb5_pointer,
		   krb5_rcache,
		   krb5_tkt_authent * ));
krb5_error_code krb5_mk_error
	PROTOTYPE((krb5_error *,
		   krb5_data * ));
krb5_error_code krb5_rd_error
	PROTOTYPE((krb5_data *,
		   krb5_error * ));
krb5_error_code krb5_mk_safe
	PROTOTYPE((krb5_data *,
		   krb5_cksumtype ,
		   krb5_keyblock *,
		   krb5_fulladdr *,
		   krb5_fulladdr *,
		   krb5_data * ));
krb5_error_code krb5_rd_safe
	PROTOTYPE((krb5_data *,
		   krb5_keyblock *,
		   krb5_fulladdr *,
		   krb5_fulladdr *,
		   krb5_data * ));
krb5_error_code krb5_mk_priv
	PROTOTYPE((krb5_data *,
		   krb5_enctype,
		   krb5_keyblock *,
		   krb5_fulladdr *,
		   krb5_fulladdr *,
		   krb5_data * ));
krb5_error_code krb5_rd_priv
	PROTOTYPE((krb5_data *,
		   krb5_keyblock *,
		   krb5_fulladdr *,
		   krb5_fulladdr *,
		   krb5_data * ));
krb5_error_code krb5_get_default_realm
	PROTOTYPE((int,
		   char * ));
krb5_error_code krb5_get_host_realm
	PROTOTYPE((char *,
		   char *** ));
krb5_error_code krb5_free_host_realm
	PROTOTYPE((char ** ));
krb5_error_code krb5_parse_name
	PROTOTYPE((char *,
		   krb5_principal * ));
krb5_error_code krb5_unparse_name
	PROTOTYPE((krb5_principal,
		   char ** ));
krb5_error_code krb5_aname_to_localname
	PROTOTYPE((krb5_principal,
		   int,
		   char * ));
krb5_error_code krb5_get_krbhst
	PROTOTYPE((krb5_data *,
		   char *** ));
krb5_error_code krb5_free_krbhst
	PROTOTYPE((char ** ));

/* libkt.spec */
krb5_error_code krb5_kt_register
	PROTOTYPE((krb5_kt_ops * ));
krb5_error_code krb5_kt_resolve
	PROTOTYPE((char *,
		   krb5_keytab * ));
krb5_error_code krb5_kt_get_name
	PROTOTYPE((krb5_keytab,
		   char *,
		   int ));
krb5_error_code krb5_kt_close
	PROTOTYPE((krb5_keytab ));
krb5_error_code krb5_kt_get_entry
	PROTOTYPE((krb5_keytab,
		   krb5_principal,
		   krb5_kvno,
		   krb5_keytab_entry * ));
krb5_error_code krb5_kt_start_seq_get
	PROTOTYPE((krb5_keytab,
		   krb5_kt_cursor * ));
krb5_error_code krb5_kt_next_entry
	PROTOTYPE((krb5_keytab,
		   krb5_keytab_entry *,
		   krb5_kt_cursor ));
krb5_error_code krb5_kt_end_seq_get
	PROTOTYPE((krb5_keytab,
		   krb5_kt_cursor ));
krb5_error_code krb5_kt_remove_entry
	PROTOTYPE((krb5_keytab,
		   krb5_keytab_entry * ));
krb5_error_code krb5_kt_add_entry
	PROTOTYPE((krb5_keytab,
		   krb5_keytab_entry * ));
krb5_error_code krb5_kt_read_service_key
	PROTOTYPE((krb5_pointer,
		   krb5_principal,
		   krb5_kvno,
		   krb5_keyblock **));

/* librc.spec */
krb5_error_code krb5_rc_initialize
	PROTOTYPE((krb5_rcache,
		   krb5_deltat ));
krb5_error_code krb5_rc_recover
	PROTOTYPE((krb5_rcache ));
krb5_error_code krb5_rc_destroy
	PROTOTYPE((krb5_rcache ));
krb5_error_code krb5_rc_close
	PROTOTYPE((krb5_rcache ));
krb5_error_code krb5_rc_store
	PROTOTYPE((krb5_rcache,
		   krb5_tkt_authent *,
		   krb5_boolean ));
krb5_error_code krb5_rc_expunge
	PROTOTYPE((krb5_rcache ));
krb5_error_code krb5_rc_get_lifespan
	PROTOTYPE((krb5_rcache,
		   krb5_deltat * ));
krb5_error_code krb5_rc_resolve
	PROTOTYPE((krb5_rcache *,
		   char * ));
krb5_error_code krb5_rc_generate_new
	PROTOTYPE((krb5_rcache *,
		   krb5_rc_ops * ));
krb5_error_code krb5_rc_register
	PROTOTYPE((krb5_rc_ops * ));
char *krb5_rc_get_name
	PROTOTYPE((krb5_rcache ));
char *krb5_rc_default_name
	PROTOTYPE((void ));
krb5_rcache krb5_rc_default
	PROTOTYPE((void ));


/* libcc.spec */
krb5_error_code krb5_cc_initialize
	PROTOTYPE((krb5_ccache,
		   krb5_principal ));
krb5_error_code krb5_cc_destroy
	PROTOTYPE((krb5_ccache ));
krb5_error_code krb5_cc_close
	PROTOTYPE((krb5_ccache ));
krb5_error_code krb5_cc_store_cred
	PROTOTYPE((krb5_ccache,
		   krb5_creds * ));
krb5_error_code krb5_cc_retrieve_cred
	PROTOTYPE((krb5_ccache,
		   krb5_flags,
		   krb5_creds *,
		   krb5_creds * ));
krb5_error_code krb5_cc_get_principal
	PROTOTYPE((krb5_ccache,
		   krb5_principal * ));
krb5_error_code krb5_cc_start_seq_get
	PROTOTYPE((krb5_ccache,
		   krb5_cc_cursor * ));
krb5_error_code krb5_cc_next_cred
	PROTOTYPE((krb5_ccache,
		   krb5_creds *,
		   krb5_cc_cursor * ));
krb5_error_code krb5_cc_end_seq_get
	PROTOTYPE((krb5_ccache,
		   krb5_cc_cursor * ));
krb5_error_code krb5_cc_remove_cred
	PROTOTYPE((krb5_ccache,
		   krb5_flags,
		   krb5_creds * ));
krb5_error_code krb5_cc_resolve
	PROTOTYPE((char *,
		   krb5_ccache * ));
krb5_error_code krb5_cc_generate_new
	PROTOTYPE((krb5_cc_ops *,
		   krb5_ccache * ));
krb5_error_code krb5_cc_register
	PROTOTYPE((krb5_cc_ops *,
		   krb5_boolean ));
char *krb5_cc_default_name
	PROTOTYPE((void ));
krb5_ccache krb5_cc_default
	PROTOTYPE((void ));


/* krb5_free.c */
void krb5_free_principal
	PROTOTYPE((krb5_principal ));
void krb5_free_authenticator
	PROTOTYPE((krb5_authenticator * ));
void krb5_free_address
	PROTOTYPE((krb5_address ** ));
void krb5_free_authdata
	PROTOTYPE((krb5_authdata ** ));
void krb5_free_enc_tkt_part
	PROTOTYPE((krb5_enc_tkt_part * ));
void krb5_free_ticket
	PROTOTYPE((krb5_ticket * ));
void krb5_free_as_req
	PROTOTYPE((krb5_as_req * ));
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
void krb5_free_tgs_req
	PROTOTYPE((krb5_tgs_req * ));
void krb5_free_tgs_req_enc_part
	PROTOTYPE((krb5_tgs_req_enc_part * ));
void krb5_free_safe
	PROTOTYPE((krb5_safe * ));
void krb5_free_priv
	PROTOTYPE((krb5_priv * ));
void krb5_free_priv_enc_part
	PROTOTYPE((krb5_priv_enc_part * ));

#endif /* __KRB5_FUNC_PROTO__ */
