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
	PROTOTYPE((krb5_msgtype type,
		   krb5_kdc_rep *dec_rep,
		   krb5_enc_kdc_rep_part *encpart,
		   krb5_keyblock *client_key,
		   krb5_enctype etype,
		   krb5_data *enc_rep ));
krb5_error_code krb5_decode_ticket
	PROTOTYPE((krb5_data *enc_ticket,
		   krb5_keyblock *srv_key,
		   krb5_enctype etype,
		   krb5_ticket **dec_ticket ));
krb5_error_code krb5_encode_ticket
	PROTOTYPE((krb5_ticket *dec_ticket,
		   krb5_keyblock *srv_key,
		   krb5_enctype etype,
		   krb5_data *enc_ticket ));
krb5_error_code krb5_decode_kdc_rep
	PROTOTYPE((krb5_data *enc_rep,
		   krb5_keyblock *key,
		   krb5_enctype etype,
		   krb5_kdc_rep **dec_rep ));
krb5_error_code krb5_send_tgs
	PROTOTYPE((krb5_flags options,
		   krb5_ticket_times *timestruct,
		   krb5_enctype etype,
		   krb5_principal sname,
		   krb5_address **addrs,
		   krb5_data *authorization_dat,
		   krb5_data *second_ticket,
		   krb5_creds *usecred,
		   krb5_response *rep ));
krb5_error_code krb5_sendto_kdc
	PROTOTYPE((krb5_data *send,
		   krb5_data *realm,
		   krb5_data *receive ));
krb5_error_code krb5_get_cred_from_kdc
	PROTOTYPE((krb5_creds *creds,
		   krb5_creds ***tgts ));
krb5_error_code krb5_free_tgt_creds
	PROTOTYPE((krb5_creds **tgts ));
krb5_error_code krb5_get_credentials
	PROTOTYPE((krb5_flags options,
		   krb5_ccache_id ccache_id,
		   krb5_creds *creds ));
krb5_error_code krb5_get_in_tkt
	PROTOTYPE((krb5_flags options,
		   krb5_address **addrs,
		   krb5_enctype etype,
		   krb5_keytype keytype,
		   int (*key_proc )(krb5_keytype type,
				    krb5_keyblock **key,
				    krb5_pointer keyseed ),
		   krb5_pointer keyseed,
		   int (*decrypt_proc )(krb5_data *rep,
					krb5_kdc_rep *dc_rep,
					krb5_keyblock *key,
					krb5_pointer decryptarg ),
		   krb5_pointer decryptarg,
		   krb5_creds *creds ));
krb5_error_code krb5_get_in_tkt_with_password
	PROTOTYPE((krb5_flags options,
		   krb5_address **addrs,
		   krb5_enctype etype,
		   krb5_keytype keytype,
		   char *password,
		   krb5_ccache_id ccache_id,
		   krb5_creds *creds,
		   int ));
krb5_error_code krb5_get_in_tkt_with_skey
	PROTOTYPE((krb5_flags options,
		   krb5_address **addrs,
		   krb5_enctype etype,
		   krb5_keyblock *key,
		   krb5_ccache_id ccache_id,
		   krb5_creds *creds ));
krb5_error_code krb5_mk_req
	PROTOTYPE((krb5_principal server,
		   krb5_flags ap_req_options,
		   krb5_checksum *checksum,
		   krb5_ccache_id ccache_id,
		   krb5_data *outbuf ));
krb5_error_code krb5_mk_req_extended
	PROTOTYPE((krb5_flags ap_req_options,
		   krb5_checksum *checksum,
		   krb5_ticket_times *times,
		   krb5_flags kdc_options,
		   krb5_creds *creds,
		   krb5_data *outbuf,
		   int ));
krb5_error_code krb5_rd_req
	PROTOTYPE((krb5_data *inbuf,
		   krb5_principal server,
		   krb5_address *sender_addr,
		   krb5_pointer fetchfrom,
		   int (*keyproc )(krb5_pointer keyprocarg,
				   krb5_principal principal,
				   krb5_kvno vno,
				   krb5_keyblock **key ),
		   krb5_pointer keyprocarg,
		   krb5_rcache rcache,
		   krb5_tkt_authent *authdat ));
krb5_error_code krb5_mk_error
	PROTOTYPE((krb5_error *dec_err,
		   krb5_data *enc_err ));
krb5_error_code krb5_rd_error
	PROTOTYPE((krb5_data *enc_errbuf,
		   krb5_error *dec_error ));
krb5_error_code krb5_mk_safe
	PROTOTYPE((krb5_data *userdata,
		   krb5_cksumtype sumtype,
		   krb5_keyblock *key,
		   krb5_fulladdr *sender_addr,
		   krb5_fulladdr *recv_addr,
		   krb5_data *outbuf ));
krb5_error_code krb5_rd_safe
	PROTOTYPE((krb5_data *inbuf,
		   krb5_keyblock *key,
		   krb5_fulladdr *sender_addr,
		   krb5_fulladdr *recv_addr,
		   krb5_data *outbuf ));
krb5_error_code krb5_mk_priv
	PROTOTYPE((krb5_data *userdata,
		   krb5_enctype etype,
		   krb5_keyblock *key,
		   krb5_fulladdr *sender_addr,
		   krb5_fulladdr *recv_addr,
		   krb5_data *outbuf ));
krb5_error_code krb5_rd_priv
	PROTOTYPE((krb5_data *inbuf,
		   krb5_keyblock *key,
		   krb5_fulladdr *sender_addr,
		   krb5_fulladdr *recv_addr,
		   krb5_data *outbuf ));
krb5_error_code krb5_get_default_realm
	PROTOTYPE((int lnsize,
		   char *lrealm ));
krb5_error_code krb5_get_host_realm
	PROTOTYPE((char *host,
		   char ***realmlist ));
krb5_error_code krb5_free_host_realm
	PROTOTYPE((char **realmlist ));
krb5_error_code krb5_parse_name
	PROTOTYPE((char *name,
		   krb5_principal *principal ));
krb5_error_code krb5_unparse_name
	PROTOTYPE((krb5_principal principal,
		   char **name ));
krb5_error_code krb5_aname_to_localname
	PROTOTYPE((krb5_principal aname,
		   int lnsize,
		   char *lname ));
krb5_error_code krb5_get_krbhst
	PROTOTYPE((krb5_data *realm,
		   char ***hostlist ));
krb5_error_code krb5_free_krbhst
	PROTOTYPE((char **hostlist ));

/* libkt.spec */
krb5_error_code krb5_kt_register
	PROTOTYPE((krb5_kt_ops *ops ));
krb5_error_code krb5_kt_resolve
	PROTOTYPE((char *string_name,
		   krb5_keytab *id ));
krb5_error_code krb5_kt_get_name
	PROTOTYPE((krb5_keytab id,
		   char *name,
		   int namesize ));
krb5_error_code krb5_kt_close
	PROTOTYPE((krb5_keytab id ));
krb5_error_code krb5_kt_get_entry
	PROTOTYPE((krb5_keytab id,
		   krb5_principal principal,
		   krb5_kvno vno,
		   krb5_keytab_entry *entry ));
krb5_error_code krb5_kt_start_seq_get
	PROTOTYPE((krb5_keytab id,
		   krb5_kt_cursor *cursor ));
krb5_error_code krb5_kt_next_entry
	PROTOTYPE((krb5_keytab id,
		   krb5_keytab_entry *entry,
		   krb5_kt_cursor cursor ));
krb5_error_code krb5_kt_end_seq_get
	PROTOTYPE((krb5_keytab id,
		   krb5_kt_cursor cursor ));
krb5_error_code krb5_kt_remove_entry
	PROTOTYPE((krb5_keytab id,
		   krb5_keytab_entry *entry ));
krb5_error_code krb5_kt_add_entry
	PROTOTYPE((krb5_keytab id,
		   krb5_keytab_entry *entry ));


/* librc.spec */
krb5_error_code krb5_rc_initialize
	PROTOTYPE((krb5_rcache id,
		   krb5_deltat auth_lifespan ));
krb5_error_code krb5_rc_recover
	PROTOTYPE((krb5_rcache id ));
krb5_error_code krb5_rc_destroy
	PROTOTYPE((krb5_rcache id ));
krb5_error_code krb5_rc_close
	PROTOTYPE((krb5_rcache id ));
krb5_error_code krb5_rc_store
	PROTOTYPE((krb5_rcache id,
		   krb5_tkt_authent *auth,
		   krb5_boolean expunge ));
krb5_error_code krb5_rc_expunge
	PROTOTYPE((krb5_rcache id ));
krb5_error_code krb5_rc_get_lifespan
	PROTOTYPE((krb5_rcache id,
		   krb5_deltat *auth_lifespan ));
krb5_error_code krb5_rc_resolve
	PROTOTYPE((krb5_rcache *id,
		   char *string_name ));
krb5_error_code krb5_rc_generate_new
	PROTOTYPE((krb5_rcache *id,
		   krb5_rc_ops *ops ));
krb5_error_code krb5_rc_register
	PROTOTYPE((krb5_rc_ops *ops ));
char *krb5_rc_get_name
	PROTOTYPE((krb5_rcache id ));
char *krb5_rc_default_name
	PROTOTYPE((void ));
krb5_rcache krb5_rc_default
	PROTOTYPE((void ));


/* libcc.spec */
krb5_error_code krb5_cc_initialize
	PROTOTYPE((krb5_ccache id,
		   krb5_principal primary_principal ));
krb5_error_code krb5_cc_destroy
	PROTOTYPE((krb5_ccache id ));
krb5_error_code krb5_cc_close
	PROTOTYPE((krb5_ccache id ));
krb5_error_code krb5_cc_store_cred
	PROTOTYPE((krb5_ccache id,
		   krb5_credentials *creds ));
krb5_error_code krb5_cc_retrieve_cred
	PROTOTYPE((krb5_ccache id,
		   krb5_flags whichfields,
		   krb5_credentials *mcreds,
		   krb5_credentials *creds ));
krb5_error_code krb5_cc_get_principal
	PROTOTYPE((krb5_ccache id,
		   krb5_principal *principal ));
krb5_error_code krb5_cc_start_seq_get
	PROTOTYPE((krb5_ccache id,
		   krb5_cc_cursor *cursor ));
krb5_error_code krb5_cc_next_cred
	PROTOTYPE((krb5_ccache id,
		   krb5_credentials *creds,
		   krb5_cc_cursor *cursor ));
krb5_error_code krb5_cc_end_seq_get
	PROTOTYPE((krb5_ccache id,
		   krb5_cc_cursor *cursor ));
krb5_error_code krb5_cc_remove_cred
	PROTOTYPE((krb5_ccache id,
		   krb5_flags which,
		   krb5_credentials *cred ));
krb5_error_code krb5_cc_resolve
	PROTOTYPE((char *string_name,
		   krb5_ccache *id ));
krb5_error_code krb5_cc_generate_new
	PROTOTYPE((krb5_cc_ops *ops,
		   krb5_ccache *id ));
krb5_error_code krb5_cc_register
	PROTOTYPE((krb5_cc_ops *ops,
		   krb5_boolean override ));
char *krb5_cc_default_name
	PROTOTYPE((void ));
krb5_ccache krb5_cc_default
	PROTOTYPE((void ));


/* krb5_free.c */
void krb5_free_principal
	PROTOTYPE((krb5_principal val ));
void krb5_free_authenticator
	PROTOTYPE((krb5_authenticator *val ));
void krb5_free_address
	PROTOTYPE((krb5_address **val ));
void krb5_free_authdata
	PROTOTYPE((krb5_authdata **val ));
void krb5_free_enc_tkt_part
	PROTOTYPE((krb5_enc_tkt_part *val ));
void krb5_free_ticket
	PROTOTYPE((krb5_ticket *val ));
void krb5_free_as_req
	PROTOTYPE((krb5_as_req *val ));
void krb5_free_kdc_rep
	PROTOTYPE((krb5_kdc_rep *val ));
void krb5_free_last_req
	PROTOTYPE((krb5_last_req_entry **val ));
void krb5_free_enc_kdc_rep_part
	PROTOTYPE((krb5_enc_kdc_rep_part *val ));
void krb5_free_error
	PROTOTYPE((krb5_error *val ));
void krb5_free_ap_req
	PROTOTYPE((krb5_ap_req *val ));
void krb5_free_ap_rep
	PROTOTYPE((krb5_ap_rep *val ));
void krb5_free_tgs_req
	PROTOTYPE((krb5_tgs_req *val ));
void krb5_free_tgs_req_enc_part
	PROTOTYPE((krb5_tgs_req_enc_part *val ));
void krb5_free_safe
	PROTOTYPE((krb5_safe *val ));
void krb5_free_priv
	PROTOTYPE((krb5_priv *val ));
void krb5_free_priv_enc_part
	PROTOTYPE((krb5_priv_enc_part *val ));

#endif /* __KRB5_FUNC_PROTO__ */
