/*
 * include/krb5/func-proto.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Function prototypes for Kerberos V5 library.
 */

#ifndef KRB5_FUNC_PROTO__
#define KRB5_FUNC_PROTO__

krb5_error_code INTERFACE krb5_init_context
	PROTOTYPE((krb5_context *));
void INTERFACE krb5_free_context
	PROTOTYPE((krb5_context));

krb5_error_code	INTERFACE krb5_set_default_in_tkt_etypes
	PROTOTYPE((krb5_context,
		   const krb5_enctype *));
krb5_error_code	INTERFACE krb5_get_default_in_tkt_etypes
	PROTOTYPE((krb5_context,
		   krb5_enctype **));

/* This is a hack to find what needs fixing later, when we've all forgotten
 which rotuines still need fixing */
extern krb5_context global_context;

/* libkrb.spec */
krb5_error_code INTERFACE krb5_kdc_rep_decrypt_proc
	PROTOTYPE((krb5_context,
		   const krb5_keyblock *,
		   krb5_const_pointer,
		   krb5_kdc_rep * ));
krb5_error_code INTERFACE krb5_encode_ticket
	PROTOTYPE((krb5_context,
		   const krb5_ticket *,
		   krb5_data ** ));
krb5_error_code INTERFACE krb5_encrypt_tkt_part
	PROTOTYPE((krb5_context,
		   krb5_encrypt_block *,
		   const krb5_keyblock *,
		   krb5_ticket * ));
krb5_error_code INTERFACE krb5_decrypt_tkt_part
	PROTOTYPE((krb5_context,
		   const krb5_keyblock *,
		   krb5_ticket * ));
krb5_error_code INTERFACE krb5_get_cred_from_kdc
	PROTOTYPE((krb5_context,
		   krb5_ccache,		/* not const, as reading may save
					   state */
		   krb5_creds *,
		   krb5_creds **,
		   krb5_creds *** ));
void INTERFACE krb5_free_tgt_creds
	PROTOTYPE((krb5_context,
		   krb5_creds ** ));	/* XXX too hard to do with const */

#define	KRB5_GC_USER_USER	1	/* want user-user ticket */
#define	KRB5_GC_CACHED		2	/* want cached ticket only */

krb5_error_code INTERFACE krb5_get_credentials
	PROTOTYPE((krb5_context,
		   const krb5_flags,
		   krb5_ccache,
		   krb5_creds *,
		   krb5_creds **));
krb5_error_code	INTERFACE krb5_get_for_creds
	PROTOTYPE((krb5_context,
		   const krb5_cksumtype,
		   char *,
		   krb5_principal,
		   krb5_keyblock *,
		   int,
		   krb5_data * ));
krb5_error_code INTERFACE krb5_mk_req
	PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   const krb5_flags,
		   const krb5_checksum *,
		   krb5_ccache,
		   krb5_data * ));
krb5_error_code INTERFACE krb5_mk_req_extended
	PROTOTYPE((krb5_context,
		   const krb5_flags,
		   const krb5_checksum *,
		   krb5_int32,
		   krb5_keyblock **,
		   krb5_creds *,
		   krb5_authenticator *,
		   krb5_data * ));
krb5_error_code INTERFACE krb5_rd_req_simple
	PROTOTYPE((krb5_context,
		   const krb5_data *,
		   krb5_const_principal,
		   const krb5_address *,
		   krb5_tkt_authent ** ));
krb5_error_code INTERFACE krb5_mk_rep
	PROTOTYPE((krb5_context,
		   const krb5_ap_rep_enc_part *,
		   const krb5_keyblock *,
		   krb5_data *));
krb5_error_code INTERFACE krb5_rd_rep
	PROTOTYPE((krb5_context,
		   const krb5_data *,
		   const krb5_keyblock *,
		   krb5_ap_rep_enc_part **));
krb5_error_code INTERFACE krb5_mk_error
	PROTOTYPE((krb5_context,
		   const krb5_error *,
		   krb5_data * ));
krb5_error_code INTERFACE krb5_rd_error
	PROTOTYPE((krb5_context,
		   const krb5_data *,
		   krb5_error ** ));
krb5_error_code INTERFACE krb5_rd_safe
	PROTOTYPE((krb5_context,
		   const krb5_data *,
		   const krb5_keyblock *,
		   const krb5_address *,
		   const krb5_address *,
		   krb5_int32, krb5_int32,
		   krb5_rcache,
		   krb5_data * ));
krb5_error_code INTERFACE krb5_rd_priv
	PROTOTYPE((krb5_context,
		   const krb5_data *,
		   const krb5_keyblock *,
		   const krb5_address *,
		   const krb5_address *,
		   krb5_int32, krb5_int32,
		   krb5_pointer,
		   krb5_rcache,
		   krb5_data * ));
krb5_error_code INTERFACE krb5_parse_name
	PROTOTYPE((krb5_context,
		   const char *,
		   krb5_principal * ));
krb5_error_code INTERFACE krb5_unparse_name
	PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   char ** ));
krb5_error_code INTERFACE krb5_unparse_name_ext
	PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   char **,
		   int *));
krb5_boolean INTERFACE krb5_address_search
	PROTOTYPE((krb5_context,
		   const krb5_address *,
		   krb5_address * const *));
krb5_boolean INTERFACE krb5_address_compare
	PROTOTYPE((krb5_context,
		   const krb5_address *,
		   const krb5_address *));
int INTERFACE krb5_address_order
	PROTOTYPE((krb5_context,
		   const krb5_address *,
		   const krb5_address *));
krb5_boolean INTERFACE krb5_realm_compare
	PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   krb5_const_principal));
krb5_boolean INTERFACE krb5_principal_compare
	PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   krb5_const_principal));
int INTERFACE krb5_fulladdr_order
	PROTOTYPE((krb5_context,
		   const krb5_fulladdr *,
		   const krb5_fulladdr *));
krb5_error_code INTERFACE krb5_copy_keyblock
    	PROTOTYPE((krb5_context,
		   const krb5_keyblock *,
	       krb5_keyblock **));
krb5_error_code INTERFACE krb5_copy_keyblock_contents
    	PROTOTYPE((krb5_context,
		   const krb5_keyblock *,
	       krb5_keyblock *));
krb5_error_code INTERFACE krb5_copy_creds
    	PROTOTYPE((krb5_context,
		   const krb5_creds *,
	       krb5_creds **));
krb5_error_code INTERFACE krb5_copy_data
    	PROTOTYPE((krb5_context,
		   const krb5_data *,
	       krb5_data **));
krb5_error_code INTERFACE krb5_copy_principal
    	PROTOTYPE((krb5_context,
		   krb5_const_principal,
	       krb5_principal *));
krb5_error_code INTERFACE krb5_copy_addresses
    	PROTOTYPE((krb5_context,
		   krb5_address * const *,
	       krb5_address ***));
krb5_error_code INTERFACE krb5_copy_ticket
    	PROTOTYPE((krb5_context,
		   const krb5_ticket *, krb5_ticket **));
krb5_error_code INTERFACE krb5_copy_authdata
    	PROTOTYPE((krb5_context,
		   krb5_authdata * const *,
	       krb5_authdata ***));
krb5_error_code INTERFACE krb5_copy_authenticator
    	PROTOTYPE((krb5_context,
		   const krb5_authenticator *,
	       krb5_authenticator **));
krb5_error_code INTERFACE krb5_copy_checksum
    	PROTOTYPE((krb5_context,
		   const krb5_checksum *,
	       krb5_checksum **));
void INTERFACE krb5_init_ets PROTOTYPE((krb5_context));
krb5_error_code INTERFACE krb5_generate_subkey
    	PROTOTYPE((krb5_context,
		   const krb5_keyblock *, krb5_keyblock **));
krb5_error_code INTERFACE krb5_generate_seq_number
    	PROTOTYPE((krb5_context,
		   const krb5_keyblock *, krb5_int32 *));
krb5_error_code INTERFACE krb5_get_server_rcache
    	PROTOTYPE((krb5_context,
		   const krb5_data *, krb5_rcache *));
krb5_error_code krb5_build_principal_ext
    	STDARG_P((krb5_context, krb5_principal *, int, const char *, ...));
krb5_error_code krb5_build_principal
    	STDARG_P((krb5_context, krb5_principal *, int, const char *, ...));
#ifdef va_start
/* XXX depending on varargs include file defining va_start... */
krb5_error_code krb5_build_principal_va
    	PROTOTYPE((krb5_context,
		   krb5_principal *, int, const char *, va_list));
#endif

krb5_error_code INTERFACE krb5_425_conv_principal
	PROTOTYPE((krb5_context,
		   const char *name, const char *instance, const char *realm,
		   krb5_principal *princ));

krb5_error_code INTERFACE krb5_obtain_padata
    	PROTOTYPE((krb5_context,
		   int type, krb5_principal client, krb5_address **src_addr,
	           krb5_keyblock *encrypt_key, krb5_pa_data **data));

krb5_error_code INTERFACE krb5_verify_padata
    	PROTOTYPE((krb5_context,
		   krb5_pa_data * data, krb5_principal client,
	       krb5_address **src_addr, krb5_keyblock *decrypt_key,
	       int *req_id, int *flags));

/* libkt.spec */
krb5_error_code INTERFACE krb5_kt_register
	PROTOTYPE((krb5_context,
		   krb5_kt_ops * ));
krb5_error_code INTERFACE krb5_kt_resolve
	PROTOTYPE((krb5_context,
		   const char *,
		   krb5_keytab * ));
krb5_error_code INTERFACE krb5_kt_default_name
	PROTOTYPE((krb5_context,
		   char *,
		   int ));
krb5_error_code INTERFACE krb5_kt_default
	PROTOTYPE((krb5_context,
		   krb5_keytab * ));
krb5_error_code INTERFACE krb5_kt_free_entry
	PROTOTYPE((krb5_context,
		   krb5_keytab_entry * ));
/* remove and add are functions, so that they can return NOWRITE
   if not a writable keytab */
krb5_error_code INTERFACE krb5_kt_remove_entry
	PROTOTYPE((krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry * ));
krb5_error_code INTERFACE krb5_kt_add_entry
	PROTOTYPE((krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry * ));
krb5_error_code INTERFACE krb5_principal2salt
	PROTOTYPE((krb5_context,
		   krb5_const_principal, krb5_data *));
krb5_error_code INTERFACE krb5_principal2salt_norealm
	PROTOTYPE((krb5_context,
		   krb5_const_principal, krb5_data *));

/* librc.spec--see rcache.h */

/* libcc.spec */
krb5_error_code INTERFACE krb5_cc_resolve
	PROTOTYPE((krb5_context,
		   char *,
		   krb5_ccache * ));
krb5_error_code INTERFACE krb5_cc_generate_new
	PROTOTYPE((krb5_context,
		   krb5_cc_ops *,
		   krb5_ccache * ));
char * INTERFACE krb5_cc_default_name
	PROTOTYPE((krb5_context));
krb5_error_code INTERFACE krb5_cc_default
	PROTOTYPE((krb5_context,
		   krb5_ccache *));

/* chk_trans.c */
krb5_error_code INTERFACE krb5_check_transited_list
    PROTOTYPE((krb5_context,
		   krb5_data *trans, krb5_data *realm1, krb5_data *realm2));

/* free_rtree.c */
void INTERFACE krb5_free_realm_tree
	PROTOTYPE((krb5_context,
		   krb5_principal *));

/* krb5_free.c */
void INTERFACE krb5_free_principal
	PROTOTYPE((krb5_context,
		   krb5_principal ));
void INTERFACE krb5_free_authenticator
	PROTOTYPE((krb5_context,
		   krb5_authenticator * ));
void INTERFACE krb5_free_authenticator_contents
	PROTOTYPE((krb5_context,
		   krb5_authenticator * ));
void INTERFACE krb5_free_addresses
	PROTOTYPE((krb5_context,
		   krb5_address ** ));
void INTERFACE krb5_free_address
	PROTOTYPE((krb5_context,
		   krb5_address * ));
void INTERFACE krb5_free_authdata
	PROTOTYPE((krb5_context,
		   krb5_authdata ** ));
void INTERFACE krb5_free_enc_tkt_part
	PROTOTYPE((krb5_context,
		   krb5_enc_tkt_part * ));
void INTERFACE krb5_free_ticket
	PROTOTYPE((krb5_context,
		   krb5_ticket * ));
void INTERFACE krb5_free_tickets
	PROTOTYPE((krb5_context,
		   krb5_ticket ** ));
void INTERFACE krb5_free_kdc_req
	PROTOTYPE((krb5_context,
		   krb5_kdc_req * ));
void INTERFACE krb5_free_kdc_rep
	PROTOTYPE((krb5_context,
		   krb5_kdc_rep * ));
void INTERFACE krb5_free_last_req
	PROTOTYPE((krb5_context,
		   krb5_last_req_entry ** ));
void INTERFACE krb5_free_enc_kdc_rep_part
	PROTOTYPE((krb5_context,
		   krb5_enc_kdc_rep_part * ));
void INTERFACE krb5_free_error
	PROTOTYPE((krb5_context,
		   krb5_error * ));
void INTERFACE krb5_free_ap_req
	PROTOTYPE((krb5_context,
		   krb5_ap_req * ));
void INTERFACE krb5_free_ap_rep
	PROTOTYPE((krb5_context,
		   krb5_ap_rep * ));
void INTERFACE krb5_free_safe
	PROTOTYPE((krb5_context,
		   krb5_safe * ));
void INTERFACE krb5_free_priv
	PROTOTYPE((krb5_context,
		   krb5_priv * ));
void INTERFACE krb5_free_priv_enc_part
	PROTOTYPE((krb5_context,
		   krb5_priv_enc_part * ));
void INTERFACE krb5_free_kdc_req
	PROTOTYPE((krb5_context,
		   krb5_kdc_req * ));
void INTERFACE krb5_free_cred
   PROTOTYPE((krb5_context, 
         krb5_cred *));
void INTERFACE krb5_free_creds
	PROTOTYPE((krb5_context,
		   krb5_creds *));
void INTERFACE krb5_free_cred_contents
	PROTOTYPE((krb5_context,
		   krb5_creds *));
void INTERFACE krb5_free_cred_enc_part
   PROTOTYPE((krb5_context,
         krb5_cred_enc_part *));
void INTERFACE krb5_free_checksum
	PROTOTYPE((krb5_context,
		   krb5_checksum *));
void INTERFACE krb5_free_keyblock
	PROTOTYPE((krb5_context,
		   krb5_keyblock *));
void INTERFACE krb5_free_pa_data
	PROTOTYPE((krb5_context,
		   krb5_pa_data **));
void INTERFACE krb5_free_ap_rep_enc_part
	PROTOTYPE((krb5_context,
		   krb5_ap_rep_enc_part *));
void INTERFACE krb5_free_tkt_authent
	PROTOTYPE((krb5_context,
		   krb5_tkt_authent *));
void INTERFACE krb5_free_pwd_data
   PROTOTYPE((krb5_context,
         krb5_pwd_data *));
void INTERFACE krb5_free_pwd_sequences
   PROTOTYPE((krb5_context,
         passwd_phrase_element **));

/* Only put things which don't have pointers to the narrow types in this
   section */

krb5_error_code INTERFACE krb5_encode_kdc_rep
	PROTOTYPE((krb5_context,
		   const krb5_msgtype,
		   const krb5_enc_kdc_rep_part *,
		   krb5_encrypt_block *,
		   const krb5_keyblock *,
		   krb5_kdc_rep *,
		   krb5_data ** ));

krb5_error_code INTERFACE krb5_send_tgs
	PROTOTYPE((krb5_context,
		   const krb5_flags,
		   const krb5_ticket_times *,
		   const krb5_enctype *,
		   const krb5_cksumtype,
		   krb5_const_principal,
		   krb5_address * const *,
		   krb5_authdata * const *,
		   krb5_pa_data * const *,
		   const krb5_data *,
		   krb5_creds *,
		   krb5_response * ));

krb5_error_code INTERFACE krb5_get_in_tkt
	PROTOTYPE((krb5_context,
		   const krb5_flags,
		   krb5_address * const *,
		   krb5_enctype *,
		   krb5_preauthtype *,
		   krb5_error_code (* )(krb5_context,
					const krb5_keytype,
                                        krb5_data *,
                                        krb5_const_pointer,
                                        krb5_keyblock **),
		   krb5_const_pointer,
		   krb5_error_code (* )(krb5_context,
					const krb5_keyblock *,
					krb5_const_pointer,
					krb5_kdc_rep * ),
		   krb5_const_pointer,
		   krb5_creds *,
		   krb5_ccache,
		   krb5_kdc_rep ** ));

krb5_error_code INTERFACE krb5_get_in_tkt_with_password
	PROTOTYPE((krb5_context,
		   const krb5_flags,
		   krb5_address * const *,
		   krb5_enctype *,
		   krb5_preauthtype *,
		   const char *,
		   krb5_ccache,
		   krb5_creds *,
		   krb5_kdc_rep ** ));

krb5_error_code INTERFACE krb5_get_in_tkt_with_skey
	PROTOTYPE((krb5_context,
		   const krb5_flags,
		   krb5_address * const *,
		   krb5_enctype *,
		   krb5_preauthtype *,
		   const krb5_keyblock *,
		   krb5_ccache,
		   krb5_creds *,
		   krb5_kdc_rep ** ));

krb5_error_code INTERFACE krb5_get_in_tkt_with_keytab
	PROTOTYPE((krb5_context,
		   const krb5_flags,
		   krb5_address * const *,
		   krb5_enctype *,
		   krb5_preauthtype *,
		   const krb5_keytab,
		   krb5_ccache,
		   krb5_creds *,
		   krb5_kdc_rep ** ));


krb5_error_code INTERFACE krb5_decode_kdc_rep
	PROTOTYPE((krb5_context,
		   krb5_data *,
		   const krb5_keyblock *,
		   const krb5_enctype,
		   krb5_kdc_rep ** ));

typedef krb5_error_code (INTERFACE *krb5_rdreq_key_proc) PROTOTYPE((krb5_context,
							  krb5_pointer, 
							  krb5_principal,
							  krb5_kvno,
							  krb5_keytype,
							  krb5_keyblock **));
	
krb5_error_code INTERFACE krb5_rd_req
	PROTOTYPE((krb5_context,
		   const krb5_data *,
		   krb5_const_principal,
		   const krb5_address *,
		   const char *,
		   krb5_rdreq_key_proc,
		   krb5_pointer,
		   krb5_rcache,
		   krb5_tkt_authent ** ));

krb5_error_code INTERFACE krb5_rd_req_decoded
	PROTOTYPE((krb5_context,
		   const krb5_ap_req *,
		   krb5_const_principal,
		   const krb5_address *,
		   const char *,
		   krb5_rdreq_key_proc,
		   krb5_pointer,
		   krb5_rcache,
		   krb5_tkt_authent ** ));

krb5_error_code INTERFACE krb5_kt_read_service_key
	PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_principal,
		   krb5_kvno,
		   krb5_keytype,
		   krb5_keyblock **));
krb5_error_code INTERFACE krb5_mk_safe
	PROTOTYPE((krb5_context,
		   const krb5_data *,
		   const krb5_cksumtype ,
		   const krb5_keyblock *,
		   const krb5_address *,
		   const krb5_address *,
		   krb5_int32, krb5_int32,
		   krb5_rcache,
		   krb5_data * ));
krb5_error_code INTERFACE krb5_mk_priv
	PROTOTYPE((krb5_context,
		   const krb5_data *,
		   const krb5_enctype,
		   const krb5_keyblock *,
		   const krb5_address *,
		   const krb5_address *,
		   krb5_int32, krb5_int32,
		   krb5_rcache,
		   krb5_pointer,
		   krb5_data * ));
krb5_error_code INTERFACE krb5_cc_register
	PROTOTYPE((krb5_context,
		   krb5_cc_ops *,
		   krb5_boolean ));

krb5_error_code INTERFACE krb5_sendauth 
	PROTOTYPE((krb5_context,
		   krb5_pointer,
		   char *,
		   krb5_principal,
		   krb5_principal,
		   krb5_flags,
		   krb5_checksum *,
		   krb5_creds *,
		   krb5_ccache,
		   krb5_int32 *,
		   krb5_keyblock **,
		   krb5_error **,
		   krb5_ap_rep_enc_part **,
		   krb5_creds **));
	
krb5_error_code INTERFACE krb5_recvauth PROTOTYPE((krb5_context,
		   krb5_pointer,
		   char *,
		   krb5_principal,
		   krb5_address *,
		   krb5_pointer,
		   krb5_rdreq_key_proc,
		   krb5_pointer,
		   char *,
		   krb5_int32, 
		   krb5_int32 *,
		   krb5_principal*,
		   krb5_ticket **,
		   krb5_authenticator **));

krb5_error_code INTERFACE krb5_walk_realm_tree
    	PROTOTYPE((krb5_context,
		   const krb5_data *,
	       const krb5_data *,
	       krb5_principal **,
	       int));

#define KRB5_REALM_BRANCH_CHAR '.'

#endif /* KRB5_FUNC_PROTO__ */
