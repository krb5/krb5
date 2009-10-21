/*
 * kdc/kdc_util.h
 *
 * Portions Copyright (C) 2007 Apple Inc.
 * Copyright 1990, 2007 by the Massachusetts Institute of Technology.
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
 * 
 *
 * Declarations for policy.c
 */

#ifndef __KRB5_KDC_UTIL__
#define __KRB5_KDC_UTIL__

#include "kdb.h"
#include "kdb_ext.h"

typedef struct _krb5_fulladdr {
    krb5_address *	address;
    krb5_ui_4		port;
} krb5_fulladdr;

krb5_error_code check_hot_list (krb5_ticket *);
krb5_boolean realm_compare (krb5_const_principal, krb5_const_principal);
krb5_boolean is_local_principal(krb5_const_principal princ1);
krb5_boolean krb5_is_tgs_principal (krb5_const_principal);
krb5_error_code add_to_transited (krb5_data *,
					    krb5_data *,
					    krb5_principal,
					    krb5_principal,
					    krb5_principal);
krb5_error_code compress_transited (krb5_data *,
					      krb5_principal,
					      krb5_data *);
krb5_error_code concat_authorization_data (krb5_authdata **,
						     krb5_authdata **,
						     krb5_authdata ***);
krb5_error_code fetch_last_req_info (krb5_db_entry *,
					       krb5_last_req_entry ***);

krb5_error_code kdc_convert_key (krb5_keyblock *,
					   krb5_keyblock *,
					   int);
krb5_error_code kdc_process_tgs_req 
	(krb5_kdc_req *,
	           const krb5_fulladdr *,
	           krb5_data *,
	           krb5_ticket **,
		   krb5_db_entry *krbtgt,
		   int *nprincs,
	           krb5_keyblock **, krb5_pa_data **pa_tgs_req);

krb5_error_code kdc_get_server_key (krb5_ticket *, unsigned int,
				    krb5_boolean match_enctype,
				    krb5_db_entry *, int *,
				    krb5_keyblock **, krb5_kvno *);

int validate_as_request (krb5_kdc_req *, krb5_db_entry, 
					  krb5_db_entry, krb5_timestamp,
					  const char **);

int validate_forwardable(krb5_kdc_req *, krb5_db_entry, 
			 krb5_db_entry, krb5_timestamp,
			 const char **);

int validate_tgs_request (krb5_kdc_req *, krb5_db_entry, 
					  krb5_ticket *, krb5_timestamp,
					  const char **);

int fetch_asn1_field (unsigned char *, unsigned int, unsigned int,
				 krb5_data *);

int
dbentry_has_key_for_enctype (krb5_context context,
				       krb5_db_entry *client,
				       krb5_enctype enctype);
    
int
dbentry_supports_enctype (krb5_context context,
				    krb5_db_entry *client,
				    krb5_enctype enctype);

krb5_enctype
select_session_keytype (krb5_context context,
				  krb5_db_entry *server,
				  int nktypes,
				  krb5_enctype *ktypes);

krb5_error_code
get_salt_from_key (krb5_context, krb5_principal,
			     krb5_key_data *, krb5_data *);

void limit_string (char *name);

void
ktypes2str(char *s, size_t len, int nktypes, krb5_enctype *ktype);

void
rep_etypes2str(char *s, size_t len, krb5_kdc_rep *rep);

/* do_as_req.c */
krb5_error_code process_as_req (krb5_kdc_req *, krb5_data *,
					  const krb5_fulladdr *,
					  krb5_data ** );

/* do_tgs_req.c */
krb5_error_code process_tgs_req (krb5_data *,
					   const krb5_fulladdr *,
					   krb5_data ** );
/* dispatch.c */
krb5_error_code dispatch (krb5_data *,
				    const krb5_fulladdr *,
				    krb5_data **);

/* main.c */
krb5_error_code kdc_initialize_rcache (krb5_context, char *);

krb5_error_code setup_server_realm (krb5_principal);
void kdc_err(krb5_context call_context, errcode_t code, const char *fmt, ...);

/* network.c */
krb5_error_code listen_and_process (void);
krb5_error_code setup_network (void);
krb5_error_code closedown_network (void);

/* policy.c */
int against_local_policy_as (krb5_kdc_req *, krb5_db_entry,
					krb5_db_entry, krb5_timestamp,
					const char **);

int against_local_policy_tgs (krb5_kdc_req *, krb5_db_entry,
					krb5_ticket *, const char **);

/* kdc_preauth.c */
krb5_boolean enctype_requires_etype_info_2(krb5_enctype enctype);

const char * missing_required_preauth
    (krb5_db_entry *client, krb5_db_entry *server,
	       krb5_enc_tkt_part *enc_tkt_reply);
void get_preauth_hint_list (krb5_kdc_req * request,
				      krb5_db_entry *client,
				      krb5_db_entry *server,
				      krb5_data *e_data);
krb5_error_code load_preauth_plugins(krb5_context context);
krb5_error_code unload_preauth_plugins(krb5_context context);

krb5_error_code check_padata
    (krb5_context context, krb5_db_entry *client, krb5_data *req_pkt,
	       krb5_kdc_req *request, krb5_enc_tkt_part *enc_tkt_reply,
	       void **padata_context, krb5_data *e_data);
    
krb5_error_code return_padata
    (krb5_context context, krb5_db_entry *client,
	       krb5_data *req_pkt, krb5_kdc_req *request, krb5_kdc_rep *reply,
	       krb5_key_data *client_key, krb5_keyblock *encrypting_key,
	       void **padata_context);
    
krb5_error_code free_padata_context
    (krb5_context context, void **padata_context);

krb5_pa_data *find_pa_data
    (krb5_pa_data **padata, krb5_preauthtype pa_type);

krb5_error_code add_pa_data_element
    (krb5_context context,
		    krb5_pa_data *padata,
		    krb5_pa_data ***out_padata,
		    krb5_boolean copy);

/* kdc_authdata.c */
krb5_error_code load_authdata_plugins(krb5_context context);
krb5_error_code unload_authdata_plugins(krb5_context context);

krb5_error_code
handle_authdata (krb5_context context,
		 unsigned int flags,
		 krb5_db_entry *client,
		 krb5_db_entry *server,
		 krb5_db_entry *krbtgt,
		 krb5_keyblock *client_key,
		 krb5_keyblock *server_key,
		 krb5_data *req_pkt,
		 krb5_kdc_req *request,
		 krb5_const_principal for_user_princ,
		 krb5_enc_tkt_part *enc_tkt_request,
		 krb5_enc_tkt_part *enc_tkt_reply);

/* replay.c */
krb5_boolean kdc_check_lookaside (krb5_data *, krb5_data **);
void kdc_insert_lookaside (krb5_data *, krb5_data *);
void kdc_free_lookaside(krb5_context);

/* kdc_util.c */
krb5_error_code
get_principal_locked (krb5_context kcontext,
		      krb5_const_principal search_for,
		      krb5_db_entry *entries, int *nentries,
		      krb5_boolean *more);
krb5_error_code
get_principal (krb5_context kcontext,
	       krb5_const_principal search_for,
	       krb5_db_entry *entries, int *nentries, krb5_boolean *more);

krb5_boolean
include_pac_p(krb5_context context, krb5_kdc_req *request);

krb5_error_code return_svr_referral_data
   (krb5_context context,
		krb5_db_entry *server,
		krb5_enc_kdc_rep_part *reply_encpart);

krb5_error_code sign_db_authdata
    (krb5_context context,
		unsigned int flags,
		krb5_const_principal client_princ,
		krb5_db_entry *client,
		krb5_db_entry *server,
		krb5_db_entry *krbtgt,
		krb5_keyblock *client_key,
		krb5_keyblock *server_key,
		krb5_timestamp authtime,
		krb5_authdata **tgs_authdata,
		krb5_keyblock *session_key,
		krb5_authdata ***ret_authdata);

krb5_error_code kdc_process_s4u2self_req
	(krb5_context context,
		krb5_kdc_req *request,
		krb5_const_principal client_princ,
		const krb5_db_entry *server,
		krb5_keyblock *tgs_subkey,
		krb5_keyblock *tgs_session,
		krb5_timestamp kdc_time,
		krb5_pa_s4u_x509_user **s4u2self_req,
		krb5_db_entry *princ,
		int *nprincs,
		const char **status);

krb5_error_code kdc_make_s4u2self_rep
	(krb5_context context,
		krb5_keyblock *tgs_subkey,
		krb5_keyblock *tgs_session,
		krb5_pa_s4u_x509_user *req_s4u_user,
		krb5_kdc_rep *reply,
		krb5_enc_kdc_rep_part *reply_encpart);

krb5_error_code kdc_process_s4u2proxy_req
	(krb5_context context,
		krb5_kdc_req *request,
		const krb5_enc_tkt_part *t2enc,
		const krb5_db_entry *server,
		krb5_const_principal server_princ,
		krb5_const_principal proxy_princ,
		const char **status);

krb5_error_code kdc_check_transited_list
	(krb5_context context,
		const krb5_data *trans,
		const krb5_data *realm1,
		const krb5_data *realm2);

krb5_error_code audit_as_request
	(krb5_kdc_req *request,
		krb5_db_entry *client,
		krb5_db_entry *server,
		krb5_timestamp authtime,
		krb5_error_code errcode);

krb5_error_code audit_tgs_request
	(krb5_kdc_req *request,
		krb5_const_principal client,
		krb5_db_entry *server,
		krb5_timestamp authtime,
		krb5_error_code errcode);

krb5_error_code
validate_transit_path(krb5_context context,
	krb5_const_principal client,
		krb5_db_entry *server,
		      krb5_db_entry *krbtgt);


void
log_as_req(const krb5_fulladdr *from,
	   krb5_kdc_req *request, krb5_kdc_rep *reply,
	   krb5_db_entry *client, const char *cname,
	   krb5_db_entry *server, const char *sname,
	   krb5_timestamp authtime,
	   const char *status, krb5_error_code errcode, const char *emsg);
void
log_tgs_req(const krb5_fulladdr *from,
	    krb5_kdc_req *request, krb5_kdc_rep *reply,
	    const char *cname, const char *sname, const char *altcname,
	    krb5_timestamp authtime,
	    unsigned int c_flags, const char *s4u_name,
	    const char *status, krb5_error_code errcode, const char *emsg);
void log_tgs_alt_tgt(krb5_principal p);

/*Request state*/

struct kdc_request_state {
    krb5_keyblock *armor_key;
  krb5_keyblock *strengthen_key; 
    krb5_pa_data *cookie;
    krb5_int32 fast_options;
    krb5_int32 fast_internal_flags;
};

krb5_error_code kdc_make_rstate(struct kdc_request_state **out);
void kdc_free_rstate
(struct kdc_request_state *s);

/* FAST*/
enum krb5_fast_kdc_flags {
    KRB5_FAST_REPLY_KEY_USED = 0x1,
    KRB5_FAST_REPLY_KEY_REPLACED = 0x02,
};

krb5_error_code  kdc_find_fast
(krb5_kdc_req **requestptr,  krb5_data *checksummed_data,
 krb5_keyblock *tgs_subkey, krb5_keyblock *tgs_session,
 struct kdc_request_state *state);

krb5_error_code kdc_fast_response_handle_padata
(struct kdc_request_state *state,
 krb5_kdc_req *request,
 krb5_kdc_rep *rep,
 krb5_enctype enctype);
krb5_error_code kdc_fast_handle_error
(krb5_context context, struct kdc_request_state *state,
 krb5_kdc_req *request,
 krb5_pa_data  **in_padata, krb5_error *err);

krb5_error_code kdc_fast_handle_reply_key(struct kdc_request_state *state,
					  krb5_keyblock *existing_key,
					  krb5_keyblock **out_key);


krb5_error_code kdc_preauth_get_cookie(struct kdc_request_state *state,
				    krb5_pa_data **cookie);

 


#define isflagset(flagfield, flag) (flagfield & (flag))
#define setflag(flagfield, flag) (flagfield |= (flag))
#define clear(flagfield, flag) (flagfield &= ~(flag))

#ifndef	min
#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

#ifdef KRB5_USE_INET6
#define ADDRTYPE2FAMILY(X) \
  ((X) == ADDRTYPE_INET6 ? AF_INET6 : (X) == ADDRTYPE_INET ? AF_INET : -1)
#else
#define ADDRTYPE2FAMILY(X) \
  ((X) == ADDRTYPE_INET ? AF_INET : -1)
#endif

/* RFC 4120: KRB5KDC_ERR_KEY_TOO_WEAK
 * RFC 4556: KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED */
#define KRB5KDC_ERR_KEY_TOO_WEAK KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED

#endif /* __KRB5_KDC_UTIL__ */
