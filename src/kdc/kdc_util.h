/*
 * kdc/kdc_util.h
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * Declarations for policy.c
 */

#ifndef __KRB5_KDC_UTIL__
#define __KRB5_KDC_UTIL__

typedef struct _krb5_fulladdr {
    krb5_address *	address;
    krb5_ui_4		port;
} krb5_fulladdr;

krb5_error_code check_hot_list PROTOTYPE((krb5_ticket *));
krb5_boolean realm_compare PROTOTYPE((krb5_principal, krb5_principal));
krb5_boolean krb5_is_tgs_principal PROTOTYPE((krb5_principal));
krb5_error_code add_to_transited PROTOTYPE((krb5_data *,
					    krb5_data *,
					    krb5_principal,
					    krb5_principal,
					    krb5_principal));
krb5_error_code compress_transited PROTOTYPE((krb5_data *,
					      krb5_principal,
					      krb5_data *));
krb5_error_code concat_authorization_data PROTOTYPE((krb5_authdata **,
						     krb5_authdata **,
						     krb5_authdata ***));
krb5_error_code fetch_last_req_info PROTOTYPE((krb5_db_entry *,
					       krb5_last_req_entry ***));

krb5_error_code kdc_convert_key PROTOTYPE((krb5_keyblock *,
					   krb5_keyblock *,
					   int));
krb5_error_code kdc_process_tgs_req 
	PROTOTYPE((krb5_kdc_req *,
	           const krb5_fulladdr *,
	           krb5_data *,
	           krb5_ticket **,
	           krb5_keyblock **));

krb5_error_code kdc_get_server_key PROTOTYPE((krb5_ticket *,
					      krb5_keyblock **,
					      krb5_kvno *));

int validate_as_request PROTOTYPE((krb5_kdc_req *, krb5_db_entry, 
					  krb5_db_entry, krb5_timestamp,
					  char **));

int validate_tgs_request PROTOTYPE((krb5_kdc_req *, krb5_db_entry, 
					  krb5_ticket *, krb5_timestamp,
					  char **));

int fetch_asn1_field PROTOTYPE((unsigned char *, unsigned int, unsigned int,
				 krb5_data *));

/* do_as_req.c */
krb5_error_code process_as_req PROTOTYPE((krb5_kdc_req *,
					  const krb5_fulladdr *,
					  int,
					  krb5_data ** ));

/* do_tgs_req.c */
krb5_error_code process_tgs_req PROTOTYPE((krb5_data *,
					   const krb5_fulladdr *,
					   int, 
					   krb5_data ** ));
/* dispatch.c */
krb5_error_code dispatch PROTOTYPE((krb5_data *,
				    const krb5_fulladdr *,
				    int,
				    krb5_data **));

/* main.c */
krb5_error_code kdc_initialize_rcache PROTOTYPE((krb5_context, char *));

/* network.c */
krb5_error_code listen_and_process PROTOTYPE((const char *));
krb5_error_code setup_network PROTOTYPE((const char *,
					 int *,
					 int *));
krb5_error_code closedown_network PROTOTYPE((const char *));
void process_packet PROTOTYPE((int, const char *, int));

/* policy.c */
int against_local_policy_as PROTOTYPE((krb5_kdc_req *, krb5_db_entry,
					krb5_db_entry, krb5_timestamp,
					char **));

int against_local_policy_tgs PROTOTYPE((krb5_kdc_req *, krb5_db_entry,
					krb5_ticket *, char **));

/* kdc_preauth.c */
const char * missing_required_preauth
    PROTOTYPE((krb5_db_entry *client, krb5_db_entry *server,
	       krb5_enc_tkt_part *enc_tkt_reply));
void get_preauth_hint_list PROTOTYPE((krb5_db_entry *client,
				     krb5_db_entry *server,
				     krb5_data *e_data));
    
/* replay.c */
krb5_boolean kdc_check_lookaside PROTOTYPE((krb5_data *, krb5_data **));
void kdc_insert_lookaside PROTOTYPE((krb5_data *, krb5_data *));

/* which way to convert key? */
#define CONVERT_INTO_DB	0
#define CONVERT_OUTOF_DB 1

#define isflagset(flagfield, flag) (flagfield & (flag))
#define setflag(flagfield, flag) (flagfield |= (flag))
#define clear(flagfield, flag) (flagfield &= ~(flag))

#ifdef KRB5_KRB4_COMPAT
krb5_error_code process_v4 PROTOTYPE((const krb5_data *,
				      const krb5_fulladdr *,
				      int is_secondary,
				      krb5_data **));
#else
#define process_v4(foo,bar,quux,foobar)	KRB5KRB_AP_ERR_BADVERSION
#endif

#ifndef	min
#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

#endif /* __KRB5_KDC_UTIL__ */
