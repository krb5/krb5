/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Declarations for policy.c
 */

#include <krb5/copyright.h>

#ifndef __KRB5_KDC_UTIL__
#define __KRB5_KDC_UTIL__

krb5_error_code check_hot_list PROTOTYPE((krb5_ticket *));
krb5_boolean realm_compare PROTOTYPE((krb5_data *, krb5_principal));
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
krb5_error_code kdc_process_tgs_req PROTOTYPE((krb5_kdc_req *,
					       const krb5_fulladdr *,
					       krb5_ticket **));

/* do_as_req.c */
krb5_error_code process_as_req PROTOTYPE((krb5_kdc_req *,
					  const krb5_fulladdr *,
					  krb5_data ** ));

/* do_tgs_req.c */
krb5_error_code process_tgs_req PROTOTYPE((krb5_kdc_req *,
					   const krb5_fulladdr *,
					   krb5_data ** ));
/* dispatch.c */
krb5_error_code dispatch PROTOTYPE((krb5_data *,
				    const krb5_fulladdr *,
				    krb5_data **));

/* network.c */
krb5_error_code listen_and_process PROTOTYPE((const char *));
krb5_error_code setup_network PROTOTYPE((const char *));
krb5_error_code closedown_network PROTOTYPE((const char *));


/* replay.c */
krb5_boolean kdc_check_lookaside PROTOTYPE((krb5_data *, krb5_data **));
void kdc_insert_lookaside PROTOTYPE((krb5_data *, krb5_data *));

/* which way to convert key? */
#define CONVERT_INTO_DB	0
#define CONVERT_OUTOF_DB 1

#define isflagset(flagfield, flag) (flagfield & (flag))
#define setflag(flagfield, flag) (flagfield |= (flag))
#define clear(flagfield, flag) (flagfield &= ~(flag))

#define realm_of_tgt(ticket) krb5_princ_realm(ticket->server)
#define process_v4(foo,bar,foobar)	KRB5KRB_AP_ERR_BADVERSION

#ifndef	min
#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

#endif /* __KRB5_KDC_UTIL__ */
