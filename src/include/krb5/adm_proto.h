/*
 * include/krb5/adm_proto.h
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 */
#ifndef	KRB5_ADM_PROTO_H__
#define	KRB5_ADM_PROTO_H__

/*
 * This is ugly, but avoids having to include k5-int or kdb.h for this.
 */
#ifndef	KRB5_KDB5__
struct _krb5_db_entry;
typedef struct _krb5_db_entry krb5_db_entry;
#endif	/* KRB5_KDB5__ */

/* Ditto for adm.h */
#ifndef	KRB5_ADM_H__
struct ___krb5_realm_params;
typedef struct ___krb5_realm_params krb5_realm_params;

struct ___krb5_key_salt_tuple;
typedef struct ___krb5_key_salt_tuple krb5_key_salt_tuple;
#endif	/* KRB5_ADM_H__ */

/*
 * Function prototypes.
 */

/* adm_conn.c */
krb5_error_code INTERFACE krb5_adm_connect
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   char *,
		   char *,
		   int *,
		   krb5_auth_context *,
		   krb5_ccache *,
		   char *,
		   krb5_timestamp));
void INTERFACE krb5_adm_disconnect
	KRB5_PROTOTYPE((krb5_context,
		   int *,
		   krb5_auth_context,
		   krb5_ccache));

#if ! defined(_WINDOWS)
/* adm_kw_dec.c */
krb5_error_code krb5_adm_proto_to_dbent
	KRB5_PROTOTYPE((krb5_context,
		   krb5_int32,
		   krb5_data *,
		   krb5_ui_4 *,
		   krb5_db_entry *,
		   char **));

/* adm_kw_enc.c */
krb5_error_code krb5_adm_dbent_to_proto
	KRB5_PROTOTYPE((krb5_context,
		   krb5_ui_4,
		   krb5_db_entry *,
		   char *,
		   krb5_int32 *,
		   krb5_data **));
#endif /* _WINDOWS */

/* adm_kt_dec.c */
krb5_error_code krb5_adm_proto_to_ktent
	KRB5_PROTOTYPE((krb5_context,
		   krb5_int32,
		   krb5_data *,
		   krb5_keytab_entry *));

/* adm_kt_enc.c */
krb5_error_code krb5_adm_ktent_to_proto
	KRB5_PROTOTYPE((krb5_context,
		   krb5_keytab_entry *,
		   krb5_int32 *,
		   krb5_data **));

/* adm_rw.c */
void INTERFACE krb5_free_adm_data
	KRB5_PROTOTYPE((krb5_context,
		   krb5_int32,
		   krb5_data *));

krb5_error_code INTERFACE krb5_send_adm_cmd
	KRB5_PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_auth_context,
		   krb5_int32,
		   krb5_data *));
krb5_error_code krb5_send_adm_reply
	KRB5_PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_auth_context,
		   krb5_int32,
		   krb5_int32,
		   krb5_data *));
krb5_error_code krb5_read_adm_cmd
	KRB5_PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_auth_context,
		   krb5_int32 *,
		   krb5_data **));
krb5_error_code INTERFACE krb5_read_adm_reply
	KRB5_PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_auth_context,
		   krb5_int32 *,
		   krb5_int32 *,
		   krb5_data **));

/* logger.c */
krb5_error_code krb5_klog_init
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   char *,
		   krb5_boolean));
void krb5_klog_close KRB5_PROTOTYPE((krb5_context));
int krb5_klog_syslog KRB5_PROTOTYPE((int, const char *, ...));

/* alt_prof.c */
krb5_error_code krb5_aprof_init
	KRB5_PROTOTYPE((char *, char *, krb5_pointer *));
krb5_error_code krb5_aprof_getvals
	KRB5_PROTOTYPE((krb5_pointer, const char **, char ***));
krb5_error_code krb5_aprof_get_deltat
	KRB5_PROTOTYPE((krb5_pointer,
			const char **,
			krb5_boolean,
			krb5_deltat *));
krb5_error_code krb5_aprof_get_string
	KRB5_PROTOTYPE((krb5_pointer, const char **, krb5_boolean, char **));
krb5_error_code krb5_aprof_get_int32
	KRB5_PROTOTYPE((krb5_pointer,
			const char **,
			krb5_boolean,
			krb5_int32 *));
krb5_error_code krb5_aprof_finish KRB5_PROTOTYPE((krb5_pointer));

krb5_error_code krb5_read_realm_params KRB5_PROTOTYPE((krb5_context,
						       char *,
						       char *,
						       char *,
						       krb5_realm_params **));
krb5_error_code krb5_free_realm_params KRB5_PROTOTYPE((krb5_context,
						       krb5_realm_params *));

/* str_conv.c */
krb5_error_code
krb5_string_to_keytype KRB5_PROTOTYPE((char *, krb5_keytype *));
krb5_error_code
krb5_string_to_salttype KRB5_PROTOTYPE((char *, krb5_int32 *));
krb5_error_code
krb5_string_to_enctype KRB5_PROTOTYPE((char *, krb5_enctype *));
krb5_error_code
krb5_string_to_cksumtype KRB5_PROTOTYPE((char *, krb5_cksumtype *));
krb5_error_code
krb5_string_to_flags KRB5_PROTOTYPE((char *,
				     const char *,
				     const char *,
				     krb5_flags *));
krb5_error_code
krb5_string_to_timestamp KRB5_PROTOTYPE((char *, krb5_timestamp *));
krb5_error_code
krb5_string_to_deltat KRB5_PROTOTYPE((char *, krb5_deltat *));
krb5_error_code
krb5_keytype_to_string KRB5_PROTOTYPE((krb5_keytype, char *, size_t));
krb5_error_code
krb5_salttype_to_string KRB5_PROTOTYPE((krb5_int32, char *, size_t));
krb5_error_code
krb5_enctype_to_string KRB5_PROTOTYPE((krb5_enctype, char *, size_t));
krb5_error_code
krb5_cksumtype_to_string KRB5_PROTOTYPE((krb5_cksumtype, char *, size_t));
krb5_error_code
krb5_flags_to_string KRB5_PROTOTYPE((krb5_flags,
				     const char *,
				     char *,
				     size_t));
krb5_error_code
krb5_timestamp_to_string KRB5_PROTOTYPE((krb5_timestamp, char *, size_t));
krb5_error_code
krb5_deltat_to_string KRB5_PROTOTYPE((krb5_deltat, char *, size_t));

/* keysalt.c */
krb5_boolean
krb5_keysalt_is_present KRB5_PROTOTYPE((krb5_key_salt_tuple *,
					krb5_int32,
					krb5_keytype,
					krb5_int32));
krb5_error_code
krb5_keysalt_iterate
	KRB5_PROTOTYPE((krb5_key_salt_tuple *,
			krb5_int32,
			krb5_boolean,
			krb5_error_code (*)
				KRB5_NPROTOTYPE((krb5_key_salt_tuple *,
						 krb5_pointer)),
			krb5_pointer));
				     
krb5_error_code
krb5_string_to_keysalts KRB5_PROTOTYPE((char *,
					const char *,
					const char *,
					krb5_boolean,
					krb5_key_salt_tuple **,
					krb5_int32 *));
#endif	/* KRB5_ADM_PROTO_H__ */
