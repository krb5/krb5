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
 * Function prototypes.
 */

/* adm_conn.c */
krb5_error_code INTERFACE krb5_adm_connect
	PROTOTYPE((krb5_context,
		   char *,
		   char *,
		   char *,
		   int *,
		   krb5_auth_context **,
		   krb5_ccache *));
void INTERFACE krb5_adm_disconnect
	PROTOTYPE((krb5_context,
		   int *,
		   krb5_auth_context *,
		   krb5_ccache));

/* adm_kw_dec.c */
krb5_error_code krb5_adm_proto_to_dbent
	PROTOTYPE((krb5_context,
		   krb5_int32,
		   krb5_data *,
		   krb5_ui_4 *,
		   krb5_db_entry *,
		   char **));

/* adm_kw_enc.c */
krb5_error_code krb5_adm_dbent_to_proto
	PROTOTYPE((krb5_context,
		   krb5_ui_4,
		   krb5_db_entry *,
		   char *,
		   krb5_int32 *,
		   krb5_data **));

/* adm_kt_dec.c */
krb5_error_code krb5_adm_proto_to_ktent
	PROTOTYPE((krb5_context,
		   krb5_int32,
		   krb5_data *,
		   krb5_keytab_entry *));

/* adm_kt_enc.c */
krb5_error_code krb5_adm_ktent_to_proto
	PROTOTYPE((krb5_context,
		   krb5_keytab_entry *,
		   krb5_int32 *,
		   krb5_data **));

/* adm_rw.c */
void krb5_free_adm_data
	PROTOTYPE((krb5_context,
		   krb5_int32,
		   krb5_data *));

krb5_error_code krb5_send_adm_cmd
	PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_auth_context *,
		   krb5_int32,
		   krb5_data *));
krb5_error_code krb5_send_adm_reply
	PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_auth_context *,
		   krb5_int32,
		   krb5_int32,
		   krb5_data *));
krb5_error_code krb5_read_adm_cmd
	PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_auth_context *,
		   krb5_int32 *,
		   krb5_data **));
krb5_error_code krb5_read_adm_reply
	PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_auth_context *,
		   krb5_int32 *,
		   krb5_int32 *,
		   krb5_data **));
#endif	/* KRB5_ADM_PROTO_H__ */
