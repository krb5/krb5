/*
 * kadmin/v5server/kadm5_defs.h
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * kadmind5
 * Version 5 administrative daemon.
 */
#ifndef	KADM5_DEFS_H__
#define	KADM5_DEFS_H__

/*
 * Debug definitions.
 */
#define	DEBUG_SPROC	1
#define	DEBUG_OPERATION	2
#define	DEBUG_HOST	4
#define	DEBUG_REALM	8
#define	DEBUG_REQUESTS	16
#define	DEBUG_ACL	32
#define	DEBUG_PROTO	64
#define	DEBUG_CALLS	128
#define	DEBUG_NOSLAVES	256
#ifdef	DEBUG
#define	DPRINT(l1, cl, al)	if ((cl & l1) != 0) xprintf al
#else	/* DEBUG */
#define	DPRINT(l1, cl, al)
#endif	/* DEBUG */
#define	DLOG(l1, cl, msg)	if ((cl & l1) != 0)	\
					com_err(programname, 0, msg)

/*
 * Access control bits.
 */
#define	ACL_ADD_PRINCIPAL	1
#define	ACL_DELETE_PRINCIPAL	2
#define	ACL_MODIFY_PRINCIPAL	4
#define	ACL_CHANGEPW		8
#define	ACL_CHANGE_OWN_PW	16
#define	ACL_INQUIRE		32
#define	ACL_EXTRACT		64
#define	ACL_RENAME_PRINCIPAL	(ACL_ADD_PRINCIPAL+ACL_DELETE_PRINCIPAL)

#define	ACL_PRINCIPAL_MASK	(ACL_ADD_PRINCIPAL|ACL_DELETE_PRINCIPAL|\
				 ACL_MODIFY_PRINCIPAL)
#define	ACL_PASSWD_MASK		(ACL_CHANGEPW|ACL_CHANGE_OWN_PW)
#define	ACL_ALL_MASK		(ACL_ADD_PRINCIPAL	| \
				 ACL_DELETE_PRINCIPAL	| \
				 ACL_MODIFY_PRINCIPAL	| \
				 ACL_CHANGEPW		| \
				 ACL_CHANGE_OWN_PW	| \
				 ACL_INQUIRE		| \
				 ACL_EXTRACT)
/*
 * Subcodes.
 */
#define	KADM_BAD_ARGS		10
#define	KADM_BAD_CMD		11
#define	KADM_NO_CMD		12
#define	KADM_BAD_PRINC		20
#define	KADM_PWD_TOO_SHORT	21
#define	KADM_PWD_WEAK		22
#define	KADM_NOT_ALLOWED	100

/*
 * Reply status values.
 */
#define	KRB5_ADM_SUCCESS		0
#define	KRB5_ADM_CMD_UNKNOWN		1
#define	KRB5_ADM_PW_UNACCEPT		2
#define	KRB5_ADM_BAD_PW			3
#define	KRB5_ADM_NOT_IN_TKT		4
#define	KRB5_ADM_CANT_CHANGE		5
#define	KRB5_ADM_LANG_NOT_SUPPORTED	6

#define	KRB5_ADM_P_ALREADY_EXISTS	64
#define	KRB5_ADM_P_DOES_NOT_EXIST	65
#define	KRB5_ADM_NOT_AUTHORIZED		66
#define	KRB5_ADM_BAD_OPTION		67
#define	KRB5_ADM_VALUE_REQUIRED		68
#define	KRB5_ADM_SYSTEM_ERROR		69
#define	KRB5_ADM_KEY_DOES_NOT_EXIST	70
#define	KRB5_ADM_KEY_ALREADY_EXISTS	71
#define KRB5_ADM_BAD_DESKEY		72

/*
 * Inter-module function prototypes
 */

krb5_keytab key_keytab_id (void);
krb5_error_code key_open_db (krb5_context);
krb5_error_code key_close_db (krb5_context);

#if 0
/* srv_key.c */
krb5_error_code key_init
	(krb5_context,
			int,
			int,
			char *,
			int,
			char *,
			char *,
			char *,
			char *,
			krb5_int32,
			krb5_key_salt_tuple *);
void key_finish
	(krb5_context,
			int);
krb5_error_code key_string_to_keys
	(krb5_context,
			krb5_db_entry *,
			krb5_data *,
			krb5_int32,
			krb5_key_salt_tuple *,
			krb5_int32 *,
			krb5_key_data **);
krb5_error_code key_random_key
	(krb5_context,
			krb5_db_entry *,
			krb5_int32 *,
			krb5_key_data **);
krb5_error_code key_encrypt_keys
	(krb5_context,
			krb5_db_entry *,
			krb5_int32 *,
			krb5_key_data *,
			krb5_key_data **);
krb5_error_code key_decrypt_keys
	(krb5_context,
			krb5_db_entry *,
			krb5_int32 *,
			krb5_key_data *,
			krb5_key_data **);
krb5_boolean key_pwd_is_weak
	(krb5_context,
			krb5_db_entry *,
			krb5_data *);
krb5_db_entry *key_master_entry();
char *key_master_realm();
krb5_keyblock *key_admin_key();
krb5_encrypt_block *key_master_encblock();
void key_free_key_data (krb5_key_data *,
				       krb5_int32);
krb5_error_code key_dbent_to_keysalts
	(krb5_db_entry *,
			krb5_int32 *,
			krb5_key_salt_tuple **);
krb5_error_code key_update_tl_attrs
	(krb5_context,
			krb5_db_entry *,
			krb5_principal,
			krb5_boolean);

/* srv_acl.c */
krb5_error_code acl_init
	(krb5_context,
		   int,
		   char *);
void acl_finish
	(krb5_context,
		   int);
krb5_boolean acl_op_permitted
	(krb5_context,
		   krb5_principal,
		   krb5_int32,
		   char *);

#endif

/* srv_output.c */
krb5_error_code output_init
	(krb5_context,
		   int,
		   char *,
		   krb5_boolean);
void output_finish
	(krb5_context,
		   int);
krb5_boolean output_lang_supported
	(char *);
char *output_krb5_errmsg
	(char *,
		   krb5_boolean,
		   krb5_int32);
char *output_adm_error
	(char *,
		   krb5_boolean,
		   krb5_int32,
		   krb5_int32,
		   krb5_int32,
		   krb5_data *);

/* srv_net.c */
krb5_error_code net_init
	(krb5_context,
		   char *,
		   int,
		   krb5_int32);
void net_finish
	(krb5_context,
		   int);
krb5_error_code net_dispatch
	(krb5_context, int);
krb5_principal net_server_princ (void);

/* proto_serv.c */
krb5_error_code proto_init
	(krb5_context,
		   int,
		   int);
void proto_finish
	(krb5_context,
		   int);
krb5_error_code proto_serv
	(krb5_context,
		   krb5_int32,
		   int,
		   void *,
		   void *);

krb5_int32 passwd_change
	(krb5_context,
		   int,
		   krb5_auth_context,
		   krb5_ticket *,
		   krb5_data *,
		   krb5_data *,
		   krb5_int32 *);

krb5_int32 pwd_change
	(krb5_context,
		   int,
		   krb5_auth_context,
		   krb5_ticket *,
		   krb5_data *,
		   krb5_data *,
		   char [],
		   unsigned int);

#if 0

/* passwd.c */
krb5_int32 passwd_check
	(krb5_context,
		   int,
		   krb5_auth_context,
		   krb5_ticket *,
		   krb5_data *,
		   krb5_int32 *);
krb5_int32 passwd_change
	(krb5_context,
		   int,
		   krb5_auth_context,
		   krb5_ticket *,
		   krb5_data *,
		   krb5_data *,
		   krb5_int32 *);
krb5_boolean passwd_check_npass_ok
	(krb5_context,
		   int,
		   krb5_principal,
		   krb5_db_entry *,
		   krb5_data *,
		   krb5_int32 *);
krb5_boolean passwd_check_opass_ok
	(krb5_context,
		   int,
		   krb5_principal,
		   krb5_db_entry *,
		   krb5_data *);

/* admin.c */
krb5_error_code admin_add_principal
	(krb5_context,
		   int,
		   krb5_ticket *,
		   krb5_int32,
		   krb5_data *);
krb5_error_code admin_delete_principal
	(krb5_context,
		   int,
		   krb5_ticket *,
		   krb5_data *);
krb5_error_code admin_rename_principal
	(krb5_context,
		   int,
		   krb5_ticket *,
		   krb5_data *,
		   krb5_data *);
krb5_error_code admin_modify_principal
	(krb5_context,
		   int,
		   krb5_ticket *,
		   krb5_int32,
		   krb5_data *);
krb5_error_code admin_change_opw
	(krb5_context,
		   int,
		   krb5_ticket *,
		   krb5_data *,
		   krb5_data *);
krb5_error_code admin_change_orandpw
	(krb5_context,
		   int,
		   krb5_ticket *,
		   krb5_data *);
krb5_error_code admin_inquire
	(krb5_context,
		   int,
		   krb5_ticket *,
		   krb5_data *,
		   krb5_int32 *,
		   krb5_data **);
krb5_error_code admin_extract_key
	(krb5_context,
		   int,
		   krb5_ticket *,
		   krb5_data *,
		   krb5_data *,
		   krb5_int32 *,
		   krb5_data **);
krb5_error_code admin_add_key
	(krb5_context,
			int,
			krb5_ticket *,
			krb5_int32,
			krb5_data *);
krb5_error_code admin_delete_key
	(krb5_context,
			int,
			krb5_ticket *,
			krb5_int32,
			krb5_data *);
void admin_init (krb5_deltat,
				krb5_deltat,
				krb5_boolean,
				krb5_timestamp,
				krb5_boolean,
				krb5_flags);
#endif

#endif	/* KADM5_DEFS_H__ */
