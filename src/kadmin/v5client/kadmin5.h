/*
 * kadmin/v5client/kadmin5.h
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

/*
 * kadmin5.h	- Describe common interfaces between kadmin modules.
 */
#ifndef	KADMIN5_H__
#define	KADMIN5_H__

/*
 * Global data.
 */
extern int		exit_status;
extern krb5_context	kcontext;
extern char		*programname;
extern char		*requestname;
extern krb5_boolean	multiple;
extern char		*principal_name;
extern char		*password_prompt;
extern char		*ccname2use;
extern krb5_timestamp	ticket_life;
extern krb5_boolean	delete_ccache;

/*
 * Function prototypes.
 */
/* network.c */
void		print_proto_sreply
			KRB5_PROTOTYPE((krb5_int32, krb5_data *));
void		print_proto_error
			KRB5_PROTOTYPE((char *,
					krb5_int32,
					krb5_int32,
					krb5_data *));
krb5_error_code	net_connect();
void		net_disconnect
			KRB5_PROTOTYPE((krb5_boolean));
krb5_error_code	net_do_proto
			KRB5_PROTOTYPE((char *,
					char *,
					char *,
					krb5_int32,
					krb5_data *,
					krb5_int32 *,
					krb5_int32 *,
					krb5_data **,
					krb5_boolean));

/* convert.c */
char *		delta2string KRB5_PROTOTYPE((krb5_deltat));
char *		abs2string KRB5_PROTOTYPE((krb5_timestamp));
char *		dbflags2string KRB5_PROTOTYPE((krb5_flags));
char *		salt2string KRB5_PROTOTYPE((krb5_int32));
krb5_boolean	parse_princ_options KRB5_PROTOTYPE((int,
						    char **,
						    krb5_ui_4 *,
						    krb5_db_entry *));
void		help_princ_options();

/* kadmin5.c */
void		kadmin_show_principal KRB5_PROTOTYPE((int, char **));
void		kadmin_add_new_key KRB5_PROTOTYPE((int, char **));
void		kadmin_change_pwd KRB5_PROTOTYPE((int, char **));
void		kadmin_add_rnd_key KRB5_PROTOTYPE((int, char **));
void		kadmin_change_rnd KRB5_PROTOTYPE((int, char **));
void		kadmin_add_key_type KRB5_PROTOTYPE((int, char **));
void		kadmin_del_key_type KRB5_PROTOTYPE((int, char **));
void		kadmin_delete_entry KRB5_PROTOTYPE((int, char **));
void		kadmin_extract KRB5_PROTOTYPE((int, char **));
void		kadmin_extract_v4 KRB5_PROTOTYPE((int, char **));
void		kadmin_modify KRB5_PROTOTYPE((int, char **));
void		kadmin_rename KRB5_PROTOTYPE((int, char **));
void		kadmin_list KRB5_PROTOTYPE((int, char **));
void		kadmin_language KRB5_PROTOTYPE((int, char **));
void		kadmin_mime KRB5_PROTOTYPE((int, char **));
void		kadmin_cd KRB5_PROTOTYPE((int, char **));
void		kadmin_pwd KRB5_PROTOTYPE((int, char **));
char *		kadmin_startup KRB5_PROTOTYPE((int, char **));
int		kadmin_cleanup();
#endif	/* KADMIN5_H__ */

