/*
 * admin/edit/kdb5_edit.h
 *
 * Copyright 1992 by the Massachusetts Institute of Technology.
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

#define REALM_SEP	'@'
#define REALM_SEP_STR	"@"

extern char *progname;
extern char *Err_no_database;

struct mblock {
    krb5_deltat max_life;
    krb5_deltat max_rlife;
    krb5_timestamp expiration;
    krb5_flags flags;
    krb5_kvno mkvno;
};

void add_key 
	PROTOTYPE((char const *, char const *, 
		   krb5_const_principal, const krb5_keyblock *, 
		   krb5_kvno, krb5_keysalt *));
void enter_pwd_key
	PROTOTYPE((char *, char *, krb5_const_principal,
		   krb5_const_principal, krb5_kvno, int));
int set_dbname_help
	PROTOTYPE((char *, char *));

char *kdb5_edit_Init PROTOTYPE((int, char **));
