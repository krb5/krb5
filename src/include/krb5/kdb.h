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
 * KDC Database interface definitions.
 */

#include <krb5/copyright.h>

#ifndef KRB5_KDB5__
#define KRB5_KDB5__

typedef struct _krb5_db_entry {
    krb5_principal principal;
    krb5_keyblock key;
    krb5_kvno kvno;
    krb5_deltat	max_life;
    krb5_deltat	max_renewable_life;
    krb5_kvno mkvno;			/* master encryption key vno */
    krb5_timestamp expiration;
    krb5_principal mod_name;
    krb5_timestamp mod_date;
    krb5_flags attributes;
} krb5_db_entry;

#define	KRB5_KDB_DISALLOW_POSTDATED	0x00000001
#define	KRB5_KDB_DISALLOW_FORWARDABLE	0x00000002
#define	KRB5_KDB_DISALLOW_TGT_BASED	0x00000004
#define	KRB5_KDB_DISALLOW_RENEWABLE	0x00000008
#define	KRB5_KDB_DISALLOW_PROXIABLE	0x00000010
#define	KRB5_KDB_DISALLOW_DUP_SKEY	0x00000020
#define	KRB5_KDB_DISALLOW_ALL_TIX	0x00000040

/* XXX depends on knowledge of krb5_parse_name() formats */
#define KRB5_KDB_M_NAME		"K/M"	/* Kerberos/Master */

/* prompts used by default when reading the KDC password from the keyboard. */
#define KRB5_KDC_MKEY_1	"Enter KDC database master key:"
#define KRB5_KDC_MKEY_2	"Re-enter KDC database master key to verify:"

extern char *krb5_mkey_pwd_prompt1;
extern char *krb5_mkey_pwd_prompt2;


/* libkdb.spec */
krb5_error_code krb5_db_set_name
	PROTOTYPE((char * ));
krb5_error_code krb5_db_set_nonblocking
	PROTOTYPE((krb5_boolean,
		   krb5_boolean * ));
krb5_error_code krb5_db_init
	PROTOTYPE((void ));
krb5_error_code krb5_db_fini
	PROTOTYPE((void ));
krb5_error_code krb5_db_get_age
	PROTOTYPE((char *,
		   time_t * ));
krb5_error_code krb5_db_create
	PROTOTYPE((char * ));
krb5_error_code krb5_db_rename
	PROTOTYPE((char *,
		   char * ));
krb5_error_code krb5_db_get_principal
	PROTOTYPE((krb5_principal ,
		   krb5_db_entry *,
		   int *,
		   krb5_boolean * ));
void krb5_db_free_principal
	PROTOTYPE((krb5_db_entry *,
		   int  ));
krb5_error_code krb5_db_put_principal
	PROTOTYPE((krb5_db_entry *,
		   int * ));
krb5_error_code krb5_db_iterate
	PROTOTYPE((krb5_error_code (* ) PROTOTYPE((krb5_pointer,
						   krb5_db_entry *)),
		   krb5_pointer ));
krb5_error_code krb5_db_verify_master_key
	PROTOTYPE((krb5_principal, krb5_keyblock *, krb5_encrypt_block *));
krb5_error_code	krb5_db_fetch_mkey
	PROTOTYPE((krb5_principal, krb5_encrypt_block *, krb5_boolean,
		   krb5_keyblock * ));
krb5_error_code krb5_db_store_mkey PROTOTYPE((char *,
					      krb5_principal,
					      krb5_keyblock *));
krb5_error_code krb5_kdb_encrypt_key
	PROTOTYPE((krb5_encrypt_block *,
		   const krb5_keyblock *,
		   krb5_keyblock *));
krb5_error_code krb5_kdb_decrypt_key
	PROTOTYPE((krb5_encrypt_block *,
		   const krb5_keyblock *,
		   krb5_keyblock *));
krb5_error_code krb5_db_setup_mkey_name
	PROTOTYPE((const char *, const char *, char **, krb5_principal *));

/* XXX these belong in some config file */
#define	KRB5_KDB_MAX_LIFE	(60*60*24) /* one day */
#define	KRB5_KDB_MAX_RLIFE	(60*60*24*7) /* one week */
#define	KRB5_KDB_EXPIRATION	2145830400 /* Thu Jan  1 00:00:00 2038 UTC */

#define KRB5_KDB_DEF_FLAGS	(KRB5_KDB_DISALLOW_DUP_SKEY)

/* XXX THIS REALLY BELONGS ELSEWHERE */
#define	TGTNAME	"krbtgt"

#endif /* KRB5_KDB5__ */
