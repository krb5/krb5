/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * KDC Database interface definitions.
 */


#ifndef KRB5_KDB5__
#define KRB5_KDB5__

/* this is the same structure as krb5_keyblock, but with a different name to
   enable compile-time catching of programmer confusion between encrypted &
   decrypted keys in the database */

typedef struct _krb5_encrypted_keyblock {
    krb5_keytype keytype;
    int length;
    krb5_octet *contents;
} krb5_encrypted_keyblock;

typedef struct _krb5_db_entry {
    krb5_principal principal;
    krb5_encrypted_keyblock key;
    krb5_kvno kvno;
    krb5_deltat	max_life;
    krb5_deltat	max_renewable_life;
    krb5_kvno mkvno;			/* master encryption key vno */
    krb5_timestamp expiration;
    krb5_principal mod_name;
    krb5_timestamp mod_date;
    krb5_flags attributes;
    krb5_int32 salt_type:8,
 	       salt_length:24;
    krb5_octet *salt;
    krb5_encrypted_keyblock alt_key;
    krb5_int32 alt_salt_type:8,
 	       alt_salt_length:24;
    krb5_octet *alt_salt;

    /* SANDIA Enhancement (Pre-Auth/Blacklist) */
    krb5_timestamp last_pwd_change;	
    krb5_timestamp last_success;
    krb5_kvno fail_auth_count;
    int lastreqid;
} krb5_db_entry;
  
#ifdef SANDIA	/* SANDIA Enhancement (Pre-Auth/Blacklist) */
#define KRB5_MAX_FAIL_COUNT		5
#endif

#define KRB5_KDB_SALTTYPE_NORMAL	0
#define KRB5_KDB_SALTTYPE_V4		1
#define KRB5_KDB_SALTTYPE_NOREALM	2
#define KRB5_KDB_SALTTYPE_ONLYREALM	3
#define KRB5_KDB_SALTTYPE_SPECIAL	4

#define	KRB5_KDB_DISALLOW_POSTDATED	0x00000001
#define	KRB5_KDB_DISALLOW_FORWARDABLE	0x00000002
#define	KRB5_KDB_DISALLOW_TGT_BASED	0x00000004
#define	KRB5_KDB_DISALLOW_RENEWABLE	0x00000008
#define	KRB5_KDB_DISALLOW_PROXIABLE	0x00000010
#define	KRB5_KDB_DISALLOW_DUP_SKEY	0x00000020
#define	KRB5_KDB_DISALLOW_ALL_TIX	0x00000040
#define	KRB5_KDB_REQUIRES_PRE_AUTH	0x00000080
#define KRB5_KDB_REQUIRES_HW_AUTH	0x00000100
#define	KRB5_KDB_REQUIRES_PWCHANGE	0x00000200
#define KRB5_KDB_DISALLOW_SVR		0x00001000

/* XXX depends on knowledge of krb5_parse_name() formats */
#define KRB5_KDB_M_NAME		"K/M"	/* Kerberos/Master */

#define KDB_CONVERT_KEY_TO_DB(in,out) krb5_kdb_encrypt_key(&master_encblock, in, out)
#define KDB_CONVERT_KEY_OUTOF_DB(in, out) krb5_kdb_decrypt_key(&master_encblock, in, out)

/* prompts used by default when reading the KDC password from the keyboard. */
#define KRB5_KDC_MKEY_1	"Enter KDC database master key:"
#define KRB5_KDC_MKEY_2	"Re-enter KDC database master key to verify:"

extern char *krb5_mkey_pwd_prompt1;
extern char *krb5_mkey_pwd_prompt2;


/* libkdb.spec */
krb5_error_code krb5_db_set_name
	PROTOTYPE((char * ));
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
krb5_error_code krb5_db_delete_principal
	PROTOTYPE((krb5_principal,
		   int * ));
krb5_error_code krb5_db_iterate
	PROTOTYPE((krb5_error_code (* ) PROTOTYPE((krb5_pointer,
						   krb5_db_entry *)),
		   krb5_pointer ));
krb5_error_code krb5_db_verify_master_key
	PROTOTYPE((krb5_principal, krb5_keyblock *, krb5_encrypt_block *));
krb5_error_code krb5_db_store_mkey PROTOTYPE((char *,
					      krb5_principal,
					      krb5_keyblock *));
krb5_error_code krb5_kdb_encrypt_key
	PROTOTYPE((krb5_encrypt_block *,
		   const krb5_keyblock *,
		   krb5_encrypted_keyblock *));
krb5_error_code krb5_kdb_decrypt_key
	PROTOTYPE((krb5_encrypt_block *,
		   const krb5_encrypted_keyblock *,
		   krb5_keyblock *));
krb5_error_code krb5_db_setup_mkey_name
	PROTOTYPE((const char *, const char *, char **, krb5_principal *));
krb5_error_code krb5_db_lock
	PROTOTYPE((int ));
krb5_error_code krb5_db_unlock
	PROTOTYPE ((void ));

/* need to play games here, since we take a pointer and the real thing,
   and it might be narrow. */
#ifdef NARROW_PROTOTYPES
krb5_error_code krb5_db_set_nonblocking
	PROTOTYPE((krb5_boolean,
		   krb5_boolean * ));
krb5_boolean krb5_db_set_lockmode
	PROTOTYPE((krb5_boolean ));
#else
krb5_error_code krb5_db_set_nonblocking
	PROTOTYPE((int, /* krb5_boolean */
		   krb5_boolean * ));
krb5_boolean krb5_db_set_lockmode
	PROTOTYPE((int /* krb5_boolean */ ));
#endif /* NARROW_PROTOTYPES */
#include <krb5/widen.h>

/* Only put things which don't have pointers to the narrow types in this
   section */

krb5_error_code	krb5_db_fetch_mkey
	PROTOTYPE((krb5_principal, krb5_encrypt_block *, krb5_boolean,
		   krb5_boolean, krb5_data *, krb5_keyblock * ));
#include <krb5/narrow.h>


#define KRB5_KDB_DEF_FLAGS	(KRB5_KDB_DISALLOW_DUP_SKEY)

/* XXX THIS REALLY BELONGS ELSEWHERE */
#define	TGTNAME	"krbtgt"

#endif /* KRB5_KDB5__ */

