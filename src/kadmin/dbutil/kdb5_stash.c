/*
 * admin/stash/kdb5_stash.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 *
 * Store the master database key in a file.
 */

#include "k5-int.h"
#include "com_err.h"
#include <kadm5/admin.h>
#include <stdio.h>

extern int errno;

extern krb5_keyblock master_keyblock;
extern krb5_principal master_princ;
extern krb5_encrypt_block master_encblock;
extern kadm5_config_params global_params;

extern int exit_status;

void
kdb5_stash(argc, argv)
int argc;
char *argv[];
{
    extern char *optarg;
    extern int optind;
    int optchar;
    krb5_error_code retval;
    char *dbname = (char *) NULL;
    char *realm = 0;
    char *mkey_name = 0;
    char *mkey_fullname;
    char *keyfile = 0;
    krb5_context context;

    int enctypedone = 0;

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    krb5_init_context(&context);
    krb5_init_ets(context);

    dbname = global_params.dbname;
    realm = global_params.realm;
    mkey_name = global_params.mkey_name;
    keyfile = global_params.stash_file;

    optind = 1;
    while ((optchar = getopt(argc, argv, "f:")) != EOF) {
	switch(optchar) {
	case 'f':
	    keyfile = optarg;
	    break;
	case '?':
	default:
	    usage();
	    return;
	}
    }

    if (!valid_enctype(master_keyblock.enctype)) {
	char tmp[32];
	if (krb5_enctype_to_string(master_keyblock.enctype, tmp, sizeof(tmp)))
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP,
		    "while setting up enctype %d", master_keyblock.enctype);
	else
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP, tmp);
	exit_status++; return; 
    }

    krb5_use_enctype(context, &master_encblock, master_keyblock.enctype);

    if (retval = krb5_db_set_name(context, dbname)) {
	com_err(argv[0], retval, "while setting active database to '%s'",
		dbname);
	exit_status++; return; 
    }

    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(context, mkey_name, realm, 
					 &mkey_fullname, &master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
	exit_status++; return; 
    }

    if (retval = krb5_db_init(context)) {
	com_err(argv[0], retval, "while initializing the database '%s'",
		dbname);
	exit_status++; return; 
    }

    /* TRUE here means read the keyboard, but only once */
    if (retval = krb5_db_fetch_mkey(context, master_princ, &master_encblock,
				    TRUE, FALSE, (char *) NULL,
				    0, &master_keyblock)) {
	com_err(argv[0], retval, "while reading master key");
	(void) krb5_db_fini(context);
	exit_status++; return; 
    }
    if (retval = krb5_db_verify_master_key(context, master_princ, 
					   &master_keyblock,&master_encblock)) {
	com_err(argv[0], retval, "while verifying master key");
	(void) krb5_db_fini(context);
	exit_status++; return; 
    }	
    if (retval = krb5_db_store_mkey(context, keyfile, master_princ, 
				    &master_keyblock)) {
	com_err(argv[0], errno, "while storing key");
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	(void) krb5_db_fini(context);
	exit_status++; return; 
    }
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    if (retval = krb5_db_fini(context)) {
	com_err(argv[0], retval, "closing database '%s'", dbname);
	exit_status++; return; 
    }

    exit_status = 0;
    return; 
}
