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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Store the master database key in a file.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "com_err.h"
#include <kadm5/admin.h>
#include <stdio.h>
#include "kdb5_util.h"

extern krb5_keyblock master_keyblock;
extern krb5_principal master_princ;
extern kadm5_config_params global_params;

extern int exit_status;
extern int close_policy_db;

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

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    /* Tell upwards to close the policy db cause we don't */
    close_policy_db = 1; 

    krb5_init_context(&context);

    dbname = global_params.dbname;
    realm = global_params.realm;
    mkey_name = global_params.mkey_name;
    keyfile = global_params.stash_file;

    optind = 1;
    while ((optchar = getopt(argc, argv, "f:")) != -1) {
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

    if (!krb5_c_valid_enctype(master_keyblock.enctype)) {
	char tmp[32];
	if (krb5_enctype_to_string(master_keyblock.enctype, tmp, sizeof(tmp)))
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP,
		    "while setting up enctype %d", master_keyblock.enctype);
	else
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP, tmp);
	exit_status++; return; 
    }

    retval = krb5_db_set_name(context, dbname);
    if (retval) {
	com_err(argv[0], retval, "while setting active database to '%s'",
		dbname);
	exit_status++; return; 
    }

    /* assemble & parse the master key name */
    retval = krb5_db_setup_mkey_name(context, mkey_name, realm, 
				     &mkey_fullname, &master_princ);
    if (retval) {
	com_err(argv[0], retval, "while setting up master key name");
	exit_status++; return; 
    }

    retval = krb5_db_init(context);
    if (retval) {
	com_err(argv[0], retval, "while initializing the database '%s'",
		dbname);
	exit_status++; return; 
    }

    /* TRUE here means read the keyboard, but only once */
    retval = krb5_db_fetch_mkey(context, master_princ,
				master_keyblock.enctype,
				TRUE, FALSE, (char *) NULL,
				0, &master_keyblock);
    if (retval) {
	com_err(argv[0], retval, "while reading master key");
	(void) krb5_db_fini(context);
	exit_status++; return; 
    }

    retval = krb5_db_verify_master_key(context, master_princ, 
				       &master_keyblock);
    if (retval) {
	com_err(argv[0], retval, "while verifying master key");
	(void) krb5_db_fini(context);
	exit_status++; return; 
    }	

    retval = krb5_db_store_mkey(context, keyfile, master_princ, 
				&master_keyblock);
    if (retval) {
	com_err(argv[0], errno, "while storing key");
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	(void) krb5_db_fini(context);
	exit_status++; return; 
    }
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);

    retval = krb5_db_fini(context);
    if (retval) {
	com_err(argv[0], retval, "closing database '%s'", dbname);
	exit_status++; return; 
    }

    krb5_free_context(context);
    exit_status = 0;
    return; 
}
