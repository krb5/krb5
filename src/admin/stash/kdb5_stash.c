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
#include "adm.h"
#include "adm_proto.h"
#include <stdio.h>

extern int errno;

krb5_keyblock master_keyblock;
krb5_principal master_princ;
krb5_encrypt_block master_encblock;

static void
usage(who, status)
char *who;
int status;
{
    fprintf(stderr, "usage: %s [-d dbpathname] [-r realmname] [-k keytype]\n\
\t[-M mkeyname] [-f keyfile]\n",
	    who);
    exit(status);
}


void
main(argc, argv)
int argc;
char *argv[];
{
    extern char *optarg;
    int optchar;
    krb5_error_code retval;
    char *dbname = (char *) NULL;
    char *realm = 0;
    char *mkey_name = 0;
    char *mkey_fullname;
    char *keyfile = 0;
    krb5_context context;
    krb5_realm_params *rparams;

    int keytypedone = 0;

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    krb5_init_context(&context);
    krb5_init_ets(context);

    while ((optchar = getopt(argc, argv, "d:r:k:M:e:f:")) != EOF) {
	switch(optchar) {
	case 'd':			/* set db name */
	    dbname = optarg;
	    break;
	case 'r':
	    realm = optarg;
	    break;
	case 'k':
	    if (!krb5_string_to_keytype(optarg, &master_keyblock.keytype))
		keytypedone++;
	    else
		com_err(argv[0], 0, "%s is an invalid keytype", optarg);
	    break;
	case 'M':			/* master key name in DB */
	    mkey_name = optarg;
	    break;
	case 'f':
	    keyfile = optarg;
	    break;
	case '?':
	default:
	    usage(argv[0], 1);
	    /*NOTREACHED*/
	}
    }

    /*
     * Attempt to read the KDC profile.  If we do, then read appropriate values
     * from it and augment values supplied on the command line.
     */
    if (!(retval = krb5_read_realm_params(context,
					  realm,
					  (char *) NULL,
					  (char *) NULL,
					  &rparams))) {
	/* Get the value for the database */
	if (rparams->realm_dbname && !dbname)
	    dbname = strdup(rparams->realm_dbname);

	/* Get the value for the master key name */
	if (rparams->realm_mkey_name && !mkey_name)
	    mkey_name = strdup(rparams->realm_mkey_name);

	/* Get the value for the master key type */
	if (rparams->realm_keytype_valid && !keytypedone) {
	    master_keyblock.keytype = rparams->realm_keytype;
	    keytypedone++;
	}

	/* Get the value for the stash file */
	if (rparams->realm_stash_file && !keyfile)
	    keyfile = strdup(rparams->realm_stash_file);

	krb5_free_realm_params(context, rparams);
    }

    if (!dbname)
	dbname = DEFAULT_KDB_FILE;

    if (!keytypedone)
	master_keyblock.keytype = DEFAULT_KDC_KEYTYPE;

    if (!valid_keytype(master_keyblock.keytype)) {
	char tmp[32];
	if (krb5_keytype_to_string(master_keyblock.keytype, tmp, sizeof(tmp)))
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP,
		    "while setting up keytype %d", master_keyblock.keytype);
	else
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP, tmp);
	exit(1);
    }

    krb5_use_keytype(context, &master_encblock, master_keyblock.keytype);

    if (retval = krb5_db_set_name(context, dbname)) {
	com_err(argv[0], retval, "while setting active database to '%s'",
		dbname);
	exit(1);
    }
    if (!realm) {
	if (retval = krb5_get_default_realm(context, &realm)) {
	    com_err(argv[0], retval, "while retrieving default realm name");
	    exit(1);
	}	    
    }

    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(context, mkey_name, realm, 
					 &mkey_fullname, &master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
	exit(1);
    }

    if (retval = krb5_db_init(context)) {
	com_err(argv[0], retval, "while initializing the database '%s'",
		dbname);
	exit(1);
    }

    /* TRUE here means read the keyboard, but only once */
    if (retval = krb5_db_fetch_mkey(context, master_princ, &master_encblock,
				    TRUE, FALSE, (char *) NULL,
				    0, &master_keyblock)) {
	com_err(argv[0], retval, "while reading master key");
	(void) krb5_db_fini(context);
	exit(1);
    }
    if (retval = krb5_db_verify_master_key(context, master_princ, 
					   &master_keyblock,&master_encblock)) {
	com_err(argv[0], retval, "while verifying master key");
	(void) krb5_db_fini(context);
	exit(1);
    }	
    if (retval = krb5_db_store_mkey(context, keyfile, master_princ, 
				    &master_keyblock)) {
	com_err(argv[0], errno, "while storing key");
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	(void) krb5_db_fini(context);
	exit(1);
    }
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    if (retval = krb5_db_fini(context)) {
	com_err(argv[0], retval, "closing database '%s'", dbname);
	exit(1);
    }

    exit(0);
}
