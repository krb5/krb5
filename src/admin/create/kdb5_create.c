/*
 * admin/create/kdb5_create.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Generate (from scratch) a Kerberos KDC database.
 */

#include "k5-int.h"
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"
#include <stdio.h>

enum ap_op {
    NULL_KEY,				/* setup null keys */
    MASTER_KEY,				/* use master key as new key */
    RANDOM_KEY				/* choose a random key */
};

struct realm_info {
    krb5_deltat max_life;
    krb5_deltat max_rlife;
    krb5_timestamp expiration;
    krb5_flags flags;
    krb5_encrypt_block *eblock;
    krb5_pointer rseed;
} rblock = { /* XXX */
    KRB5_KDB_MAX_LIFE,
    KRB5_KDB_MAX_RLIFE,
    KRB5_KDB_EXPIRATION,
    KRB5_KDB_DEF_FLAGS,
    0
};

static krb5_error_code add_principal 
	PROTOTYPE((krb5_context,
		   krb5_principal, 
		   enum ap_op,
		   struct realm_info *));

/*
 * Steps in creating a database:
 *
 * 1) use the db calls to open/create a new database
 *
 * 2) get a realm name for the new db
 *
 * 3) get a master password for the new db; convert to an encryption key.
 *
 * 4) create various required entries in the database
 *
 * 5) close & exit
 */

static void
usage(who, status)
char *who;
int status;
{
    fprintf(stderr, "usage: %s [-d dbpathname] [-r realmname] [-k keytype]\n\
\t[-e etype] [-M mkeyname]\n",
	    who);
    exit(status);
}

krb5_keyblock master_keyblock;
krb5_principal master_princ;
krb5_encrypt_block master_encblock;

krb5_data tgt_princ_entries[] = {
	{0, KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME},
	{0, 0, 0} };

krb5_data db_creator_entries[] = {
	{0, sizeof("db_creation")-1, "db_creation"} };

/* XXX knows about contents of krb5_principal, and that tgt names
 are of form TGT/REALM@REALM */
krb5_principal_data tgt_princ = {
        0,					/* magic number */
	{0, 0, 0},				/* krb5_data realm */
	tgt_princ_entries,			/* krb5_data *data */
	2,					/* int length */
	KRB5_NT_SRV_INST			/* int type */
};

krb5_principal_data db_create_princ = {
        0,					/* magic number */
	{0, 0, 0},				/* krb5_data realm */
	db_creator_entries,			/* krb5_data *data */
	1,					/* int length */
	KRB5_NT_SRV_INST			/* int type */
};

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
    char *defrealm;
    char *mkey_password = 0;
    int keytypedone = 0;
    krb5_enctype etype = 0xffff;
    krb5_data scratch, pwd;
    krb5_context context;
    krb5_realm_params *rparams;

    krb5_init_context(&context);
    krb5_init_ets(context);

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    while ((optchar = getopt(argc, argv, "d:r:k:M:e:P:")) != EOF) {
	switch(optchar) {
	case 'd':			/* set db name */
	    dbname = optarg;
	    break;
	case 'r':
	    realm = optarg;
	    break;
	case 'k':
	    master_keyblock.keytype = atoi(optarg);
	    keytypedone++;
	    break;
	case 'M':			/* master key name in DB */
	    mkey_name = optarg;
	    break;
        case 'P':		/* Only used for testing!!! */
	    mkey_password = optarg;
	    break;
	case 'e':
	    etype = atoi(optarg);
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

	/* Get the value for the encryption type */
	if (rparams->realm_enctype_valid && (etype == 0xffff))
	    etype = rparams->realm_enctype;

	/* Get the value for maximum ticket lifetime. */
	if (rparams->realm_max_life_valid)
	    rblock.max_life = rparams->realm_max_life;

	/* Get the value for maximum renewable ticket lifetime. */
	if (rparams->realm_max_rlife_valid)
	    rblock.max_rlife = rparams->realm_max_rlife;

	/* Get the value for the default principal expiration */
	if (rparams->realm_expiration_valid)
	    rblock.expiration = rparams->realm_expiration;

	/* Get the value for the default principal flags */
	if (rparams->realm_flags_valid)
	    rblock.flags = rparams->realm_flags;

	krb5_free_realm_params(context, rparams);
    }

    if (!dbname)
	dbname = DEFAULT_KDB_FILE;

    if (!keytypedone)
	master_keyblock.keytype = DEFAULT_KDC_KEYTYPE;

    if (!valid_keytype(master_keyblock.keytype)) {
	com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP,
		"while setting up keytype %d", master_keyblock.keytype);
	exit(1);
    }

    if (etype == 0xffff)
	etype = DEFAULT_KDC_ETYPE;

    if (!valid_etype(etype)) {
	com_err(argv[0], KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", etype);
	exit(1);
    }
    krb5_use_cstype(context, &master_encblock, etype);

    retval = krb5_db_set_name(context, dbname);
    if (!retval) retval = EEXIST;

    if (retval == EEXIST || retval == EACCES || retval == EPERM) {
	/* it exists ! */
	com_err(argv[0], 0, "The database '%s' appears to already exist",
		dbname);
	exit(1);
    }
    if (!realm) {
	if (retval = krb5_get_default_realm(context, &defrealm)) {
	    com_err(argv[0], retval, "while retrieving default realm name");
	    exit(1);
	}	    
	realm = defrealm;
    }

    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(context, mkey_name, realm, 
					 &mkey_fullname, &master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
	exit(1);
    }

    krb5_princ_set_realm_data(context, &db_create_princ, realm);
    krb5_princ_set_realm_length(context, &db_create_princ, strlen(realm));
    krb5_princ_set_realm_data(context, &tgt_princ, realm);
    krb5_princ_set_realm_length(context, &tgt_princ, strlen(realm));
    krb5_princ_component(context, &tgt_princ,1)->data = realm;
    krb5_princ_component(context, &tgt_princ,1)->length = strlen(realm);

    printf("Initializing database '%s' for realm '%s',\n\
master key name '%s'\n",
	   dbname, realm, mkey_fullname);

    if (mkey_password) {
	pwd.data = mkey_password;
	pwd.length = strlen(mkey_password);
	retval = krb5_principal2salt(context, master_princ, &scratch);
	if (retval) {
	    com_err(argv[0], retval, "while calculated master key salt");
	    exit(1);
	}
	retval = krb5_string_to_key(context, &master_encblock, 
				    master_keyblock.keytype, &master_keyblock, 
				    &pwd, &scratch);
	if (retval) {
	    com_err(argv[0], retval,
		    "while transforming master key from password");
	    exit(1);
	}
	free(scratch.data);
    } else {
	printf("You will be prompted for the database Master Password.\n");
	printf("It is important that you NOT FORGET this password.\n");
	fflush(stdout);

	/* TRUE here means read the keyboard, and do it twice */
	if (retval = krb5_db_fetch_mkey(context, master_princ,
					&master_encblock,
					TRUE, TRUE, (char *) NULL,
					0, &master_keyblock)) {
	    com_err(argv[0], retval, "while reading master key");
	    exit(1);
	}
    }
    
    if (retval = krb5_process_key(context, &master_encblock,&master_keyblock)){
	com_err(argv[0], retval, "while processing master key");
	exit(1);
    }

    rblock.eblock = &master_encblock;
    if (retval = krb5_init_random_key(context, &master_encblock, 
				      &master_keyblock, &rblock.rseed)) {
	com_err(argv[0], retval, "while initializing random key generator");
	(void) krb5_finish_key(context, &master_encblock);
	exit(1);
    }
    if (retval = krb5_db_create(context, dbname)) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	com_err(argv[0], retval, "while creating database '%s'",
		dbname);
	exit(1);
    }
    if (retval = krb5_db_set_name(context, dbname)) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
        com_err(argv[0], retval, "while setting active database to '%s'",
                dbname);
        exit(1);
    }
    if (retval = krb5_db_init(context)) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	com_err(argv[0], retval, "while initializing the database '%s'",
		dbname);
	exit(1);
    }

    if ((retval = add_principal(context, master_princ, MASTER_KEY, &rblock)) ||
	(retval = add_principal(context, &tgt_princ, RANDOM_KEY, &rblock))) {
	(void) krb5_db_fini(context);
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	com_err(argv[0], retval, "while adding entries to the database");
	exit(1);
    }
    /* clean up */
    (void) krb5_db_fini(context);
    (void) krb5_finish_key(context, &master_encblock);
    (void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    exit(0);

}

static krb5_error_code
add_principal(context, princ, op, pblock)
    krb5_context context;
    krb5_principal princ;
    enum ap_op op;
    struct realm_info *pblock;
{
    krb5_error_code 	  retval;
    krb5_db_entry 	  entry;
    krb5_keyblock 	* rkey;

    krb5_tl_mod_princ	  mod_princ;

    int			  nentries = 1;

    memset((char *) &entry, 0, sizeof(entry));

    entry.mkvno = 1;
    entry.len = KRB5_KDB_V1_BASE_LENGTH;
    entry.attributes = pblock->flags;
    entry.max_life = pblock->max_life;
    entry.max_renewable_life = pblock->max_rlife;
    entry.expiration = pblock->expiration;

    if (retval = krb5_copy_principal(context, princ, &entry.princ))
	goto error_out;

    mod_princ.mod_princ = &db_create_princ;
    if (retval = krb5_timeofday(context, &mod_princ.mod_date))
	goto error_out;
    if (retval = krb5_dbe_encode_mod_princ_data(context, &mod_princ, &entry))
	goto error_out;

    if ((entry.key_data=(krb5_key_data*)malloc(sizeof(krb5_key_data))) == NULL)
	goto error_out;
    memset((char *) entry.key_data, 0, sizeof(krb5_key_data));
    entry.n_key_data = 1;

    switch (op) {
    case MASTER_KEY:
	entry.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	if (retval = krb5_dbekd_encrypt_key_data(context, pblock->eblock,
				      	       	 &master_keyblock, NULL, 
					       	 1, entry.key_data))
	    return retval;
	break;
    case RANDOM_KEY:
	if (retval = krb5_random_key(context, pblock->eblock, 
				     pblock->rseed, &rkey))
	    return retval;
	retval = krb5_dbekd_encrypt_key_data(context, pblock->eblock, rkey, 
						NULL, 1, entry.key_data);
	krb5_free_keyblock(context, rkey);
	if (retval)
	    return retval;
	break;
    case NULL_KEY:
	return EOPNOTSUPP;
    default:
	break;
    }

    retval = krb5_db_put_principal(context, &entry, &nentries);

error_out:;
    krb5_dbe_free_contents(context, &entry);
    return retval;
}
