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
    TGT_KEY				/* special handling for tgt key */
};

krb5_key_salt_tuple def_kslist = { ENCTYPE_DES_CBC_CRC, KRB5_KDB_SALTTYPE_NORMAL };

struct realm_info {
    krb5_deltat max_life;
    krb5_deltat max_rlife;
    krb5_timestamp expiration;
    krb5_flags flags;
    krb5_encrypt_block *eblock;
    krb5_pointer rseed;
    krb5_int32 nkslist;
    krb5_key_salt_tuple *kslist;
} rblock = { /* XXX */
    KRB5_KDB_MAX_LIFE,
    KRB5_KDB_MAX_RLIFE,
    KRB5_KDB_EXPIRATION,
    KRB5_KDB_DEF_FLAGS,
    (krb5_encrypt_block *) NULL,
    (krb5_pointer) NULL,
    1,
    &def_kslist
};

struct iterate_args {
    krb5_context	ctx;
    struct realm_info	*rblock;
    krb5_db_entry	*dbentp;
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
    fprintf(stderr, "usage: %s [-d dbpathname] [-r realmname] [-k enctype]\n\
\t[-M mkeyname]\n",
	    who);
    exit(status);
}

krb5_keyblock master_keyblock;
krb5_principal master_princ;
krb5_encrypt_block master_encblock;
krb5_data master_salt;

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

char *mkey_password = 0;

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
    char *pw_str = 0;
    int pw_size = 0;
    int enctypedone = 0;
    krb5_data pwd;
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
	    if (!krb5_string_to_enctype(optarg, &master_keyblock.enctype))
		enctypedone++;
	    else
		com_err(argv[0], 0, "%s is an invalid enctype", optarg);
	    break;
	case 'M':			/* master key name in DB */
	    mkey_name = optarg;
	    break;
        case 'P':		/* Only used for testing!!! */
	    mkey_password = optarg;
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
	if (rparams->realm_enctype_valid && !enctypedone) {
	    master_keyblock.enctype = rparams->realm_enctype;
	    enctypedone++;
	}

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

	/* Get the value of the supported key/salt pairs */
	if (rparams->realm_num_keysalts) {
	    rblock.nkslist = rparams->realm_num_keysalts;
	    rblock.kslist = rparams->realm_keysalts;
	    rparams->realm_num_keysalts = 0;
	    rparams->realm_keysalts = (krb5_key_salt_tuple *) NULL;
	}

	krb5_free_realm_params(context, rparams);
    }

    if (!dbname)
	dbname = DEFAULT_KDB_FILE;

    if (!enctypedone)
	master_keyblock.enctype = DEFAULT_KDC_ENCTYPE;

    if (!valid_enctype(master_keyblock.enctype)) {
	char tmp[32];
	if (krb5_enctype_to_string(master_keyblock.enctype, tmp, sizeof(tmp)))
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP,
		    "while setting up enctype %d", master_keyblock.enctype);
	else
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP, tmp);
	exit(1);
    }

    krb5_use_enctype(context, &master_encblock, master_keyblock.enctype);

    retval = krb5_db_set_name(context, dbname);
    if (!retval) retval = EEXIST;

    if (retval == EEXIST || retval == EACCES || retval == EPERM) {
	/* it exists ! */
	com_err(argv[0], 0, "The database '%s' appears to already exist",
		dbname);
	exit(1);
    }
    if (!realm) {
	if ((retval = krb5_get_default_realm(context, &defrealm))) {
	    com_err(argv[0], retval, "while retrieving default realm name");
	    exit(1);
	}	    
	realm = defrealm;
    }

    /* assemble & parse the master key name */

    if ((retval = krb5_db_setup_mkey_name(context, mkey_name, realm, 
					  &mkey_fullname, &master_princ))) {
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

    if (!mkey_password) {
	printf("You will be prompted for the database Master Password.\n");
	printf("It is important that you NOT FORGET this password.\n");
	fflush(stdout);

	pw_size = 1024;
	pw_str = malloc(pw_size);
	
	retval = krb5_read_password(context, KRB5_KDC_MKEY_1, KRB5_KDC_MKEY_2,
				    pw_str, &pw_size);
	if (retval) {
	    com_err(argv[0], retval, "while reading master key from keyboard");
	    exit(1);
	}
	mkey_password = pw_str;
    }

    pwd.data = mkey_password;
    pwd.length = strlen(mkey_password);
    retval = krb5_principal2salt(context, master_princ, &master_salt);
    if (retval) {
	com_err(argv[0], retval, "while calculated master key salt");
	exit(1);
    }
    retval = krb5_string_to_key(context, &master_encblock, 
				master_keyblock.enctype, &master_keyblock, 
				&pwd, &master_salt);
    if (retval) {
	com_err(argv[0], retval,
		"while transforming master key from password");
	exit(1);
    }

    if ((retval = krb5_process_key(context, &master_encblock,
				   &master_keyblock))) {
	com_err(argv[0], retval, "while processing master key");
	exit(1);
    }

    rblock.eblock = &master_encblock;
    if ((retval = krb5_init_random_key(context, &master_encblock, 
				       &master_keyblock, &rblock.rseed))) {
	com_err(argv[0], retval, "while initializing random key generator");
	(void) krb5_finish_key(context, &master_encblock);
	exit(1);
    }
    if ((retval = krb5_db_create(context, dbname))) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	com_err(argv[0], retval, "while creating database '%s'",
		dbname);
	exit(1);
    }
    if ((retval = krb5_db_set_name(context, dbname))) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
        com_err(argv[0], retval, "while setting active database to '%s'",
                dbname);
        exit(1);
    }
    if ((retval = krb5_db_init(context))) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	com_err(argv[0], retval, "while initializing the database '%s'",
		dbname);
	exit(1);
    }

    if ((retval = add_principal(context, master_princ, MASTER_KEY, &rblock)) ||
	(retval = add_principal(context, &tgt_princ, TGT_KEY, &rblock))) {
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
    free(master_keyblock.contents);
    if (pw_str) {
	memset(pw_str, 0, pw_size);
	free(pw_str);
    }
    free(master_salt.data);
    exit(0);

}

static krb5_error_code
tgt_keysalt_iterate(ksent, ptr)
    krb5_key_salt_tuple	*ksent;
    krb5_pointer	ptr;
{
    krb5_context	context;
    krb5_error_code	kret;
    struct iterate_args	*iargs;
    krb5_keyblock	random_keyblock, *key;
    krb5_int32		ind;
    krb5_encrypt_block  random_encblock;
    krb5_pointer rseed;
    krb5_data	pwd;

    iargs = (struct iterate_args *) ptr;
    kret = 0;

    context = iargs->ctx;

    /*
     * Convert the master key password into a key for this particular
     * encryption system.
     */
    krb5_use_enctype(context, &random_encblock, ksent->ks_enctype);
    pwd.data = mkey_password;
    pwd.length = strlen(mkey_password);
    kret = krb5_string_to_key(context, &random_encblock, 
				ksent->ks_enctype, &random_keyblock, 
				&pwd, &master_salt);
    if (kret)
	return kret;
    if ((kret = krb5_init_random_key(context, &random_encblock, 
				       &random_keyblock, &rseed)))
	return kret;
    
    if (!(kret = krb5_dbe_create_key_data(iargs->ctx, iargs->dbentp))) {
	ind = iargs->dbentp->n_key_data-1;
	if (!(kret = krb5_random_key(context,
				     &random_encblock, rseed,
				     &key))) {
	    kret = krb5_dbekd_encrypt_key_data(context,
					       iargs->rblock->eblock,
					       key, 
					       NULL,
					       1,
					       &iargs->dbentp->key_data[ind]);
	    krb5_free_keyblock(context, key);
	}
    }
    memset((char *)random_keyblock.contents, 0, random_keyblock.length);
    free(random_keyblock.contents);
    (void) krb5_finish_random_key(context, &random_encblock, &rseed);
    return(kret);
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

    krb5_tl_mod_princ	  mod_princ;
    struct iterate_args	  iargs;

    int			  nentries = 1;

    memset((char *) &entry, 0, sizeof(entry));

    entry.mkvno = 1;
    entry.len = KRB5_KDB_V1_BASE_LENGTH;
    entry.attributes = pblock->flags;
    entry.max_life = pblock->max_life;
    entry.max_renewable_life = pblock->max_rlife;
    entry.expiration = pblock->expiration;

    if ((retval = krb5_copy_principal(context, princ, &entry.princ)))
	goto error_out;

    mod_princ.mod_princ = &db_create_princ;
    if ((retval = krb5_timeofday(context, &mod_princ.mod_date)))
	goto error_out;
    if ((retval = krb5_dbe_encode_mod_princ_data(context, &mod_princ, &entry)))
	goto error_out;

    switch (op) {
    case MASTER_KEY:
	if ((entry.key_data=(krb5_key_data*)malloc(sizeof(krb5_key_data)))
	    == NULL)
	    goto error_out;
	memset((char *) entry.key_data, 0, sizeof(krb5_key_data));
	entry.n_key_data = 1;

	entry.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	if ((retval = krb5_dbekd_encrypt_key_data(context, pblock->eblock,
						  &master_keyblock, NULL, 
						  1, entry.key_data)))
	    return retval;
	break;
    case TGT_KEY:
	iargs.ctx = context;
	iargs.rblock = pblock;
	iargs.dbentp = &entry;
	/*
	 * Iterate through the key/salt list, ignoring salt types.
	 */
	if ((retval = krb5_keysalt_iterate(pblock->kslist,
					   pblock->nkslist,
					   1,
					   tgt_keysalt_iterate,
					   (krb5_pointer) &iargs)))
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
