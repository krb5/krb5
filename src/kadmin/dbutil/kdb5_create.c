/*
 * kadmin/dbutil/kdb5_create.c
 *
 * Copyright 1990,1991,2001, 2002 by the Massachusetts Institute of Technology.
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
 * Generate (from scratch) a Kerberos KDC database.
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

#include <stdio.h>
#include <k5-int.h>
#include <kadm5/admin.h>
#include <kadm5/adb.h>
#include <krb5/adm_proto.h>
#include "kdb5_util.h"

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
    krb5_keyblock *key;
    krb5_int32 nkslist;
    krb5_key_salt_tuple *kslist;
} rblock = { /* XXX */
    KRB5_KDB_MAX_LIFE,
    KRB5_KDB_MAX_RLIFE,
    KRB5_KDB_EXPIRATION,
    KRB5_KDB_DEF_FLAGS,
    (krb5_keyblock *) NULL,
    1,
    &def_kslist
};

struct iterate_args {
    krb5_context	ctx;
    struct realm_info	*rblock;
    krb5_db_entry	*dbentp;
};

static krb5_error_code add_principal 
	(krb5_context,
	 krb5_principal,
	 enum ap_op,
	 struct realm_info *);

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

extern krb5_keyblock master_keyblock;
extern krb5_principal master_princ;
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

extern char *mkey_password;

extern char *progname;
extern int exit_status;
extern osa_adb_policy_t policy_db;
extern kadm5_config_params global_params;
extern krb5_context util_context;

void kdb5_create(argc, argv)
   int argc;
   char *argv[];
{
    int optchar;

    krb5_error_code retval;
    char *mkey_fullname;
    char *pw_str = 0;
    unsigned int pw_size = 0;
    int do_stash = 0;
    krb5_int32 crflags = KRB5_KDB_CREATE_BTREE;
    krb5_data pwd, seed;
	   
    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    while ((optchar = getopt(argc, argv, "s")) != -1) {
	switch(optchar) {
	case 's':
	    do_stash++;
	    break;
	case 'h':
	    crflags = KRB5_KDB_CREATE_HASH;
	case '?':
	default:
	    usage();
	    return;
	}
    }

    rblock.max_life = global_params.max_life;
    rblock.max_rlife = global_params.max_rlife;
    rblock.expiration = global_params.expiration;
    rblock.flags = global_params.flags;
    rblock.nkslist = global_params.num_keysalts;
    rblock.kslist = global_params.keysalts;

    retval = krb5_db_set_name(util_context, global_params.dbname);
    if (!retval) retval = EEXIST;

    if (retval == EEXIST || retval == EACCES || retval == EPERM) {
	/* it exists ! */
	com_err(argv[0], 0, "The database '%s' appears to already exist",
		global_params.dbname);
	exit_status++; return;
    }

    printf ("Loading random data\n");
    retval = krb5_c_random_os_entropy (util_context, 1, NULL);
    if (retval) {
      com_err (argv[0], retval, "Loading random data");
      exit_status++; return;
    }
    
    /* assemble & parse the master key name */

    if ((retval = krb5_db_setup_mkey_name(util_context,
					  global_params.mkey_name,
					  global_params.realm,  
					  &mkey_fullname, &master_princ))) {
	com_err(argv[0], retval, "while setting up master key name");
	exit_status++; return;
    }

    krb5_princ_set_realm_data(util_context, &db_create_princ, global_params.realm);
    krb5_princ_set_realm_length(util_context, &db_create_princ, strlen(global_params.realm));
    krb5_princ_set_realm_data(util_context, &tgt_princ, global_params.realm);
    krb5_princ_set_realm_length(util_context, &tgt_princ, strlen(global_params.realm));
    krb5_princ_component(util_context, &tgt_princ,1)->data = global_params.realm;
    krb5_princ_component(util_context, &tgt_princ,1)->length = strlen(global_params.realm);

    printf("Initializing database '%s' for realm '%s',\n\
master key name '%s'\n",
	   global_params.dbname, global_params.realm, mkey_fullname);

    if (!mkey_password) {
	printf("You will be prompted for the database Master Password.\n");
	printf("It is important that you NOT FORGET this password.\n");
	fflush(stdout);

	pw_size = 1024;
	pw_str = malloc(pw_size);
	
	retval = krb5_read_password(util_context, KRB5_KDC_MKEY_1, KRB5_KDC_MKEY_2,
				    pw_str, &pw_size);
	if (retval) {
	    com_err(argv[0], retval, "while reading master key from keyboard");
	    exit_status++; return;
	}
	mkey_password = pw_str;
    }

    pwd.data = mkey_password;
    pwd.length = strlen(mkey_password);
    retval = krb5_principal2salt(util_context, master_princ, &master_salt);
    if (retval) {
	com_err(argv[0], retval, "while calculating master key salt");
	exit_status++; return;
    }

    retval = krb5_c_string_to_key(util_context, master_keyblock.enctype, 
				  &pwd, &master_salt, &master_keyblock);
    if (retval) {
	com_err(argv[0], retval, "while transforming master key from password");
	exit_status++; return;
    }

    rblock.key = &master_keyblock;

    seed.length = master_keyblock.length;
    seed.data = master_keyblock.contents;

    if ((retval = krb5_c_random_seed(util_context, &seed))) {
	com_err(argv[0], retval, "while initializing random key generator");
	exit_status++; return;
    }
    if ((retval = krb5_db_create(util_context,
				 global_params.dbname, crflags))) {
	com_err(argv[0], retval, "while creating database '%s'",
		global_params.dbname);
	exit_status++; return;
    }
    if ((retval = krb5_db_fini(util_context))) {
        com_err(argv[0], retval, "while closing current database");
        exit_status++; return;
    }
    if ((retval = krb5_db_set_name(util_context, global_params.dbname))) {
        com_err(argv[0], retval, "while setting active database to '%s'",
                global_params.dbname);
        exit_status++; return;
    }
    if ((retval = krb5_db_init(util_context))) {
	com_err(argv[0], retval, "while initializing the database '%s'",
		global_params.dbname);
	exit_status++; return;
    }

    if ((retval = add_principal(util_context, master_princ, MASTER_KEY, &rblock)) ||
	(retval = add_principal(util_context, &tgt_princ, TGT_KEY, &rblock))) {
	(void) krb5_db_fini(util_context);
	com_err(argv[0], retval, "while adding entries to the database");
	exit_status++; return;
    }
    /*
     * Always stash the master key so kadm5_create does not prompt for
     * it; delete the file below if it was not requested.  DO NOT EXIT
     * BEFORE DELETING THE KEYFILE if do_stash is not set.
     */
    retval = krb5_db_store_mkey(util_context,
			    global_params.stash_file,
			    master_princ,
			    &master_keyblock);
    if (retval) {
	com_err(argv[0], errno, "while storing key");
	printf("Warning: couldn't stash master key.\n");
    }
    /* clean up */
    (void) krb5_db_fini(util_context);
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    free(master_keyblock.contents);
    if (pw_str) {
	memset(pw_str, 0, pw_size);
	free(pw_str);
    }
    free(master_salt.data);

    if (kadm5_create(&global_params)) {
	 if (!do_stash) unlink(global_params.stash_file);
	 exit_status++;
	 return;
    }
    if (!do_stash) unlink(global_params.stash_file);

    return;
}

static krb5_error_code
tgt_keysalt_iterate(ksent, ptr)
    krb5_key_salt_tuple	*ksent;
    krb5_pointer	ptr;
{
    krb5_context	context;
    krb5_error_code	kret;
    struct iterate_args	*iargs;
    krb5_keyblock	key;
    krb5_int32		ind;
    krb5_data	pwd;

    iargs = (struct iterate_args *) ptr;
    kret = 0;

    context = iargs->ctx;

    /*
     * Convert the master key password into a key for this particular
     * encryption system.
     */
    pwd.data = mkey_password;
    pwd.length = strlen(mkey_password);
    kret = krb5_c_random_seed(context, &pwd);
    if (kret)
	return kret;

    if (!(kret = krb5_dbe_create_key_data(iargs->ctx, iargs->dbentp))) {
	ind = iargs->dbentp->n_key_data-1;
	if (!(kret = krb5_c_make_random_key(context, ksent->ks_enctype,
					    &key))) {
	    kret = krb5_dbekd_encrypt_key_data(context,
					       iargs->rblock->key,
					       &key, 
					       NULL,
					       1,
					       &iargs->dbentp->key_data[ind]);
	    krb5_free_keyblock_contents(context, &key);
	}
    }

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

    krb5_timestamp	  now;
    struct iterate_args	  iargs;

    int			  nentries = 1;

    memset((char *) &entry, 0, sizeof(entry));

    entry.len = KRB5_KDB_V1_BASE_LENGTH;
    entry.attributes = pblock->flags;
    entry.max_life = pblock->max_life;
    entry.max_renewable_life = pblock->max_rlife;
    entry.expiration = pblock->expiration;

    if ((retval = krb5_copy_principal(context, princ, &entry.princ)))
	goto error_out;

    if ((retval = krb5_timeofday(context, &now)))
	goto error_out;

    if ((retval = krb5_dbe_update_mod_princ_data(context, &entry,
						 now, &db_create_princ)))
	goto error_out;

    switch (op) {
    case MASTER_KEY:
	if ((entry.key_data=(krb5_key_data*)malloc(sizeof(krb5_key_data)))
	    == NULL)
	    goto error_out;
	memset((char *) entry.key_data, 0, sizeof(krb5_key_data));
	entry.n_key_data = 1;

	entry.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	if ((retval = krb5_dbekd_encrypt_key_data(context, pblock->key,
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
