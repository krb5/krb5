/*
 * admin/convert/kdb5_convert.c
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
 * Generate (from scratch) a Kerberos V5 KDC database, filling it in with the
 * entries from a V4 database.
 *
 * Code lifted from kdb5_create, kdb5_edit (v5 utilities),
 * kdb_util, kdb_edit, libkdb (v4 utilities/libraries), put into a blender,
 * and this is the result. 
 */

#include <des.h>
#include <krb.h>
#include <krb_db.h>
/* MKEYFILE is now defined in kdc.h */
#include <kdc.h>

static C_Block master_key;
static Key_schedule master_key_schedule;
static long master_key_version;

#include "k5-int.h"
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"
#include <stdio.h>

#include <netinet/in.h>			/* ntohl */

#define PROGNAME argv[0]

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

static int verbose = 0;

static krb5_error_code add_principal 
	PROTOTYPE((krb5_context,
		   krb5_principal, 
		   enum ap_op,
		   struct realm_info *));

void v4fini PROTOTYPE((void));
int v4init PROTOTYPE((char *, char *, int, char *));
krb5_error_code enter_in_v5_db PROTOTYPE((krb5_context, char *, Principal *));
krb5_error_code process_v4_dump PROTOTYPE((krb5_context, char *, char *));
krb5_error_code fixup_database PROTOTYPE((krb5_context, char *));
	
int create_local_tgt = 0;

/*
 * I can't say for sure what ODBM is for, but when KDB4_DISABLE is defined,
 * we are to avoid compiling any references to KDB4 functions.
 */
#if	defined(ODBM) || defined(KDB4_DISABLE)
static void
usage(who, status)
char *who;
int status;
{
    fprintf(stderr, "usage: %s [-d v5dbpathname] [-t] [-n] [-r realmname] [-K] [-k keytype]\n\
\t[-e etype] [-M mkeyname] -f inputfile\n",
	    who);
    fprintf(stderr, "\t(You must supply a v4 database dump file for this version of %s)\n",who);
    exit(status);
}
#else
static void
usage(who, status)
char *who;
int status;
{
    fprintf(stderr, "usage: %s [-d v5dbpathname] [-t] [-n] [-r realmname] [-K] [-k keytype]\n\
\t[-e etype] [-M mkeyname] [-D v4dbpathname | -f inputfile]\n",
	    who);
    exit(status);
}
#endif

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
    /* The kdb library will default to this, but it is convenient to
       make it explicit (error reporting and temporary filename generation
       use it).  */
    char *dbname = DEFAULT_KDB_FILE;
    char *v4dbname = 0;
    char *v4dumpfile = 0;
    char *realm = 0;
    char *mkey_name = 0;
    char *mkey_fullname;
    char *defrealm;
    int keytypedone = 0;
    int v4manual = 0;
    int read_mkey = 0;
    int tempdb = 0;
    char *tempdbname;
    krb5_context context;
    char *stash_file = (char *) NULL;
    krb5_realm_params *rparams;

    krb5_enctype etype = 0xffff;

    krb5_init_context(&context);

    krb5_init_ets(context);

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    while ((optchar = getopt(argc, argv, "d:tD:r:Kvk:M:e:nf:")) != EOF) {
	switch(optchar) {
	case 'd':			/* set db name */
	    dbname = optarg;
	    break;
        case 'T':
	    create_local_tgt = 1;
	    break;
	case 't':
	    tempdb = 1;
	    break;
	case 'D':			/* set db name */
#if	defined(ODBM) || defined(KDB4_DISABLE)
	    usage(PROGNAME, 1);
#else
	    if (v4dumpfile)
		usage(PROGNAME, 1);
	    v4dbname = optarg;
	    break;
#endif
	case 'r':
	    realm = optarg;
	    break;
	case 'K':
	    read_mkey = 1;
	    break;
	case 'v':
	    verbose = 1;
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
	case 'e':
	    if (krb5_string_to_enctype(optarg, &etype))
		com_err(argv[0], 0, "%s is an invalid encryption type",
			optarg);
	    break;
	case 'n':
	    v4manual++;
	    break;
	case 'f':
	    if (v4dbname)
		usage(PROGNAME, 1);
	    v4dumpfile = optarg;
	    break;
	case '?':
	default:
	    usage(PROGNAME, 1);
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

	/* Get the value for the stashfile */
	if (rparams->realm_stash_file)
	    stash_file = strdup(rparams->realm_stash_file);

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

#if	defined(ODBM) || defined(KDB4_DISABLE)
    if (!v4dumpfile) {
	usage(PROGNAME, 1);
    }
#endif

    if (!keytypedone)
	master_keyblock.keytype = DEFAULT_KDC_KEYTYPE;

    if (!valid_keytype(master_keyblock.keytype)) {
	com_err(PROGNAME, KRB5_PROG_KEYTYPE_NOSUPP,
		"while setting up keytype %d", master_keyblock.keytype);
	exit(1);
    }

    if (etype == 0xffff)
	etype = DEFAULT_KDC_ETYPE;

    if (!valid_etype(etype)) {
	com_err(PROGNAME, KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", etype);
	exit(1);
    }
    krb5_use_cstype(context, &master_encblock, etype);

    /* If the user has not requested locking, don't modify an existing database. */
    if (! tempdb) {
	retval = krb5_db_set_name(context, dbname);
	if (retval != ENOENT) {
	    fprintf(stderr,
		    "%s: The v5 database appears to already exist.\n",
		    PROGNAME);
	    exit(1);
	}
	tempdbname = dbname;
    } else {
	int dbnamelen = strlen(dbname);
	tempdbname = malloc(dbnamelen + 2);
	if (tempdbname == 0) {
	    com_err(PROGNAME, ENOMEM, "allocating temporary filename");
	    exit(1);
	}
	strcpy(tempdbname, dbname);
	tempdbname[dbnamelen] = '~';
	tempdbname[dbnamelen+1] = 0;
	(void) kdb5_db_destroy(context, tempdbname);
    }
	

    if (!realm) {
	if (retval = krb5_get_default_realm(context, &defrealm)) {
	    com_err(PROGNAME, retval, "while retrieving default realm name");
	    exit(1);
	}	    
	realm = defrealm;
    }

    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(context, mkey_name, realm,
					 &mkey_fullname, &master_princ)) {
	com_err(PROGNAME, retval, "while setting up master key name");
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

    if (read_mkey) {
	puts("You will be prompted for the version 5 database Master Password.");
	puts("It is important that you NOT FORGET this password.");
	fflush(stdout);
    }

    if (retval = krb5_db_fetch_mkey(context, master_princ, &master_encblock,
				    read_mkey, read_mkey, stash_file, 0, 
				    &master_keyblock)) {
	com_err(PROGNAME, retval, "while reading master key");
	exit(1);
    }
    if (retval = krb5_process_key(context, &master_encblock, &master_keyblock)) {
	com_err(PROGNAME, retval, "while processing master key");
	exit(1);
    }

    rblock.eblock = &master_encblock;
    if (retval = krb5_init_random_key(context, &master_encblock,
				      &master_keyblock, &rblock.rseed)) {
	com_err(PROGNAME, retval, "while initializing random key generator");
	(void) krb5_finish_key(context, &master_encblock);
	exit(1);
    }
    if (retval = krb5_db_create(context, tempdbname)) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	(void) krb5_dbm_db_destroy(context, tempdbname);
	com_err(PROGNAME, retval, "while creating %sdatabase '%s'",
		tempdb ? "temporary " : "", tempdbname);
	exit(1);
    }
    if (retval = krb5_db_set_name(context, tempdbname)) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	(void) krb5_dbm_db_destroy(context, tempdbname);
        com_err(PROGNAME, retval, "while setting active database to '%s'",
                tempdbname);
        exit(1);
    }
    if (v4init(PROGNAME, v4dbname, v4manual, v4dumpfile)) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	(void) krb5_dbm_db_destroy(context, tempdbname);
	exit(1);
    }
    if ((retval = krb5_db_init(context)) || 
	(retval = krb5_dbm_db_open_database(context))) {
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	(void) krb5_dbm_db_destroy(context, tempdbname);
	v4fini();
	com_err(PROGNAME, retval, "while initializing the database '%s'",
		tempdbname);
	exit(1);
    }

    if (retval = add_principal(context, master_princ, MASTER_KEY, &rblock)) {
	(void) krb5_db_fini(context);
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	(void) krb5_dbm_db_destroy(context, tempdbname);
	v4fini();
	com_err(PROGNAME, retval, "while adding K/M to the database");
	exit(1);
    }

    if (create_local_tgt &&
	(retval = add_principal(context, &tgt_princ, RANDOM_KEY, &rblock))) {
	(void) krb5_db_fini(context);
	(void) krb5_finish_key(context, &master_encblock);
	(void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
	(void) krb5_dbm_db_destroy(context, tempdbname);
	v4fini();
	com_err(PROGNAME, retval, "while adding TGT service to the database");
	exit(1);
    }

#ifndef	KDB4_DISABLE
    if (v4dumpfile)
	retval = process_v4_dump(context, v4dumpfile, realm);
    else
	retval = kerb_db_iterate(enter_in_v5_db, realm);
#else	/* KDB4_DISABLE */
    retval = process_v4_dump(context, v4dumpfile, realm);
#endif	/* KDB4_DISABLE */
    putchar('\n');
    if (retval)
	com_err(PROGNAME, retval, "while translating entries to the database");
    else {
	retval = fixup_database(context, realm);
    }
    
    /* clean up; rename temporary database if there were no errors */
    if (retval == 0) {
	if (retval = krb5_db_fini (context))
	    com_err(PROGNAME, retval, "while shutting down database");
	else if (tempdb && (retval = krb5_dbm_db_rename(context, tempdbname,
							dbname)))
	    com_err(PROGNAME, retval, "while renaming temporary database");
    } else {
	(void) krb5_db_fini (context);
	if (tempdb)
		(void) krb5_dbm_db_destroy (context, tempdbname);
    }
    (void) krb5_finish_key(context, &master_encblock);
    (void) krb5_finish_random_key(context, &master_encblock, &rblock.rseed);
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    v4fini();
    exit(retval ? 1 : 0);
}

void
v4fini()
{
#if	!defined(ODBM) && !defined(KDB4_DISABLE)
    kerb_fini();
#endif
}

int
v4init(pname, name, manual, dumpfile)
char *pname, *name;
int manual;
char *dumpfile;
{
#if	!defined(ODBM) && !defined(KDB4_DISABLE)
    kerb_init();
#endif
#if	!defined(KDB4_DISABLE)
    if (name) {
	if (kerb_db_set_name(name) != 0) {
	    com_err(pname, 0,
		    "Could not open alternate v4 database name %s\n",
		    name);
	    return 1;
	}
    }
    if (kdb_get_master_key (manual, master_key, master_key_schedule) != 0) {
	com_err(pname, 0, "Couldn't read v4 master key.");
	return 1;
    }
#else	/* KDB4_DISABLE */
    /*
     * Always reads from terminal.
     */
    des_read_password(master_key, "Kerberos master key: ", 1);
    printf("\n");
    key_sched(master_key, master_key_schedule);
#endif	/* !KDB4_DISABLE */
#if	!defined(ODBM) && !defined(KDB4_DISABLE)
    if (!dumpfile) {
	if ((master_key_version = kdb_verify_master_key(master_key,
							master_key_schedule,
							stdout)) < 0) {
	    com_err(pname, 0,
		    "Couldn't verify v4 master key (did you type it correctly?).");
	    return 1;
	}
    }
#endif
    return 0;
}

krb5_error_code
enter_in_v5_db(context, realm, princ)
krb5_context context;
char *realm;
Principal *princ;
{
    krb5_db_entry entry;
    krb5_error_code retval;
    krb5_encrypted_keyblock ekey;
    krb5_keyblock v4v5key;
    int nentries = 1;
    des_cblock v4key;
    char *name;

    /* don't convert local TGT if we created a TGT already.... */
    if (create_local_tgt && !strcmp(princ->name, "krbtgt") &&
	!strcmp(princ->instance, realm)) {
	    if (verbose)
		    printf("\nignoring local TGT: '%s.%s' ...",
			   princ->name, princ->instance);
	    return 0;
    }
    if (!strcmp(princ->name, KERB_M_NAME) &&
	!strcmp(princ->instance, KERB_M_INST)) {
	des_cblock key_from_db;
	int val;

	/* here's our chance to verify the master key */
	/*
	 * use the master key to decrypt the key in the db, had better
	 * be the same! 
	 */
	memcpy(key_from_db, (char *)&princ->key_low, 4);
	memcpy(((long *) key_from_db) + 1, (char *)&princ->key_high, 4);
#ifndef	KDB4_DISABLE
	kdb_encrypt_key (key_from_db, key_from_db, 
			 master_key, master_key_schedule, DECRYPT);
#else	/* KDB4_DISABLE */
	pcbc_encrypt((C_Block *) key_from_db,
		     (C_Block *) key_from_db,
		     (long) sizeof(C_Block),
		     master_key_schedule,
		     (C_Block *) master_key,
		     DECRYPT);
#endif	/* KDB4_DISABLE */
	val = memcmp((char *) master_key, (char *) key_from_db,
		     sizeof(master_key));
	memset((char *)key_from_db, 0, sizeof(key_from_db));
	if (val) {
	    return KRB5_KDB_BADMASTERKEY;
	}
	if (verbose)
	    printf("\nignoring '%s.%s' ...", princ->name, princ->instance);
	return 0;
    }
    memset((char *) &entry, 0, sizeof(entry));
    if (retval = krb5_425_conv_principal(context, princ->name, princ->instance,
					 realm, &entry.principal))
	return retval;
    if (verbose) {
	if (retval = krb5_unparse_name(context, entry.principal, &name))
	   name = strdup("<not unparsable name!>");
	if (verbose)
	    printf("\ntranslating %s...", name);
	free(name);
    }

    if (retval = krb5_build_principal(context, &entry.mod_name, strlen(realm),
				      realm, princ->mod_name,
				      princ->mod_instance[0] ? princ->mod_instance : 0,
				      0)) {
	krb5_free_principal(context, entry.principal);
	return retval;
    }

    entry.kvno = princ->key_version;
    entry.max_life = princ->max_life * 60 * 5;
    entry.max_renewable_life = rblock.max_rlife;
    entry.mkvno = 1;
    entry.expiration = princ->exp_date;
    entry.mod_date = princ->mod_date;
    entry.attributes = rblock.flags;	/* XXX is there a way to convert
					   the old attrs? */

    memcpy((char *)v4key, (char *)&(princ->key_low), 4);
    memcpy((char *) (((long *) v4key) + 1), (char *)&(princ->key_high), 4);
#ifndef	KDB4_DISABLE
    kdb_encrypt_key (v4key, v4key, master_key, master_key_schedule, DECRYPT);
#else	/* KDB4_DISABLE */
    pcbc_encrypt((C_Block *) v4key,
		 (C_Block *) v4key,
		 (long) sizeof(C_Block),
		 master_key_schedule,
		 (C_Block *) master_key,
		 DECRYPT);
#endif	/* KDB4_DISABLE */

    v4v5key.magic = KV5M_KEYBLOCK;
    v4v5key.etype = master_keyblock.etype;
    v4v5key.contents = (krb5_octet *)v4key;
    v4v5key.keytype = KEYTYPE_DES;
    v4v5key.length = sizeof(v4key);

    retval = krb5_kdb_encrypt_key(context, rblock.eblock, &v4v5key, &ekey);
    if (retval) {
	krb5_free_principal(context, entry.principal);
	krb5_free_principal(context, entry.mod_name);
	return retval;
    }
    memset((char *)v4key, 0, sizeof(v4key));
    entry.key = ekey;
    entry.salt_type = KRB5_KDB_SALTTYPE_V4;
    entry.salt_length = 0;
    entry.salt = 0;

    retval = krb5_db_put_principal(context, &entry, &nentries);

    if (!retval && !strcmp(princ->name, "krbtgt") &&
	strcmp(princ->instance, realm) && princ->instance[0]) {
	    krb5_free_principal(context, entry.principal);
	    if (retval = krb5_build_principal(context, &entry.principal,
					      strlen(princ->instance),
					      princ->instance,
					      "krbtgt", realm, 0))
		    return retval;
	    retval = krb5_db_put_principal(context, &entry, &nentries);
    }

    krb5_free_principal(context, entry.principal);
    krb5_free_principal(context, entry.mod_name);
    krb5_xfree(ekey.contents);

    return retval;
}

static krb5_error_code
add_principal(context, princ, op, pblock)
krb5_context context;
krb5_principal princ;
enum ap_op op;
struct realm_info *pblock;
{
    krb5_db_entry entry;
    krb5_error_code retval;
    krb5_encrypted_keyblock ekey;
    krb5_keyblock *rkey;
    int nentries = 1;

    memset((char *) &entry, 0, sizeof(entry));
    entry.principal = princ;
    entry.kvno = 1;
    entry.max_life = pblock->max_life;
    entry.max_renewable_life = pblock->max_rlife;
    entry.mkvno = 1;
    entry.expiration = pblock->expiration;
    entry.mod_name = &db_create_princ;

    if (retval = krb5_timeofday(context, &entry.mod_date))
	return retval;
    entry.attributes = pblock->flags;

    switch (op) {
    case MASTER_KEY:
	entry.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	if (retval = krb5_kdb_encrypt_key(context, pblock->eblock,
					  &master_keyblock,
					  &ekey))
	    return retval;
	break;
    case RANDOM_KEY:
	if (retval = krb5_random_key(context, pblock->eblock, pblock->rseed, &rkey))
	    return retval;
	retval = krb5_kdb_encrypt_key(context, pblock->eblock, rkey, &ekey);
	krb5_free_keyblock(context, rkey);
	if (retval)
	    return retval;
	break;
    case NULL_KEY:
	return EOPNOTSUPP;
    default:
	break;
    }
    entry.key = ekey;
    entry.salt_type = KRB5_KDB_SALTTYPE_NORMAL;
    entry.salt_length = 0;
    entry.salt = 0;

    if (retval = krb5_db_put_principal(context, &entry, &nentries))
	return retval;

    krb5_xfree(ekey.contents);
    return 0;
}

/*
 * Convert a struct tm * to a UNIX time.
 */


#define daysinyear(y) (((y) % 4) ? 365 : (((y) % 100) ? 366 : (((y) % 400) ? 365 : 366)))

#define SECSPERDAY 24*60*60
#define SECSPERHOUR 60*60
#define SECSPERMIN 60

static int cumdays[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334,
			     365};

static int leapyear[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
static int nonleapyear[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

long
maketime(tp, local)
register struct tm *tp;
int local;
{
    register long retval;
    int foo;
    int *marray;

    if (tp->tm_mon < 0 || tp->tm_mon > 11 ||
	tp->tm_hour < 0 || tp->tm_hour > 23 ||
	tp->tm_min < 0 || tp->tm_min > 59 ||
	tp->tm_sec < 0 || tp->tm_sec > 59) /* out of range */
	return 0;

    retval = 0;
    if (tp->tm_year < 1900)
	foo = tp->tm_year + 1900;
    else
	foo = tp->tm_year;

    if (foo < 1901 || foo > 2038)	/* year is too small/large */
	return 0;

    if (daysinyear(foo) == 366) {
	if (tp->tm_mon > 1)
	    retval+= SECSPERDAY;	/* add leap day */
	marray = leapyear;
    } else
	marray = nonleapyear;

    if (tp->tm_mday < 0 || tp->tm_mday > marray[tp->tm_mon])
	return 0;			/* out of range */

    while (--foo >= 1970)
	retval += daysinyear(foo) * SECSPERDAY;

    retval += cumdays[tp->tm_mon] * SECSPERDAY;
    retval += (tp->tm_mday-1) * SECSPERDAY;
    retval += tp->tm_hour * SECSPERHOUR + tp->tm_min * SECSPERMIN + tp->tm_sec;

    if (local) {
	/* need to use local time, so we retrieve timezone info */
	struct timezone tz;
	struct timeval tv;
	if (gettimeofday(&tv, &tz) < 0) {
	    /* some error--give up? */
	    return(retval);
	}
	retval += tz.tz_minuteswest * SECSPERMIN;
    }
    return(retval);
}

long
time_explode(cp)
register char *cp;
{
    char wbuf[5];
    struct tm tp;
    int local;

    memset((char *)&tp, 0, sizeof(tp));
    
    if (strlen(cp) > 10) {		/* new format */
	(void) strncpy(wbuf, cp, 4);
	wbuf[4] = 0;
	tp.tm_year = atoi(wbuf);
	cp += 4;			/* step over the year */
	local = 0;			/* GMT */
    } else {				/* old format: local time, 
					   year is 2 digits, assuming 19xx */
	wbuf[0] = *cp++;
	wbuf[1] = *cp++;
	wbuf[2] = 0;
	tp.tm_year = 1900 + atoi(wbuf);
	local = 1;			/* local */
    }

    wbuf[0] = *cp++;
    wbuf[1] = *cp++;
    wbuf[2] = 0;
    tp.tm_mon = atoi(wbuf)-1;

    wbuf[0] = *cp++;
    wbuf[1] = *cp++;
    tp.tm_mday = atoi(wbuf);
    
    wbuf[0] = *cp++;
    wbuf[1] = *cp++;
    tp.tm_hour = atoi(wbuf);
    
    wbuf[0] = *cp++;
    wbuf[1] = *cp++;
    tp.tm_min = atoi(wbuf);


    return(maketime(&tp, local));
}

krb5_error_code
process_v4_dump(context, dumpfile, realm)
krb5_context context;
char *dumpfile;
char *realm;
{
    krb5_error_code retval;
    FILE *input_file;
    Principal aprinc;
    char    exp_date_str[50];
    char    mod_date_str[50];
    int     temp1, temp2, temp3;
    long time_explode();

    input_file = fopen(dumpfile, "r");
    if (!input_file)
	return errno;

    for (;;) {			/* explicit break on eof from fscanf */
	int nread;

	memset((char *)&aprinc, 0, sizeof(aprinc));
	nread = fscanf(input_file,
		       "%s %s %d %d %d %hd %x %x %s %s %s %s\n",
		       aprinc.name,
		       aprinc.instance,
		       &temp1,
		       &temp2,
		       &temp3,
		       &aprinc.attributes,
		       &aprinc.key_low,
		       &aprinc.key_high,
		       exp_date_str,
		       mod_date_str,
		       aprinc.mod_name,
		       aprinc.mod_instance);
	if (nread != 12) {
	    retval = nread == EOF ? 0 : KRB5_KDB_DB_CORRUPT;
	    break;
	}
	aprinc.key_low = ntohl (aprinc.key_low);
	aprinc.key_high = ntohl (aprinc.key_high);
	aprinc.max_life = (unsigned char) temp1;
	aprinc.kdc_key_ver = (unsigned char) temp2;
	aprinc.key_version = (unsigned char) temp3;
	aprinc.exp_date = time_explode(exp_date_str);
	aprinc.mod_date = time_explode(mod_date_str);
	if (aprinc.instance[0] == '*')
	    aprinc.instance[0] = '\0';
	if (aprinc.mod_name[0] == '*')
	    aprinc.mod_name[0] = '\0';
	if (aprinc.mod_instance[0] == '*')
	    aprinc.mod_instance[0] = '\0';
	if (retval = enter_in_v5_db(context, realm, &aprinc))
	    break;
    }
    (void) fclose(input_file);
    return retval;
}

krb5_error_code fixup_database(context, realm)
    krb5_context context;
    char * realm;
{
    krb5_db_entry entry;
    krb5_error_code retval;
    int nprincs;
    krb5_boolean more;

    nprincs = 1;
    if (retval = krb5_db_get_principal(context, &tgt_princ, &entry, 
				       &nprincs, &more))
	return retval;
    
    if (nprincs == 0)
	return 0;
    
    entry.attributes |= KRB5_KDB_SUPPORT_DESMD5;
    
    retval = krb5_db_put_principal(context, &entry, &nprincs);
    
    if (nprincs)
	krb5_db_free_principal(context, &entry, nprincs);
    
    return retval;
}

    
