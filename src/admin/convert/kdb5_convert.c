/*
 * $Source$
 * $Author$
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
 * Generate (from scratch) a Kerberos V5 KDC database, filling it in with the
 * entries from a V4 database.
 * You'd better have NDBM if you're doing this!
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_create_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <des.h>
#include <krb.h>
#include <krb_db.h>
/* MKEYFILE is now defined in kdc.h */
#include <kdc.h>

static C_Block master_key;
static Key_schedule master_key_schedule;
static long master_key_version;

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/los-proto.h>
#include <krb5/asn1.h>
#include <krb5/osconf.h>

#include <com_err.h>
#include <stdio.h>

#include <krb5/ext-proto.h>

#ifdef ODBM
#error:  This program cannot work properly with a DBM database unless it has the NDBM package
/* This is because the program opens both databases simultaneously,
   and the old DBM does not support multiple simultaneous databases. */
#endif

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


static krb5_error_code add_principal PROTOTYPE((krb5_principal, enum ap_op,
						struct realm_info *));
void v4cleanup PROTOTYPE((void));
int v4init PROTOTYPE((char *, char *, int));
krb5_error_code enter_in_v5_db PROTOTYPE((char *, Principal *));

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
    fprintf(stderr, "usage: %s [-d v5dbpathname] [-D v4dbpathname] [-n] [-r realmname] [-k keytype]\n\
\t[-e etype] [-M mkeyname]\n",
	    who);
    exit(status);
}

krb5_keyblock master_keyblock;
krb5_principal master_princ;
krb5_encrypt_block master_encblock;

krb5_data tgt_princ_entries[] = {
	{0, 0},
	{sizeof(TGTNAME)-1, TGTNAME} };

krb5_data db_creator_entries[] = {
	{sizeof("db_creation")-1, "db_creation"} };

/* XXX knows about contents of krb5_principal, and that tgt names
 are of form TGT/REALM@REALM */
krb5_data *tgt_princ[] = {
	&tgt_princ_entries[0],
	&tgt_princ_entries[1],
	&tgt_princ_entries[0],
	0 };

krb5_data *db_create_princ[] = {
	&tgt_princ_entries[0],
	&db_creator_entries[0],
	0 };

void
main(argc, argv)
int argc;
char *argv[];
{
    extern char *optarg;	
    int optchar;
    
    krb5_error_code retval;
    char *dbname = 0;
    char *v4dbname = 0;
    char *realm = 0;
    char *mkey_name = 0;
    char *mkey_fullname;
    char *defrealm;
    int keytypedone = 0;
    int v4manual = 0;
    krb5_enctype etype = 0xffff;

    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    while ((optchar = getopt(argc, argv, "d:D:r:k:M:e:n")) != EOF) {
	switch(optchar) {
	case 'd':			/* set db name */
	    dbname = optarg;
	    break;
	case 'D':			/* set db name */
	    v4dbname = optarg;
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
	case 'e':
	    etype = atoi(optarg);
	    break;
	case 'n':
	    v4manual++;
	    break;
	case '?':
	default:
	    usage(PROGNAME, 1);
	    /*NOTREACHED*/
	}
    }

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
    krb5_use_cstype(&master_encblock, etype);

    if (!dbname)
	dbname = DEFAULT_DBM_FILE;	/* XXX? */

    retval = krb5_db_set_name(dbname);
    if (!retval) retval = EEXIST;

    if (retval == EEXIST || retval == EACCES || retval == EPERM) {
	/* it exists ! */
	com_err(PROGNAME, 0, "The database '%s' appears to already exist",
		dbname);
	exit(1);
    }
    if (!realm) {
	if (retval = krb5_get_default_realm(&defrealm)) {
	    com_err(PROGNAME, retval, "while retrieving default realm name");
	    exit(1);
	}	    
	realm = defrealm;
    }

    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(mkey_name, realm, &mkey_fullname,
				 &master_princ)) {
	com_err(PROGNAME, retval, "while setting up master key name");
	exit(1);
    }

    tgt_princ[0]->data = realm;
    tgt_princ[0]->length = strlen(realm);

    printf("Initializing database '%s' for realm '%s',\n\
master key name '%s'\n",
	   dbname, realm, mkey_fullname);

    printf("You will be prompted for the database Master Password.\n");
    printf("It is important that you NOT FORGET this password.\n");
    fflush(stdout);

    /* TRUE here means read the keyboard, and do it twice */
    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock, TRUE, TRUE,
				    &master_keyblock)) {
	com_err(PROGNAME, retval, "while reading master key");
	exit(1);
    }
    if (retval = krb5_process_key(&master_encblock, &master_keyblock)) {
	com_err(PROGNAME, retval, "while processing master key");
	exit(1);
    }

    rblock.eblock = &master_encblock;
    if (retval = krb5_init_random_key(&master_encblock, &master_keyblock,
				      &rblock.rseed)) {
	com_err(PROGNAME, retval, "while initializing random key generator");
	(void) krb5_finish_key(&master_encblock);
	exit(1);
    }
    if (retval = krb5_db_create(dbname)) {
	(void) krb5_finish_key(&master_encblock);
	(void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
	com_err(PROGNAME, retval, "while creating database '%s'",
		dbname);
	exit(1);
    }
    if (retval = krb5_db_set_name(dbname)) {
	(void) krb5_finish_key(&master_encblock);
	(void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
        com_err(PROGNAME, retval, "while setting active database to '%s'",
                dbname);
        exit(1);
    }
    if (v4init(PROGNAME, v4dbname, v4manual)) {
	(void) krb5_finish_key(&master_encblock);
	(void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
	exit(1);
    }
    if (retval = krb5_db_init()) {
	(void) krb5_finish_key(&master_encblock);
	(void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
	com_err(PROGNAME, retval, "while initializing the database '%s'",
		dbname);
	exit(1);
    }

    if ((retval = add_principal(master_princ, MASTER_KEY, &rblock)) ||
	(retval = add_principal(tgt_princ, RANDOM_KEY, &rblock))) {
	(void) krb5_db_fini();
	(void) krb5_finish_key(&master_encblock);
	(void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
	com_err(PROGNAME, retval, "while adding entries to the database");
	exit(1);
    }
    if (retval = kerb_db_iterate(enter_in_v5_db, realm)) {
	com_err(PROGNAME, retval, "while translating entries to the database");
    }
    putchar('\n');
    /* clean up */
    (void) krb5_db_fini();
    (void) krb5_finish_key(&master_encblock);
    (void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    exit(retval ? 1 : 0);
}

void
v4cleanup()
{
    return;
}

int
v4init(pname, name, manual)
char *pname, *name;
int manual;
{
    kerb_init();
    if (name) {
	if (kerb_db_set_name(name) != 0) {
	    com_err(pname, 0,
		    "Could not open alternate v4 database name %s\n",
		    name);
	    return 1;
	}
    }
    if (kdb_get_master_key ((manual == 0), 
			    master_key, master_key_schedule) != 0) {
	com_err(pname, 0, "Couldn't read v4 master key.");
	return 1;
    }
    if ((master_key_version = kdb_verify_master_key(master_key,
						    master_key_schedule,
						    stdout)) < 0) {
	com_err(pname, 0, "Couldn't verify v4 master key.");
	return 1;
    }
    return 0;
}

krb5_error_code
enter_in_v5_db(realm, princ)
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

    /* don't convert certain principals... */
    if (!strcmp(princ->name, "krbtgt") ||
	(!strcmp(princ->name, KERB_M_NAME) &&
	 !strcmp(princ->instance, KERB_M_INST))) {
	printf("\nignoring '%s.%s' ...", princ->name, princ->instance);
	return 0;
    }
    if (retval = krb5_build_principal(&entry.principal, strlen(realm),
				      realm, princ->name,
				      princ->instance[0] ? princ->instance : 0,
				      0))
	return retval;
    if (retval = krb5_unparse_name(entry.principal, &name))
	name = strdup("<not unparsable name!>");
    printf("\ntranslating %s...", name);
    free(name);

    if (retval = krb5_build_principal(&entry.mod_name, strlen(realm),
				      realm, princ->mod_name,
				      princ->mod_instance[0] ? princ->instance : 0,
				      0)) {
	krb5_free_principal(entry.principal);
	return retval;
    }

    entry.kvno = princ->key_version;
    entry.max_life = princ->max_life * 60 * 5;
    entry.max_renewable_life = rblock.max_rlife;
    entry.mkvno = 0;
    entry.expiration = princ->exp_date;
    entry.mod_date = princ->mod_date;
    entry.attributes = rblock.flags;	/* XXX is there a way to convert
					   the old attrs? */

    bcopy((char *)&(princ->key_low), (char *)v4key, 4);
    bcopy((char *)&(princ->key_high), (char *) (((long *) v4key) + 1), 4);
    kdb_encrypt_key (v4key, v4key, master_key, master_key_schedule, DECRYPT);

    v4v5key.contents = (krb5_octet *)v4key;
    v4v5key.keytype = KEYTYPE_DES;
    v4v5key.length = sizeof(v4key);

    retval = krb5_kdb_encrypt_key(rblock.eblock, &v4v5key, &ekey);
    if (retval) {
	krb5_free_principal(entry.principal);
	krb5_free_principal(entry.mod_name);
	return retval;
    }
    memset((char *)v4key, 0, sizeof(v4key));
    entry.key = ekey;
    entry.salt_type = KRB5_KDB_SALTTYPE_V4;
    entry.salt_length = 0;
    entry.salt = 0;

    if (retval = krb5_db_put_principal(&entry, &nentries)) {
	krb5_free_principal(entry.principal);
	krb5_free_principal(entry.mod_name);
	return retval;
    }
    xfree(ekey.contents);
    return 0;
}

static krb5_error_code
add_principal(princ, op, pblock)
krb5_principal princ;
enum ap_op op;
struct realm_info *pblock;
{
    krb5_db_entry entry;
    krb5_error_code retval;
    krb5_encrypted_keyblock ekey;
    krb5_keyblock *rkey;
    int nentries = 1;

    entry.principal = princ;
    entry.kvno = 0;
    entry.max_life = pblock->max_life;
    entry.max_renewable_life = pblock->max_rlife;
    entry.mkvno = 0;
    entry.expiration = pblock->expiration;
    entry.mod_name = db_create_princ;

    if (retval = krb5_timeofday(&entry.mod_date))
	return retval;
    entry.attributes = pblock->flags;

    switch (op) {
    case MASTER_KEY:
	entry.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	if (retval = krb5_kdb_encrypt_key(pblock->eblock,
					  &master_keyblock,
					  &ekey))
	    return retval;
	break;
    case RANDOM_KEY:
	if (retval = krb5_random_key(pblock->eblock, pblock->rseed, &rkey))
	    return retval;
	retval = krb5_kdb_encrypt_key(pblock->eblock, rkey, &ekey);
	krb5_free_keyblock(rkey);
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

    if (retval = krb5_db_put_principal(&entry, &nentries))
	return retval;

    xfree(ekey.contents);
    return 0;
}
