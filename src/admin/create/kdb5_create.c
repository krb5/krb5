/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Generate (from scratch) a Kerberos KDC database.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_create_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/krb5_err.h>
#include <krb5/kdb5_err.h>
#include <krb5/isode_err.h>
#include <stdio.h>
#include <krb5/libos-proto.h>

#include <com_err.h>
#include <errno.h>

#include <krb5/ext-proto.h>

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
    fprintf(stderr, "usage: %s [-n dbname] [-r realmname] [-t keytype] [-e etype]\n",
	    who);
    exit(status);
}

krb5_keyblock master_keyblock;
krb5_principal master_princ;
krb5_encrypt_block master_encblock;

krb5_data tgt_princ_entries[] = {
	{0, 0},
	{sizeof(TGTNAME), TGTNAME} };

krb5_data db_creator_entries[] = {
	{sizeof("db_creation"), "db_creation"} };

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
    char *realm = 0;
    char *mkey_name = 0;
    char *mkey_fullname;
    char defrealm[BUFSIZ];
    int keytypedone = 0, etypedone = 0;
    krb5_enctype etype;
    register krb5_cryptosystem_entry *csentry;

    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();

    while ((optchar = getopt(argc, argv, "n:r:t:M:e:")) != EOF) {
	switch(optchar) {
	case 'n':			/* set db name */
	    dbname = optarg;
	    break;
	case 'r':
	    realm = optarg;
	    break;
	case 't':
	    master_keyblock.keytype = atoi(optarg);
	    keytypedone++;
	    break;
	case 'M':			/* master key name in DB */
	    mkey_name = optarg;
	    break;
	case 'e':
	    etype = atoi(optarg);
	    etypedone++;
	    break;
	case '?':
	default:
	    usage(argv[0], 1);
	    /*NOTREACHED*/
	}
    }
    if (!mkey_name)
	mkey_name = KRB5_KDB_M_NAME;

    if (!keytypedone)
	master_keyblock.keytype = KEYTYPE_DES;

    if (!valid_keytype(master_keyblock.keytype)) {
	com_err(argv[0], KRB5KDC_ERR_ETYPE_NOSUPP,
		"while setting up keytype %d", master_keyblock.keytype);
	exit(1);
    }

    if (!etypedone)
	etype = keytype_to_etype(master_keyblock.keytype);

    if (!valid_etype(etype)) {
	com_err(argv[0], KRB5KDC_ERR_ETYPE_NOSUPP,
		"while setting up etype %d", etype);
	exit(1);
    }
    master_encblock.crypto_entry = krb5_csarray[etype]->system;
    csentry = master_encblock.crypto_entry;

    if (!dbname)
	dbname = DEFAULT_DBM_FILE;	/* XXX? */

    if (retval = krb5_db_create(dbname)) {
	com_err(argv[0], retval, "while creating database '%s'",
		dbname);
	exit(1);
    }
    if (retval = krb5_db_set_name(dbname)) {
	com_err(argv[0], retval, "while setting active database to '%s'",
		dbname);
	exit(1);
    }
    if (!realm) {
	if (retval = krb5_get_default_realm(sizeof(defrealm), defrealm)) {
	    com_err(argv[0], retval, "while retrieving default realm name");
	    exit(1);
	}	    
	realm = defrealm;
    }

    /* assemble & parse the master key name */

    if (retval = setup_mkey_name(mkey_name, realm, &mkey_fullname,
				 &master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
	exit(1);
    }

    tgt_princ[0]->data = realm;
    tgt_princ[0]->length = strlen(realm);

    printf("Initializing database '%s' for realm '%s', master key name '%s'\n",
	   dbname, realm, mkey_fullname);

    printf("You will be prompted for the database Master Password.\n");
    printf("It is important that you NOT FORGET this password.\n");
    fflush(stdout);

    /* TRUE here means read the keyboard */
    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock, TRUE,
				    &master_keyblock)) {
	com_err(argv[0], retval, "while reading master key");
	exit(1);
    }
    if (retval = (*csentry->process_key)(&master_encblock,
						 &master_keyblock)) {
	com_err(argv[0], retval, "while processing master key");
	exit(1);
    }

    rblock.eblock = &master_encblock;
    if (retval = (*csentry->init_random_key)(&master_keyblock,
						     &rblock.rseed)) {
	com_err(argv[0], retval, "while initializing random key generator");
	(void) (*csentry->finish_key)(&master_encblock);
	exit(1);
    }
    if (retval = krb5_db_init()) {
	(void) (*csentry->finish_key)(&master_encblock);
	(void) (*csentry->finish_random_key)(&rblock.rseed);
	com_err(argv[0], retval, "while initializing the database");
	exit(1);
    }

    if ((retval = add_principal(master_princ, MASTER_KEY, &rblock)) ||
	(retval = add_principal(tgt_princ, RANDOM_KEY, &rblock))) {
	(void) krb5_db_fini();
	(void) (*csentry->finish_key)(&master_encblock);
	(void) (*csentry->finish_random_key)(&rblock.rseed);
	com_err(argv[0], retval, "while adding entries to the database");
	exit(1);
    }
    /* clean up */
    (void) krb5_db_fini();
    (void) (*csentry->finish_key)(&master_encblock);
    (void) (*csentry->finish_random_key)(&rblock.rseed);
    bzero((char *)master_keyblock.contents, master_keyblock.length);
    exit(0);

}

static krb5_error_code
add_principal(princ, op, pblock)
krb5_principal princ;
enum ap_op op;
struct realm_info *pblock;
{
    krb5_db_entry entry;
    krb5_error_code retval;
    krb5_keyblock ekey;
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
	if (retval = krb5_kdb_encrypt_key(pblock->eblock,
					  &master_keyblock,
					  &ekey))
	    return retval;
	break;
    case RANDOM_KEY:
	if (retval = (*pblock->eblock->crypto_entry->random_key)(pblock->rseed,
								 &rkey))
	    return retval;
	ekey = *rkey;
	free((char *)rkey);
	break;
    case NULL_KEY:
	return EOPNOTSUPP;
    default:
	break;
    }
    entry.key = ekey;

    if (retval = krb5_db_put_principal(&entry, &nentries))
	return retval;

    free((char *)ekey.contents);
    return 0;
}
