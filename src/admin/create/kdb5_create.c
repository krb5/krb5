/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Generate (from scratch) a Kerberos KDC database.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_create_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/libos-proto.h>
#include <krb5/asn1.h>
#include <krb5/osconf.h>

#include <com_err.h>
#include <stdio.h>


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
    fprintf(stderr, "usage: %s [-d dbpathname] [-r realmname] [-k keytype]\n\
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
    char *realm = 0;
    char *mkey_name = 0;
    char *mkey_fullname;
    char *defrealm;
    int keytypedone = 0;
    krb5_enctype etype = 0xffff;

    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    while ((optchar = getopt(argc, argv, "d:r:k:M:e:")) != EOF) {
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
	case 'e':
	    etype = atoi(optarg);
	    break;
	case '?':
	default:
	    usage(argv[0], 1);
	    /*NOTREACHED*/
	}
    }

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
    krb5_use_cstype(&master_encblock, etype);

    if (!dbname)
	dbname = DEFAULT_DBM_FILE;	/* XXX? */

    retval = krb5_db_set_name(dbname);
    if (!retval) retval = EEXIST;

    if (retval == EEXIST || retval == EACCES || retval == EPERM) {
	/* it exists ! */
	com_err(argv[0], 0, "The database '%s' appears to already exist",
		dbname);
	exit(1);
    }
    if (!realm) {
	if (retval = krb5_get_default_realm(&defrealm)) {
	    com_err(argv[0], retval, "while retrieving default realm name");
	    exit(1);
	}	    
	realm = defrealm;
    }

    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(mkey_name, realm, &mkey_fullname,
				 &master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
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
	com_err(argv[0], retval, "while reading master key");
	exit(1);
    }
    if (retval = krb5_process_key(&master_encblock, &master_keyblock)) {
	com_err(argv[0], retval, "while processing master key");
	exit(1);
    }

    rblock.eblock = &master_encblock;
    if (retval = krb5_init_random_key(&master_encblock, &master_keyblock,
				      &rblock.rseed)) {
	com_err(argv[0], retval, "while initializing random key generator");
	(void) krb5_finish_key(&master_encblock);
	exit(1);
    }
    if (retval = krb5_db_create(dbname)) {
	(void) krb5_finish_key(&master_encblock);
	(void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
	com_err(argv[0], retval, "while creating database '%s'",
		dbname);
	exit(1);
    }
    if (retval = krb5_db_set_name(dbname)) {
	(void) krb5_finish_key(&master_encblock);
	(void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
        com_err(argv[0], retval, "while setting active database to '%s'",
                dbname);
        exit(1);
    }
    if (retval = krb5_db_init()) {
	(void) krb5_finish_key(&master_encblock);
	(void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
	com_err(argv[0], retval, "while initializing the database '%s'",
		dbname);
	exit(1);
    }

    if ((retval = add_principal(master_princ, MASTER_KEY, &rblock)) ||
	(retval = add_principal(tgt_princ, RANDOM_KEY, &rblock))) {
	(void) krb5_db_fini();
	(void) krb5_finish_key(&master_encblock);
	(void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
	com_err(argv[0], retval, "while adding entries to the database");
	exit(1);
    }
    /* clean up */
    (void) krb5_db_fini();
    (void) krb5_finish_key(&master_encblock);
    (void) krb5_finish_random_key(&master_encblock, &rblock.rseed);
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
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
