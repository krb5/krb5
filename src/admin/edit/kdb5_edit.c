/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Edit a KDC database.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_edit_c[] =
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
#include <krb5/asn1.h>

#include <com_err.h>
#include <ss/ss.h>
#include <errno.h>

#include <krb5/ext-proto.h>

struct mblock {
    krb5_deltat max_life;
    krb5_deltat max_rlife;
    krb5_timestamp expiration;
    krb5_flags flags;
    krb5_kvno mkvno;
} mblock = {				/* XXX */
    KRB5_KDB_MAX_LIFE,
    KRB5_KDB_MAX_RLIFE,
    KRB5_KDB_EXPIRATION,
    KRB5_KDB_DEF_FLAGS,
    0
};

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
krb5_db_entry master_entry;
krb5_encrypt_block master_encblock;

extern ss_request_table kdb5_edit_cmds;

extern char *krb5_default_pwd_prompt1, *krb5_default_pwd_prompt2;

static char *progname;

void
quit()
{
    krb5_error_code retval = krb5_db_fini();
    bzero((char *)master_keyblock.contents, master_keyblock.length);
    if (retval) {
	com_err(progname, retval, "while closing database");
	exit(1);
    }
    exit(0);
}

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
    int keytypedone = 0;
    krb5_boolean manual = FALSE;
    krb5_enctype etype = -1;
    register krb5_cryptosystem_entry *csentry;
    int sci_idx;
    krb5_boolean more;
    int nentries;

    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();

    if (rindex(argv[0], '/'))
	argv[0] = rindex(argv[0], '/')+1;

    progname = argv[0];

    while ((optchar = getopt(argc, argv, "d:r:k:M:e:m")) != EOF) {
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
	case 'm':
	    manual = TRUE;
	    break;
	case '?':
	default:
	    usage(argv[0], 1);
	    /*NOTREACHED*/
	}
    }

    if (!keytypedone)
	master_keyblock.keytype = KEYTYPE_DES;

    if (!valid_keytype(master_keyblock.keytype)) {
	com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP,
		"while setting up keytype %d", master_keyblock.keytype);
	exit(1);
    }

    if (etype == -1)
	etype = krb5_keytype_array[master_keyblock.keytype]->system->proto_enctype;

    if (!valid_etype(etype)) {
	com_err(argv[0], KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", etype);
	exit(1);
    }
    master_encblock.crypto_entry = krb5_csarray[etype]->system;
    csentry = master_encblock.crypto_entry;

    if (!dbname)
	dbname = DEFAULT_DBM_FILE;	/* XXX? */

    sci_idx = ss_create_invocation("kdb5_edit", "5.0", (char *) NULL,
				   &kdb5_edit_cmds, &retval);
    if (retval) {
	ss_perror(sci_idx, retval, "creating invocation");
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

    if (retval = krb5_db_setup_mkey_name(mkey_name, realm, &mkey_fullname,
					 &master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
	exit(1);
    }
    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock, manual,
				    &master_keyblock)) {
	com_err(argv[0], retval, "while reading master key");
	exit(1);
    }
    if (retval = krb5_db_init()) {
	com_err(argv[0], retval, "while initializing database");
	exit(1);
    }
    if (retval = krb5_db_verify_master_key(master_princ, &master_keyblock,
					   &master_encblock)) {
	com_err(argv[0], retval, "while verifying master key");
	(void) krb5_db_fini();
	exit(1);
    }
    nentries = 1;
    if (retval = krb5_db_get_principal(master_princ, &master_entry, &nentries,
				       &more)) {
	com_err(argv[0], retval, "while retrieving master entry");
	(void) krb5_db_fini();
	exit(1);
    }
    if (retval = (*master_encblock.crypto_entry->process_key)(&master_encblock,
							      &master_keyblock)) {
	com_err(argv[0], retval, "while processing master key");
	(void) krb5_db_fini();
	exit(1);
    }

    mblock.max_life = master_entry.max_life;
    mblock.max_rlife = master_entry.max_renewable_life;
    mblock.expiration = master_entry.expiration;
    /* don't set flags, master has some extra restrictions */
    mblock.mkvno = master_entry.kvno;

    ss_listen(sci_idx, &retval);
    printf("\n");
    (void) (*master_encblock.crypto_entry->finish_key)(&master_encblock);
    retval = krb5_db_fini();
    bzero((char *)master_keyblock.contents, master_keyblock.length);
    if (retval) {
	com_err(progname, retval, "while closing database");
	exit(1);
    }
    exit(0);
}

krb5_error_code
add_new_key(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    krb5_keyblock tempkey;
    krb5_principal newprinc;
    krb5_db_entry newentry;
    krb5_data pwd;
    char password[BUFSIZ];
    int pwsize = sizeof(password);
    int one = 1;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: add_new_key principal");
	return 1;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	return 1;
    }
    if (retval = krb5_read_password(krb5_default_pwd_prompt1,
				    krb5_default_pwd_prompt2,
				    password, &pwsize)) {
	com_err(argv[0], retval, "while reading password for '%s'", argv[1]);
	krb5_free_principal(newprinc);
	return 1;
    }
    pwd.data = password;
    pwd.length = pwsize;

    retval = (*master_encblock.crypto_entry->
	      string_to_key)(master_keyblock.keytype,
			     &tempkey,
			     &pwd,
			     newprinc);
    bzero(password, sizeof(password)); /* erase it */
    if (retval) {
	com_err(argv[0], retval, "while converting password to key for '%s'", argv[1]);
	krb5_free_principal(newprinc);
	return 1;
    }
    retval = krb5_kdb_encrypt_key(&master_encblock,
				  &tempkey,
				  &newentry.key);
    bzero((char *)tempkey.contents, tempkey.length);
    free((char *)tempkey.contents);
    if (retval) {
	com_err(argv[0], retval, "while encrypting key for '%s'", argv[1]);
	krb5_free_principal(newprinc);
	return 1;
    }
    newentry.principal = newprinc;
    newentry.kvno = 1;
    newentry.max_life = mblock.max_life;
    newentry.max_renewable_life = mblock.max_rlife;
    newentry.mkvno = mblock.mkvno;
    newentry.expiration = mblock.expiration;
    newentry.mod_name = master_princ;
    if (retval = krb5_timeofday(&newentry.mod_date)) {
	com_err(argv[0], retval, "while fetching date");
	bzero((char *)newentry.key.contents, newentry.key.length);
	free((char *)newentry.key.contents);
	krb5_free_principal(newprinc);
	return 1;
    }
    newentry.attributes = mblock.flags;
    
    if (retval = krb5_db_put_principal(&newentry, &one)) {
	com_err(argv[0], retval, "while storing entry for '%s'\n", argv[1]);
	krb5_free_principal(newprinc);
	bzero((char *)newentry.key.contents, newentry.key.length);
	free((char *)newentry.key.contents);
	return 1;
    }
    bzero((char *)newentry.key.contents, newentry.key.length);
    free((char *)newentry.key.contents);
    krb5_free_principal(newprinc);
    if (one != 1) {
	com_err(argv[0], 0, "entry not stored in database (unknown failure)");
	return 1;
    }
    return 0;
}
