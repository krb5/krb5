/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Store the master database key in a file.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_stash_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>
#include <krb5/sysincl.h>

#include <com_err.h>
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
\t[-e etype] [-M mkeyname] [-f keyfile]\n",
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
    char *dbname = 0;
    char *realm = 0;
    char *mkey_name = 0;
    char *mkey_fullname;
    char defrealm[BUFSIZ];
    char *keyfile = 0;

    int keytypedone = 0;
    krb5_enctype etype = 0xffff;

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();

    while ((optchar = getopt(argc, argv, "d:r:k:M:e:f:")) != EOF) {
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
	case 'f':
	    keyfile = optarg;
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

    if (etype == 0xffff)
	etype = krb5_keytype_array[master_keyblock.keytype]->system->proto_enctype;

    if (!valid_etype(etype)) {
	com_err(argv[0], KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", etype);
	exit(1);
    }

    krb5_use_cstype(&master_encblock, etype);

    if (!dbname)
	dbname = DEFAULT_DBM_FILE;	/* XXX? */

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

    if (retval = krb5_db_init()) {
	com_err(argv[0], retval, "while initializing the database '%s'",
		dbname);
	exit(1);
    }

    /* TRUE here means read the keyboard, but only once */
    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock, TRUE,
				    FALSE,
				    &master_keyblock)) {
	com_err(argv[0], retval, "while reading master key");
	(void) krb5_db_fini();
	exit(1);
    }
    if (retval = krb5_db_verify_master_key(master_princ, &master_keyblock,
					   &master_encblock)) {
	com_err(argv[0], retval, "while verifying master key");
	(void) krb5_db_fini();
	exit(1);
    }	
    if (retval = krb5_db_store_mkey(keyfile, master_princ, &master_keyblock)) {
	com_err(argv[0], errno, "while storing key");
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	(void) krb5_db_fini();
	exit(1);
    }
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    if (retval = krb5_db_fini()) {
	com_err(argv[0], retval, "closing database '%s'", dbname);
	exit(1);
    }

    exit(0);
}
