/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
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
#include <krb5/krb5_err.h>
#include <krb5/kdb5_err.h>
#include <krb5/isode_err.h>

#include <com_err.h>

#include <stdio.h>
#include <krb5/ext-proto.h>

#include <sys/param.h>			/* XXX */

extern int errno;

#define DEFAULT_KEYFILE_STUB	"/.k5."

krb5_keyblock master_keyblock;
krb5_principal master_princ;
krb5_encrypt_block master_encblock;

static void
usage(who, status)
char *who;
int status;
{
    fprintf(stderr, "usage: %s [-n dbname] [-r realmname] [-k keytype]\n\
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
    char defkeyfile[MAXPATHLEN];
    char *keyfile = 0;
    FILE *kf;

    int keytypedone = 0, etypedone = 0;
    krb5_enctype etype;

    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();

    while ((optchar = getopt(argc, argv, "n:r:k:M:e:f:")) != EOF) {
	switch(optchar) {
	case 'n':			/* set db name */
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
	    etypedone++;
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

    if (!keyfile) {
	(void) strcpy(defkeyfile, DEFAULT_KEYFILE_STUB);
	(void) strncat(defkeyfile, realm, sizeof(defkeyfile)-sizeof(DEFAULT_KEYFILE_STUB));
	keyfile = defkeyfile;
    }

    /* assemble & parse the master key name */

    if (retval = setup_mkey_name(mkey_name, realm, &mkey_fullname,
				 &master_princ)) {
	com_err(argv[0], retval, "while setting up master key name");
	exit(1);
    }

    if (retval = krb5_db_init()) {
	com_err(argv[0], retval, "while initializing the database '%s'",
		dbname);
	exit(1);
    }

    /* TRUE here means read the keyboard */
    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock, TRUE,
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
    if (!(kf = fopen(keyfile, "w"))) {
	/* error opening */
	com_err(argv[0], errno, "while opening keyfile '%s'",keyfile);
	bzero((char *)master_keyblock.contents, master_keyblock.length);
	(void) krb5_db_fini();
	exit(1);
    }
    if ((fwrite((krb5_pointer) &master_keyblock.keytype,
		sizeof(master_keyblock.keytype),
		1, kf) != 1) ||
	(fwrite((krb5_pointer) &master_keyblock.length,
		sizeof(master_keyblock.length),
		1, kf) != 1) ||
	(fwrite((krb5_pointer) master_keyblock.contents,
		sizeof(master_keyblock.contents[0]),
		master_keyblock.length, kf) != master_keyblock.length)) {
	/* error writing */
	retval = errno;
	com_err(argv[0], retval, "error writing to keyfile '%s'", keyfile);
	(void) fclose(kf);
    cleanup:
	bzero((char *)master_keyblock.contents, master_keyblock.length);
	(void) unlink(keyfile);
	(void) krb5_db_fini();
	exit(1);
    }
    if (fclose(kf) == EOF) {
	retval = errno;
	com_err(argv[0], retval, "closing keyfile '%s'", keyfile);
	goto cleanup;
    }
    bzero((char *)master_keyblock.contents, master_keyblock.length);
    if (retval = krb5_db_fini()) {
	com_err(argv[0], retval, "closing database '%s'", dbname);
	exit(1);
    }

    exit(0);
}
