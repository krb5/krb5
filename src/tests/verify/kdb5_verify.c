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
 * Edit a KDC database.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_verify_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/libos-proto.h>
#include <krb5/asn1.h>
#include <krb5/config.h>
#include <krb5/sysincl.h>		/* for MAXPATHLEN */
#include <krb5/ext-proto.h>

#include <com_err.h>
#include <ss/ss.h>
#include <stdio.h>


#define REALM_SEP	'@'
#define REALM_SEP_STR	"@"

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

int set_dbname_help PROTOTYPE((char *, char *));

static void
usage(who, status)
char *who;
int status;
{
    fprintf(stderr,
	    "usage: %s -p prefix -n num_to_check [-d dbpathname] [-r realmname]\n",
	    who);
    fprintf(stderr, "\t [-D depth] [-k keytype] [-e etype] [-M mkeyname]\n");

    exit(status);
}

krb5_keyblock master_keyblock;
krb5_principal master_princ;
krb5_db_entry master_entry;
krb5_encrypt_block master_encblock;
krb5_pointer master_random;
char *str_master_princ;

static char *progname;
static char *cur_realm = 0;
static char *mkey_name = 0;
static krb5_boolean manual_mkey = FALSE;
static krb5_boolean dbactive = FALSE;

void
quit()
{
    krb5_error_code retval = krb5_db_fini();
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    if (retval) {
	com_err(progname, retval, "while closing database");
	exit(1);
    }
    exit(0);
}

int check_princ PROTOTYPE((char *));

void
main(argc, argv)
int argc;
char *argv[];
{
    extern char *optarg;	
    int optchar, i, n;
    char tmp[4096], tmp2[BUFSIZ], *str_princ;

    krb5_error_code retval;
    char *dbname = 0;
    int keytypedone = 0;
    krb5_enctype etype = 0xffff;
    register krb5_cryptosystem_entry *csentry;
    int num_to_check;
    char principal_string[BUFSIZ];
    char *suffix;
    int depth, errors;

    krb5_init_ets();

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    progname = argv[0];

    memset(principal_string, 0, sizeof(principal_string));
    num_to_check = 0;
    depth = 1;

    while ((optchar = getopt(argc, argv, "D:p:n:d:r:R:k:M:e:m")) != EOF) {
	switch(optchar) {
	case 'D':
	    depth = atoi(optarg);       /* how deep to go */
	    break;
	case 'p':                       /* prefix name to check */
	    strcpy(principal_string, optarg);
	    suffix = principal_string + strlen(principal_string);
	    break;
       case 'n':                        /* how many to check */
	    num_to_check = atoi(optarg);
	    break;
	case 'd':			/* set db name */
	    dbname = optarg;
	    break;
	case 'r':
	    cur_realm = optarg;
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
	    manual_mkey = TRUE;
	    break;
	case '?':
	default:
	    usage(progname, 1);
	    /*NOTREACHED*/
	}
    }

    if (!(num_to_check && principal_string[0])) usage(progname, 1);

    if (!keytypedone)
	master_keyblock.keytype = DEFAULT_KDC_KEYTYPE;

    if (!valid_keytype(master_keyblock.keytype)) {
	com_err(progname, KRB5_PROG_KEYTYPE_NOSUPP,
		"while setting up keytype %d", master_keyblock.keytype);
	exit(1);
    }

    if (etype == 0xffff)
	etype = krb5_keytype_array[master_keyblock.keytype]->system->proto_enctype;

    if (!valid_etype(etype)) {
	com_err(progname, KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", etype);
	exit(1);
    }
    master_encblock.crypto_entry = krb5_csarray[etype]->system;
    csentry = master_encblock.crypto_entry;

    if (!dbname)
	dbname = DEFAULT_DBM_FILE;	/* XXX? */

    if (!cur_realm) {
	if (retval = krb5_get_default_realm(&cur_realm)) {
	    com_err(progname, retval, "while retrieving default realm name");
	    exit(1);
	}	    
    }
    if (retval = set_dbname_help(progname, dbname))
	exit(retval);

    errors = 0;

    fprintf(stdout, "\nChecking ");

    for (n = 1; n <= num_to_check; n++) {
      /* build the new principal name */
      /* we can't pick random names because we need to generate all the names 
	 again given a prefix and count to test the db lib and kdb */
      (void) sprintf(suffix, "%d", n);
      (void) sprintf(tmp, "%s-DEPTH-1", principal_string);
      str_princ = tmp;
      if (check_princ(str_princ)) errors++;

      for (i = 2; i <= depth; i++) {
	tmp2[0] = '\0';
	(void) sprintf(tmp2, "/%s-DEPTH-%d", principal_string, i);
	strcat(tmp, tmp2);
	str_princ = tmp;
	if (check_princ(str_princ)) errors++;
      }
    }

    if (errors)
      fprintf(stdout, "\n%d errors principals failed.\n", errors);
    else
      fprintf(stdout, "\nNo errors.\n");

    (void) (*csentry->finish_key)(&master_encblock);
    (void) (*csentry->finish_random_key)(&master_random);
    retval = krb5_db_fini();
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    if (retval && retval != KRB5_KDB_DBNOTINITED) {
	com_err(progname, retval, "while closing database");
	exit(1);
    }
    exit(0);
}

int
check_princ(DECLARG(char *, str_princ))
OLDDECLARG(char *, str_princ)
{
    krb5_error_code retval;
    krb5_db_entry kdbe;
    krb5_keyblock pwd_key, db_key;
    krb5_data pwd, salt;
    krb5_principal princ;
    krb5_boolean more;
    int nprincs = 1;
    char *str_mod_name;

    fprintf(stderr, "\t%s ...\n", str_princ);

    if (retval = krb5_parse_name(str_princ, &princ)) {
      com_err(progname, retval, "while parsing '%s'", str_princ);
      goto out;
    }

    pwd.data = str_princ;  /* must be able to regenerate */
    pwd.length = strlen(str_princ);

    if (retval = krb5_principal2salt(princ, &salt)) {
	com_err(progname, retval, "while converting principal to salt for '%s'", str_princ);
	goto out;
    }

    retval = krb5_string_to_key(&master_encblock, master_keyblock.keytype,
				&pwd_key,
				&pwd,
				&salt);
    if (retval) {
	com_err(progname, retval, "while converting password to key for '%s'", str_princ);
	goto out;
    }

    if (retval = krb5_db_get_principal(princ, &kdbe, &nprincs, &more)) {
      com_err(progname, retval, "while attempting to verify principal's existence");
      goto out;
    }

    if (nprincs != 1) {
      com_err(progname, 0, "Found more than one db entry for %s.\n", str_princ);
      goto out;
    }

    retval = krb5_kdb_decrypt_key(&master_encblock,
				  &kdbe.key,
				  &db_key);
    if (retval) {
	com_err(progname, retval, "while decrypting key for '%s'", str_princ);
	goto out;
    }

    if ((pwd_key.keytype != db_key.keytype) | 
	(pwd_key.length != db_key.length)) {
      fprintf (stderr, "\tKey types do not agree (%d expected, %d from db)\n",
	       pwd_key.keytype, db_key.keytype);
errout:
      krb5_db_free_principal(&kdbe, nprincs);
      return(-1);
    }
    else {
      if (memcmp((char *)pwd_key.contents, (char *) db_key.contents, pwd_key.length)) {
	fprintf(stderr, "\t key did not match stored value for %s\n", 
		str_princ);
	goto errout;
      }
    }

    free((char *)pwd_key.contents);
    free((char *)db_key.contents);

    if (kdbe.kvno != 0) {
      fprintf(stderr, "\tkvno did not match stored value for %s.\n", str_princ);
      goto errout;
    }

    if (kdbe.max_life != mblock.max_life) {
      fprintf(stderr, "\tmax life did not match stored value for %s.\n", 
	      str_princ);
      goto errout;
    }

    if (kdbe.max_renewable_life != mblock.max_rlife) {
      fprintf(stderr, 
	      "\tmax renewable life did not match stored value for %s.\n",
	      str_princ);
      goto errout;
    }

    if (kdbe.mkvno != mblock.mkvno) {
      fprintf(stderr, "\tmaster keyvno did not match stored value for %s.\n", 
	      str_princ);
      goto errout;
    }

    if (kdbe.expiration != mblock.expiration) {
      fprintf(stderr, "\texpiration time did not match stored value for %s.\n",
	      str_princ);
      goto errout;
    }

    if (retval = krb5_unparse_name(kdbe.mod_name, &str_mod_name))
      com_err(progname, retval, "while unparsing mode name");
    else {
      if (strcmp(str_mod_name, str_master_princ) != 0) {
	fprintf(stderr, "\tmod name isn't the master princ (%s not %s).\n",
		str_mod_name, str_master_princ);
	free(str_mod_name);
	goto errout;
      }
      else free(str_mod_name);
    }

    if (kdbe.attributes != mblock.flags) {
      fprintf(stderr, "\tAttributes did not match stored value for %s.\n",
	      str_princ);
      goto errout;
    }

    out:
    krb5_db_free_principal(&kdbe, nprincs);

    return(0);
}

int
set_dbname_help(pname, dbname)
char *pname;
char *dbname;
{
    krb5_error_code retval;
    int nentries;
    krb5_boolean more;
    register krb5_cryptosystem_entry *csentry;

    csentry = master_encblock.crypto_entry;

    if (retval = krb5_db_set_name(dbname)) {
	com_err(pname, retval, "while setting active database to '%s'",
		dbname);
	return(1);
    }
    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(mkey_name, cur_realm, 0,
					 &master_princ)) {
	com_err(pname, retval, "while setting up master key name");
	return(1);
    }
    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock,
				    manual_mkey,
				    FALSE, &master_keyblock)) {
	com_err(pname, retval, "while reading master key");
	return(1);
    }
    if (retval = krb5_db_init()) {
	com_err(pname, retval, "while initializing database");
	return(1);
    }
    if (retval = krb5_db_verify_master_key(master_princ, &master_keyblock,
					   &master_encblock)) {
	com_err(pname, retval, "while verifying master key");
	(void) krb5_db_fini();
	return(1);
    }
    nentries = 1;
    if (retval = krb5_db_get_principal(master_princ, &master_entry, &nentries,
				       &more)) {
	com_err(pname, retval, "while retrieving master entry");
	(void) krb5_db_fini();
	return(1);
    } else if (more) {
	com_err(pname, KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE,
		"while retrieving master entry");
	(void) krb5_db_fini();
	return(1);
    } else if (!nentries) {
	com_err(pname, KRB5_KDB_NOENTRY, "while retrieving master entry");
	(void) krb5_db_fini();
	return(1);
    }

    if (retval = krb5_unparse_name(master_princ, &str_master_princ)) {
      com_err(pname, retval, "while unparsing master principal");
      krb5_db_fini();
      return(1);
    }

    if (retval = (*csentry->process_key)(&master_encblock,
					 &master_keyblock)) {
	com_err(pname, retval, "while processing master key");
	(void) krb5_db_fini();
	return(1);
    }
    if (retval = (*csentry->init_random_key)(&master_keyblock,
					     &master_random)) {
	com_err(pname, retval, "while initializing random key generator");
	(void) (*csentry->finish_key)(&master_encblock);
	(void) krb5_db_fini();
	return(1);
    }
    mblock.max_life = master_entry.max_life;
    mblock.max_rlife = master_entry.max_renewable_life;
    mblock.expiration = master_entry.expiration;
    /* don't set flags, master has some extra restrictions */
    mblock.mkvno = master_entry.kvno;

    krb5_db_free_principal(&master_entry, nentries);
    dbactive = TRUE;
    return 0;
}

