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

void add_key PROTOTYPE((char * const *, const krb5_principal,
			const krb5_keyblock *, krb5_kvno));
void enter_rnd_key PROTOTYPE((char **, const krb5_principal, krb5_kvno));
void enter_pwd_key PROTOTYPE((char **, const krb5_principal, const krb5_principal, krb5_kvno));

int set_dbname_help PROTOTYPE((char *, char *));

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
krb5_pointer master_random;

extern ss_request_table kdb5_edit_cmds;

extern char *krb5_default_pwd_prompt1, *krb5_default_pwd_prompt2;

static char *progname;
static char *cur_realm = 0;
static char *mkey_name = 0;
static krb5_boolean manual_mkey = FALSE;
static krb5_boolean dbactive = FALSE;

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
    char defrealm[BUFSIZ];
    int keytypedone = 0;
    krb5_enctype etype = -1;
    register krb5_cryptosystem_entry *csentry;
    int sci_idx;

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

    if (!cur_realm) {
	if (retval = krb5_get_default_realm(sizeof(defrealm), defrealm)) {
	    com_err(argv[0], retval, "while retrieving default realm name");
	    exit(1);
	}	    
	cur_realm = defrealm;
    }
    if (retval = set_dbname_help(argv[0], dbname))
	exit(retval);

    ss_listen(sci_idx, &retval);
    (void) (*csentry->finish_key)(&master_encblock);
    (void) (*csentry->finish_random_key)(&master_random);
    retval = krb5_db_fini();
    bzero((char *)master_keyblock.contents, master_keyblock.length);
    if (retval && retval != KRB5_KDB_DBNOTINITED) {
	com_err(progname, retval, "while closing database");
	exit(1);
    }
    exit(0);
}

krb5_kvno
princ_exists(pname, principal)
char *pname;
krb5_principal principal;
{
    int nprincs = 1;
    krb5_db_entry entry;
    krb5_boolean more;
    krb5_error_code retval;
    krb5_kvno vno;

    if (retval = krb5_db_get_principal(principal, &entry, &nprincs, &more)) {
	com_err(pname, retval, "while attempting to verify principal's existence");
	return 0;
    }
    vno = entry.kvno;
    krb5_db_free_principal(&entry, nprincs);
    if (nprincs)
	return vno;
    else
	return 0;
}

void
add_new_key(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	return;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	return;
    }
    if (princ_exists(argv[0], newprinc)) {
	com_err(argv[0], 0, "principal '%s' already exists", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    enter_pwd_key(argv, newprinc, newprinc, 0);
    krb5_free_principal(newprinc);
    return;
}

void
add_v4_key(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	return;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	return;
    }
    if (princ_exists(argv[0], newprinc)) {
	com_err(argv[0], 0, "principal '%s' already exists", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    enter_pwd_key(argv, newprinc, 0, 0);
    krb5_free_principal(newprinc);
    return;
}

void
add_rnd_key(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;
    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	return;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	return;
    }
    if (princ_exists(argv[0], newprinc)) {
	com_err(argv[0], 0, "principal '%s' already exists", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    enter_rnd_key(argv, newprinc, 0);
    krb5_free_principal(newprinc);
    return;
}

void
add_key(DECLARG(char * const *, argv),
	DECLARG(const krb5_principal, principal),
	DECLARG(const krb5_keyblock *, key),
	DECLARG(krb5_kvno, vno))
OLDDECLARG(char * const *, argv)
OLDDECLARG(const krb5_principal, principal)
OLDDECLARG(const krb5_keyblock *, key)
OLDDECLARG(krb5_kvno, vno)
{
    krb5_error_code retval;
    krb5_db_entry newentry;
    int one = 1;

    newentry.key = *key;
    retval = krb5_kdb_encrypt_key(&master_encblock,
				  key,
				  &newentry.key);
    if (retval) {
	com_err(argv[0], retval, "while encrypting key for '%s'", argv[1]);
	return;
    }
    newentry.principal = principal;
    newentry.kvno = vno;
    newentry.max_life = mblock.max_life;
    newentry.max_renewable_life = mblock.max_rlife;
    newentry.mkvno = mblock.mkvno;
    newentry.expiration = mblock.expiration;
    newentry.mod_name = master_princ;
    if (retval = krb5_timeofday(&newentry.mod_date)) {
	com_err(argv[0], retval, "while fetching date");
	bzero((char *)newentry.key.contents, newentry.key.length);
	free((char *)newentry.key.contents);
	return;
    }
    newentry.attributes = mblock.flags;
    
    retval = krb5_db_put_principal(&newentry, &one);
    bzero((char *)newentry.key.contents, newentry.key.length);
    free((char *)newentry.key.contents);
    if (retval) {
	com_err(argv[0], retval, "while storing entry for '%s'\n", argv[1]);
	return;
    }
    if (one != 1)
	com_err(argv[0], 0, "entry not stored in database (unknown failure)");
    return;
}

void
set_dbname(argc, argv, sci_idx, infop)
int argc;
char *argv[];
int sci_idx;
krb5_pointer infop;
{
    krb5_error_code retval;
    register krb5_cryptosystem_entry *csentry;

    csentry = master_encblock.crypto_entry;

    if (argc < 3) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s dbpathname realmname", argv[0]);
	return;
    }
    if (dbactive) {
	if ((retval = krb5_db_fini()) && retval != KRB5_KDB_DBNOTINITED) {
	    com_err(argv[0], retval, "while closing previous database");
	    return;
	}
	(void) (*csentry->finish_key)(&master_encblock);
	(void) (*csentry->finish_random_key)(&master_random);
	krb5_free_principal(master_princ);
	dbactive = FALSE;
    }
    cur_realm = malloc(strlen(argv[2])+1);
    if (!cur_realm) {
	com_err(argv[0], 0, "Insufficient memory to proceed");
	ss_quit(argc, argv, sci_idx, infop);
	/*NOTREACHED*/
	return;
    }
    (void) strcpy(cur_realm, argv[2]);
    (void) set_dbname_help(argv[0], argv[1]);
    return;
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

extern krb5_kt_ops krb5_ktf_writable_ops;

/* this brings in only the writable keytab version, replacing ktdir.c */
static krb5_kt_ops *krb5_kt_dir_array[] = {
    &krb5_ktf_writable_ops,
    0
};

krb5_kt_ops **krb5_kt_directory = krb5_kt_dir_array;

void
extract_srvtab(argc, argv)
int argc;
char *argv[];
{
    char ktname[MAXPATHLEN+sizeof("WRFILE:")+1];
    krb5_keytab ktid;
    krb5_error_code retval;
    krb5_principal princ;
    krb5_db_entry dbentry;
    char *pname;
    register int i;
    int nentries;
    krb5_boolean more;
    krb5_keytab_entry newentry;

    if (argc < 3) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s instance name [name ...]", argv[0]);
	return;
    }

    bzero(ktname, sizeof(ktname));
    strcpy(ktname, "WRFILE:");
    if (strlen(argv[1])+sizeof("WRFILE:")+sizeof("-new-srvtab") >= sizeof(ktname)) {
	com_err(argv[0], 0,
		"Instance name '%s' is too long to form a filename", argv[1]);
	com_err(argv[0], 0, "using 'foobar' instead.");
	strcat(ktname, "foobar");
    } else
	strcat(ktname, argv[1]);

    strcat(ktname, "-new-srvtab");
    if (retval = krb5_kt_resolve(ktname, &ktid)) {
	com_err(argv[0], retval, "while resolving keytab name '%s'", ktname);
	return;
    }

    for (i = 2; i < argc; i++) {
	/* iterate over the names */
	pname = malloc(strlen(argv[1])+strlen(argv[i])+strlen(cur_realm)+3);
	if (!pname) {
	    com_err(argv[0], ENOMEM,
		    "while preparing to extract key for %s/%s",
		    argv[i], argv[1]);
	    continue;
	}
	strcpy(pname, argv[i]);
	strcat(pname, "/");
	strcat(pname, argv[1]);
	if (!strchr(argv[1], REALM_SEP)) {
	    strcat(pname, REALM_SEP_STR);
	    strcat(pname, cur_realm);
	}

	if (retval = krb5_parse_name(pname, &princ)) {
	    com_err(argv[0], retval, "while parsing %s", pname);
	    free(pname);
	    continue;
	}
	nentries = 1;
	if (retval = krb5_db_get_principal(princ, &dbentry, &nentries,
					   &more)) {
	    com_err(argv[0], retval, "while retrieving %s", pname);
	    goto cleanmost;
	} else if (more) {
	    com_err(argv[0], KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE,
		    "while retrieving %s", pname);
	    if (nentries)
		krb5_db_free_principal(&dbentry, nentries);
	    goto cleanmost;
	} else if (!nentries) {
	    com_err(argv[0], KRB5_KDB_NOENTRY, "while retrieving %s", pname);
	    goto cleanmost;
	}
	if (retval = krb5_kdb_decrypt_key(&master_encblock,
					  &dbentry.key,
					  &newentry.key)) {
	    com_err(argv[0], retval, "while decrypting key for '%s'", pname);
	    goto cleanall;
	}
	newentry.principal = princ;
	newentry.vno = dbentry.kvno;
	if (retval = krb5_kt_add_entry(ktid, &newentry)) {
	    com_err(argv[0], retval, "while adding key to keytab '%s'",
		    ktname);
	} else
	    printf("'%s' added to keytab '%s'\n",
		   pname, ktname);
	bzero((char *)newentry.key.contents, newentry.key.length);
	free((char *)newentry.key.contents);
    cleanall:
	    krb5_db_free_principal(&dbentry, nentries);
    cleanmost:
	    free(pname);
	    krb5_free_principal(princ);
    }
    if (retval = krb5_kt_close(ktid))
	com_err(argv[0], retval, "while closing keytab");
    return;
}

krb5_error_code
list_iterator(ptr, entry)
krb5_pointer ptr;
krb5_db_entry *entry;
{
    krb5_error_code retval;
    char *comerrname = (char *)ptr;
    char *name;

    if (retval = krb5_unparse_name(entry->principal, &name)) {
	com_err(comerrname, retval, "while unparsing principal");
	return retval;
    }
    printf("entry: %s\n", name);
    free(name);
    return 0;
}

/*ARGSUSED*/
void
list_db(argc, argv)
int argc;
char *argv[];
{
    (void) krb5_db_iterate(list_iterator, argv[0]);
}

void
delete_entry(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;
    char yesno[80];
    int one = 1;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	return;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	return;
    }
    if (!princ_exists(argv[0], newprinc)) {
	com_err(argv[0], 0, "principal '%s' is not in the database", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    printf("Are you sure you want to delete '%s'?\nType 'yes' to confirm:",
	   argv[1]);
    if ((fgets(yesno, sizeof(yesno), stdin) == NULL) ||
	strcmp(yesno, "yes\n")) {
	printf("NOT removing '%s'\n", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    printf("OK, deleting '%s'\n", argv[1]);
    if (retval = krb5_db_delete_principal(newprinc, &one)) {
	com_err(argv[0], retval, "while deleting '%s'", argv[1]);
    } else if (one != 1) {
	com_err(argv[0], 0, "no principal deleted? unknown error");
    }
#ifdef __STDC__
    printf("\a\a\aWARNING:  Be sure to take '%s' off all access control lists\n\tbefore reallocating the name\n", argv[1]);
#else
    printf("\007\007\007WARNING:  Be sure to take '%s' off all access control lists\n\tbefore reallocating the name\n", argv[1]);
#endif

    krb5_free_principal(newprinc);
    return;
}

void
change_rnd_key(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;
    krb5_kvno vno;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	return;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	return;
    }
    if (!(vno = princ_exists(argv[0], newprinc))) {
	com_err(argv[0], 0, "No principal '%s' exists", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    enter_rnd_key(argv, newprinc, vno);
    krb5_free_principal(newprinc);
    return;
}

void
enter_rnd_key(DECLARG(char **, argv),
	      DECLARG(krb5_principal, princ),
	      DECLARG(krb5_kvno, vno))
OLDDECLARG(char **, argv)
OLDDECLARG(krb5_principal, princ)
OLDDECLARG(krb5_kvno, vno)
{
    krb5_error_code retval;
    krb5_keyblock *tempkey;

    if (retval = krb5_random_key(&master_encblock, master_random, &tempkey)) {
	com_err(argv[0], retval, "while generating random key");
	return;
    }
    add_key(argv, princ, tempkey, ++vno);
    bzero((char *)tempkey->contents, tempkey->length);
    krb5_free_keyblock(tempkey);
    return;
}

void
change_pwd_key(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;
    krb5_kvno vno;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	return;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	return;
    }
    if (!(vno = princ_exists(argv[0], newprinc))) {
	com_err(argv[0], 0, "No principal '%s' exists!", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    enter_pwd_key(argv, newprinc, newprinc, vno);
    krb5_free_principal(newprinc);
    return;
}

void
change_v4_key(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;
    krb5_kvno vno;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	return;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	return;
    }
    if (!(vno = princ_exists(argv[0], newprinc))) {
	com_err(argv[0], 0, "No principal '%s' exists!", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    enter_pwd_key(argv, newprinc, 0, vno);
    krb5_free_principal(newprinc);
    return;
}

void
enter_pwd_key(DECLARG(char **, argv),
	      DECLARG(const krb5_principal, princ),
	      DECLARG(const krb5_principal, string_princ),
	      DECLARG(krb5_kvno, vno))
OLDDECLARG(char **, argv)
OLDDECLARG(const krb5_principal, princ)
OLDDECLARG(const krb5_principal, string_princ)
OLDDECLARG(krb5_kvno, vno)
{
    krb5_error_code retval;
    char password[BUFSIZ];
    int pwsize = sizeof(password);
    krb5_keyblock tempkey;
    krb5_data pwd;

    if (retval = krb5_read_password(krb5_default_pwd_prompt1,
				    krb5_default_pwd_prompt2,
				    password, &pwsize)) {
	com_err(argv[0], retval, "while reading password for '%s'", argv[1]);
	return;
    }
    pwd.data = password;
    pwd.length = pwsize;

    retval = krb5_string_to_key(&master_encblock, master_keyblock.keytype,
				&tempkey,
				&pwd,
				string_princ);
    bzero(password, sizeof(password)); /* erase it */
    if (retval) {
	com_err(argv[0], retval, "while converting password to key for '%s'", argv[1]);
	return;
    }
    add_key(argv, princ, &tempkey, ++vno);
    bzero((char *)tempkey.contents, tempkey.length);
    free((char *)tempkey.contents);
    return;
}

