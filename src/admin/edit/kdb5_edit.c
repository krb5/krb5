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
 * Edit a KDC database.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdb_edit_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/los-proto.h>
#include <krb5/asn1.h>
#include <krb5/config.h>
#include <krb5/sysincl.h>		/* for MAXPATHLEN */
#include <krb5/ext-proto.h>

#include <com_err.h>
#include <ss/ss.h>
#include <stdio.h>


#define REALM_SEP	'@'
#define REALM_SEP_STR	"@"

struct saltblock {
    int salttype;
    krb5_data saltdata;
};

#define norealm_salt(princ, retdata) krb5_principal2salt(&(princ)[1], retdata)

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

char	*Err_no_master_msg = "Master key not entered!\n";
char	*Err_no_database = "Database not currently opened!\n";
char	*current_dbname = NULL;

/* krb5_kvno may be narrow */
#include <krb5/widen.h>
void add_key PROTOTYPE((char const *, char const *, krb5_const_principal,
			const krb5_keyblock *, krb5_kvno, struct saltblock *));
void enter_rnd_key PROTOTYPE((char **, const krb5_principal, krb5_kvno));
void enter_pwd_key PROTOTYPE((char *, char *, krb5_const_principal,
			      krb5_const_principal, krb5_kvno, int));
int set_dbname_help PROTOTYPE((char *, char *));

#include <krb5/narrow.h>

static void
usage(who, status)
char *who;
int status;
{
    fprintf(stderr,
	    "usage: %s [-d dbpathname] [-r realmname] [-R request ]\n",
	    who);
    fprintf(stderr, "\t [-k keytype] [-e etype] [-M mkeyname]\n");
    exit(status);
}

krb5_keyblock master_keyblock;
krb5_principal master_princ;
krb5_db_entry master_entry;
krb5_encrypt_block master_encblock;
krb5_pointer master_random;
int	valid_master_key = 0;

extern ss_request_table kdb5_edit_cmds;

extern char *krb5_default_pwd_prompt1, *krb5_default_pwd_prompt2;

char *progname;
char *cur_realm = 0;
char *mkey_name = 0;
krb5_boolean manual_mkey = FALSE;
krb5_boolean dbactive = FALSE;

/*
 * XXX Memory leak for cur_realm, which is assigned both allocated
 * values (in set_dbname) and unallocated values (from argv()).
 */

void
quit()
{
    krb5_error_code retval = krb5_db_fini();
    if (valid_master_key)
	    memset((char *)master_keyblock.contents, 0,
		   master_keyblock.length);
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
    char *defrealm;
    int keytypedone = 0;
    krb5_enctype etype = 0xffff;
    int sci_idx, code;
    extern krb5_kt_ops krb5_ktf_writable_ops;
    char	*request = NULL;

    krb5_init_ets();

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    progname = argv[0];

    while ((optchar = getopt(argc, argv, "d:r:R:k:M:e:m")) != EOF) {
	switch(optchar) {
	case 'd':			/* set db name */
	    dbname = optarg;
	    break;
	case 'r':
	    cur_realm = optarg;
	    break;
        case 'R':
	    request = optarg;
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


    if (retval = krb5_kt_register(&krb5_ktf_writable_ops)) {
	com_err(progname, retval,
		"while registering writable key table functions");
	exit(1);
    }

    if (!keytypedone)
	master_keyblock.keytype = DEFAULT_KDC_KEYTYPE;

    if (!valid_keytype(master_keyblock.keytype)) {
	com_err(progname, KRB5_PROG_KEYTYPE_NOSUPP,
		"while setting up keytype %d", master_keyblock.keytype);
	exit(1);
    }

    if (etype == 0xffff)
	etype = DEFAULT_KDC_ETYPE;

    if (!valid_etype(etype)) {
	com_err(progname, KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", etype);
	exit(1);
    }
    krb5_use_cstype(&master_encblock, etype);

    if (!dbname)
	dbname = DEFAULT_DBM_FILE;	/* XXX? */

    sci_idx = ss_create_invocation("kdb5_edit", "5.0", (char *) NULL,
				   &kdb5_edit_cmds, &retval);
    if (retval) {
	ss_perror(sci_idx, retval, "creating invocation");
	exit(1);
    }

    if (!cur_realm) {
	if (retval = krb5_get_default_realm(&defrealm)) {
	    com_err(progname, retval, "while retrieving default realm name");
	    exit(1);
	}	    
	cur_realm = defrealm;
    }
    (void) set_dbname_help(progname, dbname);

    if (request) {
	    (void) ss_execute_line(sci_idx, request, &code);
	    if (code != 0)
		    ss_perror(sci_idx, code, request);
    } else
	    ss_listen(sci_idx, &retval);
    if (valid_master_key) {
	    (void) krb5_finish_key(&master_encblock);
	    (void) krb5_finish_random_key(&master_encblock, &master_random);
    }
    retval = krb5_db_fini();
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
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
    if (!nprincs)
	    return 0;
    vno = entry.kvno;
    krb5_db_free_principal(&entry, nprincs);
    return(vno);
}

void
add_new_key(argc, argv)
int argc;
char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;
    int		salttype = KRB5_KDB_SALTTYPE_NORMAL;
    char	*cmdname = argv[0];

    if (argc > 2) {
	    if (!strcmp(argv[1], "-onlyrealmsalt")) {
		    salttype = KRB5_KDB_SALTTYPE_ONLYREALM;
		    argc--;
		    argv++;
	    } else if (!strcmp(argv[1], "-norealmsalt")) {
		    salttype = KRB5_KDB_SALTTYPE_NOREALM;
		    argc--;
		    argv++;
	    }
    }
    if (argc != 2) {
	com_err(cmdname, 0,
		"Usage: %s [-onlyrealmsalt|-norealmsalt] principal", argv[0]);
	return;
    }
    if (!valid_master_key) {
	    com_err(cmdname, 0, Err_no_master_msg);
	    return;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(cmdname, retval, "while parsing '%s'", argv[1]);
	return;
    }
    if (princ_exists(cmdname, newprinc)) {
	com_err(cmdname, 0, "principal '%s' already exists", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    enter_pwd_key(cmdname, argv[1], newprinc, newprinc, 0, salttype);
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
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
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
    enter_pwd_key(argv[0], argv[1], newprinc, newprinc, 0,
		  KRB5_KDB_SALTTYPE_V4);
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
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
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
add_key(DECLARG(char const *, cmdname),
	DECLARG(char const *, newprinc),
	DECLARG(krb5_const_principal, principal),
	DECLARG(const krb5_keyblock *, key),
	DECLARG(krb5_kvno, vno),
	DECLARG(struct saltblock *, salt))
OLDDECLARG(char const *, cmdname)
OLDDECLARG(char const *, newprinc)
OLDDECLARG(krb5_const_principal, principal)
OLDDECLARG(const krb5_keyblock *, key)
OLDDECLARG(krb5_kvno, vno)
OLDDECLARG(struct saltblock *, salt)
{
    krb5_error_code retval;
    krb5_db_entry newentry;
    int one = 1;

    retval = krb5_kdb_encrypt_key(&master_encblock,
				  key,
				  &newentry.key);
    if (retval) {
	com_err(cmdname, retval, "while encrypting key for '%s'", newprinc);
	return;
    }
    newentry.principal = (krb5_principal) principal;
    newentry.kvno = vno;
    newentry.max_life = mblock.max_life;
    newentry.max_renewable_life = mblock.max_rlife;
    newentry.mkvno = mblock.mkvno;
    newentry.expiration = mblock.expiration;
    newentry.mod_name = master_princ;
    if (retval = krb5_timeofday(&newentry.mod_date)) {
	com_err(cmdname, retval, "while fetching date");
	memset((char *)newentry.key.contents, 0, newentry.key.length);
	xfree(newentry.key.contents);
	return;
    }
    newentry.attributes = mblock.flags;
    if (salt) {
	newentry.salt_type = salt->salttype;
	newentry.salt_length = salt->saltdata.length;
	newentry.salt = (krb5_octet *) salt->saltdata.data;
    } else {
	newentry.salt_type = KRB5_KDB_SALTTYPE_NORMAL;
	newentry.salt_length = 0;
	newentry.salt = 0;
    }
    
    retval = krb5_db_put_principal(&newentry, &one);
    memset((char *)newentry.key.contents, 0, newentry.key.length);
    xfree(newentry.key.contents);
    if (retval) {
	com_err(cmdname, retval, "while storing entry for '%s'\n", newprinc);
	return;
    }
    if (one != 1)
	com_err(cmdname, 0, "entry not stored in database (unknown failure)");
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
	if (valid_master_key) {
		(void) krb5_finish_key(&master_encblock);
		(void) krb5_finish_random_key(&master_encblock,
					      &master_random);
		memset((char *)master_keyblock.contents, 0,
		       master_keyblock.length);
		xfree(master_keyblock.contents);
		master_keyblock.contents = NULL;
	}
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

    if (current_dbname)
	    free(current_dbname);
    if (!(current_dbname = malloc(strlen(dbname)+1))) {
	    com_err(pname, 0, "Out of memory while trying to store dbname");
	    exit(1);
    }
    strcpy(current_dbname, dbname);
    if (retval = krb5_db_set_name(current_dbname)) {
	com_err(pname, retval, "while setting active database to '%s'",
		dbname);
	return(1);
    } 
    if (retval = krb5_db_init()) {
	com_err(pname, retval, "while initializing database");
	return(1);
    }
	    
   /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(mkey_name, cur_realm, 0,
					 &master_princ)) {
	com_err(pname, retval, "while setting up master key name");
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
    mblock.max_life = master_entry.max_life;
    mblock.max_rlife = master_entry.max_renewable_life;
    mblock.expiration = master_entry.expiration;
    /* don't set flags, master has some extra restrictions */
    mblock.mkvno = master_entry.kvno;

    krb5_db_free_principal(&master_entry, nentries);
    if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock,
				    manual_mkey,
				    FALSE, &master_keyblock)) {
	com_err(pname, retval, "while reading master key");
	com_err(pname, 0, "Warning: proceeding without master key");
	valid_master_key = 0;
	dbactive = TRUE;
	return(0);
    } else
	    valid_master_key = 1;
    if (retval = krb5_db_verify_master_key(master_princ, &master_keyblock,
					   &master_encblock)) {
	com_err(pname, retval, "while verifying master key");
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	xfree(master_keyblock.contents);
	valid_master_key = 0;
	dbactive = TRUE;
	return(1);
    }
    if (retval = krb5_process_key(&master_encblock,
				  &master_keyblock)) {
	com_err(pname, retval, "while processing master key");
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	xfree(master_keyblock.contents);
	valid_master_key = 0;
	dbactive = TRUE;
	return(1);
    }
    if (retval = krb5_init_random_key(&master_encblock,
				      &master_keyblock,
				      &master_random)) {
	com_err(pname, retval, "while initializing random key generator");
	(void) krb5_finish_key(&master_encblock);
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	xfree(master_keyblock.contents);
	valid_master_key = 0;
	dbactive = TRUE;
	return(1);
    }
    dbactive = TRUE;
    return 0;
}

void enter_master_key(argc, argv)
	int	argc;
	char	**argv;
{
	char	*pname = argv[0];
	krb5_error_code retval;
	
	if (!dbactive) {
		com_err(pname, 0, Err_no_database);
		return;
	}
	if (retval = krb5_db_fetch_mkey(master_princ, &master_encblock,
					TRUE, FALSE, &master_keyblock)) {
		com_err(pname, retval, "while reading master key");
		return;
	}
	if (retval = krb5_db_verify_master_key(master_princ, &master_keyblock,
					       &master_encblock)) {
		com_err(pname, retval, "while verifying master key");
		return;
	}
	if (retval = krb5_process_key(&master_encblock,
				      &master_keyblock)) {
		com_err(pname, retval, "while processing master key");
		return;
	}
	if (retval = krb5_init_random_key(&master_encblock,
					  &master_keyblock,
					  &master_random)) {
		com_err(pname, retval, "while initializing random key generator");
		(void) krb5_finish_key(&master_encblock);
		return;
	}
	valid_master_key = 1;
	return;
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
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    return;
    }

    memset(ktname, 0, sizeof(ktname));
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
	memset((char *)newentry.key.contents, 0, newentry.key.length);
	xfree(newentry.key.contents);
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

void
extract_v4_srvtab(argc, argv)
int argc;
char *argv[];
{
    char ktname[MAXPATHLEN+1];
    FILE	*fout;
    krb5_error_code retval;
    krb5_principal princ;
    krb5_db_entry dbentry;
    char *pname;
    register int i;
    int nentries;
    krb5_boolean more;
    krb5_keyblock	key;

    if (argc < 3) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s instance name [name ...]", argv[0]);
	return;
    }
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    return;
    }

    memset(ktname, 0, sizeof(ktname));
    if (strlen(argv[1])+sizeof("-new-v4-srvtab") >= sizeof(ktname)) {
	com_err(argv[0], 0,
		"Instance name '%s' is too long to form a filename", argv[1]);
	com_err(argv[0], 0, "using 'foobar' instead.");
	strcat(ktname, "foobar");
    } else
	strcat(ktname, argv[1]);

    strcat(ktname, "-new-v4-srvtab");
    if ((fout = fopen(ktname, "w")) == NULL) {
	com_err(argv[0], 0, "Couldn't create file '%s'.\n", ktname);
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
					  &key)) {
	    com_err(argv[0], retval, "while decrypting key for '%s'", pname);
	    goto cleanall;
	}
	if (key.keytype != 1) {
		com_err(argv[0], 0, "%s does not have a DES key!", pname);
		memset((char *)key.contents, 0, key.length);
		xfree(key.contents);
		continue;
	}
	fwrite(argv[i], strlen(argv[1]) + 1, 1, fout); /* p.name */
	fwrite(argv[1], strlen(argv[i]) + 1, 1, fout); /* p.instance */
	fwrite(cur_realm, strlen(cur_realm) + 1, 1, fout); /* p.realm */
	fwrite((char *)&dbentry.kvno, sizeof(dbentry.kvno), 1, fout);
	fwrite((char *)key.contents, 8, 1, fout);
	printf("'%s' added to V4 srvtab '%s'\n", pname, ktname);
	memset((char *)key.contents, 0, key.length);
	xfree(key.contents);
    cleanall:
	    krb5_db_free_principal(&dbentry, nentries);
    cleanmost:
	    free(pname);
	    krb5_free_principal(princ);
    }
    fclose(fout);
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
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    return;
    }
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
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
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
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
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
    add_key(argv[0], argv[1], princ, tempkey, ++vno, 0);
    memset((char *)tempkey->contents, 0, tempkey->length);
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
    int		salttype = KRB5_KDB_SALTTYPE_NORMAL;
    char	*cmdname = argv[0];

    if (argc > 2) {
	    if (!strcmp(argv[1], "-onlyrealmsalt")) {
		    salttype = KRB5_KDB_SALTTYPE_ONLYREALM;
		    argc--;
		    argv++;
	    } else if (!strcmp(argv[1], "-norealmsalt")) {
		    salttype = KRB5_KDB_SALTTYPE_NOREALM;
		    argc--;
		    argv++;
	    }
    }
    if (argc != 2) {
	com_err(cmdname, 0,
		"Usage: %s [-onlyrealmsalt|-norealmsalt] principal", argv[0]);
	return;
    }
    if (!dbactive) {
	    com_err(cmdname, 0, Err_no_database);
	    return;
    }
    if (!valid_master_key) {
	    com_err(cmdname, 0, Err_no_master_msg);
	    return;
    }
    if (retval = krb5_parse_name(argv[1], &newprinc)) {
	com_err(cmdname, retval, "while parsing '%s'", argv[1]);
	return;
    }
    if (!(vno = princ_exists(argv[0], newprinc))) {
	com_err(cmdname, 0, "No principal '%s' exists!", argv[1]);
	krb5_free_principal(newprinc);
	return;
    }
    enter_pwd_key(cmdname, argv[1], newprinc, newprinc, vno+1, salttype);
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
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
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
    enter_pwd_key(argv[0], argv[1], newprinc, newprinc, vno+1,
		  KRB5_KDB_SALTTYPE_V4);
    krb5_free_principal(newprinc);
    return;
}

void
enter_pwd_key(DECLARG(char *, cmdname),
	      DECLARG(char *, newprinc),
	      DECLARG(krb5_const_principal, princ),
	      DECLARG(krb5_const_principal, string_princ),
	      DECLARG(krb5_kvno, vno),
	      DECLARG(int, salttype))
OLDDECLARG(char *, cmdname)
OLDDECLARG(char *, newprinc)
OLDDECLARG(krb5_const_principal, princ)
OLDDECLARG(krb5_const_principal, string_princ)
OLDDECLARG(krb5_kvno, vno)
OLDDECLARG(int, salttype)
{
    krb5_error_code retval;
    char password[BUFSIZ];
    int pwsize = sizeof(password);
    krb5_keyblock tempkey;
    krb5_data pwd;
    struct saltblock salt;

    if (retval = krb5_read_password(krb5_default_pwd_prompt1,
				    krb5_default_pwd_prompt2,
				    password, &pwsize)) {
	com_err(cmdname, retval, "while reading password for '%s'", newprinc);
	return;
    }
    pwd.data = password;
    pwd.length = pwsize;

    salt.salttype = salttype;

    switch (salttype) {
    case KRB5_KDB_SALTTYPE_NORMAL:
	if (retval = krb5_principal2salt(string_princ, &salt.saltdata)) {
	    com_err(cmdname, retval,
		    "while converting principal to salt for '%s'", newprinc);
	    return;
	}
	break;
    case KRB5_KDB_SALTTYPE_V4:
	salt.saltdata.data = 0;
	salt.saltdata.length = 0;
	break;
    case KRB5_KDB_SALTTYPE_NOREALM:
	if (retval = norealm_salt(string_princ, &salt.saltdata)) {
	    com_err(cmdname, retval,
		    "while converting principal to salt for '%s'", newprinc);
	    return;
	}
	break;
    case KRB5_KDB_SALTTYPE_ONLYREALM:
    {
	krb5_data *foo;
	if (retval = krb5_copy_data(krb5_princ_realm(string_princ),
				    &foo)) {
	    com_err(cmdname, retval,
		    "while converting principal to salt for '%s'", newprinc);
	    return;
	}
	salt.saltdata = *foo;
	xfree(foo);
	break;
    }
    default:
	com_err(cmdname, 0, "Don't know how to enter salt type %d", salttype);
	return;
    }
    retval = krb5_string_to_key(&master_encblock, master_keyblock.keytype,
				&tempkey,
				&pwd,
				&salt.saltdata);
    memset(password, 0, sizeof(password)); /* erase it */
    if (retval) {
	com_err(cmdname, retval, "while converting password to key for '%s'",
		newprinc);
	xfree(salt.saltdata.data);
	return;
    }
    add_key(cmdname, newprinc, princ, &tempkey, ++vno,
	    (salttype == KRB5_KDB_SALTTYPE_NORMAL) ? 0 : &salt);
    xfree(salt.saltdata.data);
    memset((char *)tempkey.contents, 0, tempkey.length);
    xfree(tempkey.contents);
    return;
}

void change_working_dir(argc, argv)
	int	argc;
	char	**argv;
{
	if (argc != 2) {
		com_err(argv[0], 0, "Usage: %s directory", argv[0]);
		return;
	}
	if (chdir(argv[1])) {
		com_err(argv[0], errno,
			"Couldn't change directory to %s", argv[1]);
	}
}

void print_working_dir(argc, argv)
	int	argc;
	char	**argv;
{
	char	buf[MAXPATHLEN];

	if (!getwd(buf)) {
		com_err(argv[0], 0, "Couldn't get working directory: %s",
			buf);
		return;
	}
	puts(buf);
}


