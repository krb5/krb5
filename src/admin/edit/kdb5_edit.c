/*
 * admin/edit/kdb5_edit.c
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
 * Edit a KDC database.
 */

#include "k5-int.h"
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"
#include <stdio.h>
#include <time.h>
/* timeb is part of the interface to get_date. */
#if defined(HAVE_SYS_TIMEB_H)
#include <sys/timeb.h>
#else
/*
** We use the obsolete `struct timeb' as part of our interface!
** Since the system doesn't have it, we define it here;
** our callers must do likewise.
*/
struct timeb {
    time_t		time;		/* Seconds since the epoch	*/
    unsigned short	millitm;	/* Field not used		*/
    short		timezone;	/* Minutes west of GMT		*/
    short		dstflag;	/* Field not used		*/
};
#endif /* defined(HAVE_SYS_TIMEB_H) */

#include "kdb5_edit.h"

/* special struct to convert flag names for principals
   to actual krb5_flags for a principal */
struct pflag {
    char *flagname;		/* name of flag as typed to CLI */
    int flaglen;		/* length of string (not counting -,+) */
    krb5_flags theflag;		/* actual principal flag to set/clear */
    int set;			/* 0 means clear, 1 means set (on '-') */
};

struct mblock mblock = {				/* XXX */
    KRB5_KDB_MAX_LIFE,
    KRB5_KDB_MAX_RLIFE,
    KRB5_KDB_EXPIRATION,
    KRB5_KDB_DEF_FLAGS,
    0
};

char	*Err_no_master_msg = "Master key not entered!\n";
char	*Err_no_database = "Database not currently opened!\n";
char	*current_dbname = NULL;


/*
 * XXX Ick, ick, ick.  These global variables shouldn't be global....
 */
static char search_name[40];
static int num_name_tokens;
static char search_instance[40];
static int num_instance_tokens;
static int must_be_first[2];
static char *mkey_password = 0;
static char *stash_file = (char *) NULL;

/*
 * I can't figure out any way for this not to be global, given how ss
 * works.
 */

int exit_status = 0;

krb5_context edit_context;

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

extern char *krb5_default_pwd_prompt1, *krb5_default_pwd_prompt2;

char *progname;
char *cur_realm = 0;
char *mkey_name = 0;
krb5_boolean manual_mkey = FALSE;
krb5_boolean dbactive = FALSE;

char *kdb5_edit_Init(argc, argv)
    int argc;
    char *argv[];
{
    extern char *optarg;	
    int optchar;

    krb5_error_code retval;
    char *dbname = (char *) NULL;
    char *defrealm;
    int keytypedone = 0;
    int etypedone = 0;
    krb5_enctype etype = DEFAULT_KDC_ETYPE;
    extern krb5_kt_ops krb5_ktf_writable_ops;
    char	*request = NULL;
    krb5_realm_params *rparams;

    retval = krb5_init_context(&edit_context);
    if (retval) {
	    fprintf(stderr, "krb5_init_context failed with error #%ld\n",
		    retval);
	    exit(1);
    }
    krb5_init_ets(edit_context);

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    progname = argv[0];

    while ((optchar = getopt(argc, argv, "P:d:r:R:k:M:e:m")) != EOF) {
	switch(optchar) {
        case 'P':		/* Only used for testing!!! */
	    mkey_password = optarg;
	    break;
	case 'd':			/* set db name */
	    dbname = optarg;
	    break;
	case 'r':
	    if (cur_realm)
		    free(cur_realm);
	    cur_realm = malloc(strlen(optarg)+1);
	    if (!cur_realm) {
		    com_err(argv[0], 0, "Insufficient memory to proceed");
		    exit(1);
	    }
	    (void) strcpy(cur_realm, optarg);
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
	    etypedone++;
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

    /*
     * Attempt to read the KDC profile.  If we do, then read appropriate values
     * from it and augment values supplied on the command line.
     */
    if (!(retval = krb5_read_realm_params(edit_context,
					  cur_realm,
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
	if (rparams->realm_enctype_valid && !etypedone)
	    etype = rparams->realm_enctype;

	/* Get the value for the stashfile */
	if (rparams->realm_stash_file)
	    stash_file = strdup(rparams->realm_stash_file);

	/* Get the value for maximum ticket lifetime. */
	if (rparams->realm_max_life_valid)
	    mblock.max_life = rparams->realm_max_life;

	/* Get the value for maximum renewable ticket lifetime. */
	if (rparams->realm_max_rlife_valid)
	    mblock.max_rlife = rparams->realm_max_rlife;

	/* Get the value for the default principal expiration */
	if (rparams->realm_expiration_valid)
	    mblock.expiration = rparams->realm_expiration;

	/* Get the value for the default principal flags */
	if (rparams->realm_flags_valid)
	    mblock.flags = rparams->realm_flags;

	krb5_free_realm_params(edit_context, rparams);
    }

    /* Dump creates files which should not be world-readable.  It is easiest
       to do a single umask call here; any shells run by the ss command
       interface will have umask = 77 but that is not a serious problem. */
    (void) umask(077);

    if (retval = krb5_kt_register(edit_context, &krb5_ktf_writable_ops)) {
	com_err(progname, retval,
		"while registering writable key table functions");
	exit(1);
    }

    /* Handle defaults */
    if (!dbname)
	dbname = DEFAULT_KDB_FILE;

    if (!keytypedone)
	master_keyblock.keytype = DEFAULT_KDC_KEYTYPE;

    if (!valid_keytype(master_keyblock.keytype)) {
	com_err(progname, KRB5_PROG_KEYTYPE_NOSUPP,
		"while setting up keytype %d", master_keyblock.keytype);
	exit(1);
    }

    if (!valid_etype(etype)) {
	com_err(progname, KRB5_PROG_ETYPE_NOSUPP,
		"while setting up etype %d", etype);
	exit(1);
    }
    krb5_use_cstype(edit_context, &master_encblock, etype);

    if (cur_realm) {
	if (retval = krb5_set_default_realm(edit_context, cur_realm)) {
	    com_err(progname, retval, "while setting default realm name");
	    exit(1);
        }
    } else {
	if (retval = krb5_get_default_realm(edit_context, &defrealm)) {
	    com_err(progname, retval, "while retrieving default realm name");
	    exit(1);
	}	    
	cur_realm = malloc(strlen(defrealm)+1);
	if (!cur_realm) {
		com_err(argv[0], 0, "Insufficient memory to proceed");
		exit(1);
	}
	(void) strcpy(cur_realm, defrealm);
    }

    (void) set_dbname_help(progname, dbname);
    exit_status = 0;	/* It's OK if we get errors in set_dbname_help */
    return request;
}

#define	NO_PRINC ((krb5_kvno)-1)

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

    if (retval = krb5_db_get_principal(edit_context, principal, &entry, 
				       &nprincs, &more)) {
	com_err(pname, retval, 
		"while attempting to verify principal's existence");
	exit_status++;
	return 0;
    }
    if (!nprincs)
	    return NO_PRINC;
    vno = entry.kvno;
    krb5_db_free_principal(edit_context, &entry, nprincs);
    return(vno);
}

int create_db_entry( principal, newentry)
    krb5_principal principal;
    krb5_db_entry  *newentry;
{
    int	retval;

    memset(newentry, 0, sizeof(krb5_db_entry));
    
    if (retval = krb5_copy_principal(edit_context, principal, &newentry->principal))
	return retval;
    newentry->kvno = 1;
    newentry->max_life = mblock.max_life;
    newentry->max_renewable_life = mblock.max_rlife;
    newentry->mkvno = mblock.mkvno;
    newentry->expiration = mblock.expiration;
    if (retval = krb5_copy_principal(edit_context, master_princ,&newentry->mod_name))
	goto errout;
    
    newentry->attributes = mblock.flags;
    newentry->salt_type = KRB5_KDB_SALTTYPE_NORMAL;

    if (retval = krb5_timeofday(edit_context, &newentry->mod_date))
	goto errout;

    return 0;

errout:
    if (newentry->principal)
	krb5_free_principal(edit_context, newentry->principal);
    memset(newentry, 0, sizeof(krb5_db_entry));
    return retval;
}    

void
add_key(cmdname, newprinc, principal, key, vno, salt)
    char const * cmdname;
    char const * newprinc;
    krb5_const_principal principal;
    const krb5_keyblock * key;
    krb5_kvno vno;
    struct saltblock * salt;
{
    krb5_error_code retval;
    krb5_db_entry newentry;
    int one = 1;

    memset((char *) &newentry, 0, sizeof(newentry));
    retval = krb5_kdb_encrypt_key(edit_context, &master_encblock,
				  key,
				  &newentry.key);
    if (retval) {
	com_err(cmdname, retval, "while encrypting key for '%s'", newprinc);
	exit_status++;
	return;
    }
    newentry.principal = (krb5_principal) principal;
    newentry.kvno = vno;
    newentry.max_life = mblock.max_life;
    newentry.max_renewable_life = mblock.max_rlife;
    newentry.mkvno = mblock.mkvno;
    newentry.expiration = mblock.expiration;
    newentry.mod_name = master_princ;
    if (retval = krb5_timeofday(edit_context, &newentry.mod_date)) {
	com_err(cmdname, retval, "while fetching date");
	exit_status++;
	memset((char *)newentry.key.contents, 0, newentry.key.length);
	krb5_xfree(newentry.key.contents);
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
    
    retval = krb5_db_put_principal(edit_context, &newentry, &one);
    memset((char *)newentry.key.contents, 0, newentry.key.length);
    krb5_xfree(newentry.key.contents);
    if (retval) {
	com_err(cmdname, retval, "while storing entry for '%s'\n", newprinc);
	exit_status++;
	return;
    }
    if (one != 1) {
	com_err(cmdname, 0, "entry not stored in database (unknown failure)");
	exit_status++;
    }
    return;
}

void
set_dbname(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;

    if (argc < 3) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s dbpathname realmname", argv[0]);
	exit_status++;
	return;
    }
    if (dbactive) {
	if ((retval = krb5_db_fini(edit_context)) && retval!= KRB5_KDB_DBNOTINITED) {
	    com_err(argv[0], retval, "while closing previous database");
	    exit_status++;
	    return;
	}
	if (valid_master_key) {
		(void) krb5_finish_key(edit_context, &master_encblock);
		(void) krb5_finish_random_key(edit_context, &master_encblock,
					      &master_random);
		memset((char *)master_keyblock.contents, 0,
		       master_keyblock.length);
		krb5_xfree(master_keyblock.contents);
		master_keyblock.contents = NULL;
		valid_master_key = 0;
	}
	krb5_free_principal(edit_context, master_princ);
	dbactive = FALSE;
    }
    if (cur_realm)
	    free(cur_realm);
    cur_realm = malloc(strlen(argv[2])+1);
    if (!cur_realm) {
	(void)quit();
	exit(1);		/* XXX */
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
    krb5_data scratch, pwd;

    if (current_dbname)
	    free(current_dbname);
    if (!(current_dbname = malloc(strlen(dbname)+1))) {
	    com_err(pname, 0, "Out of memory while trying to store dbname");
	    exit(1);
    }
    strcpy(current_dbname, dbname);
    if (retval = krb5_db_set_name(edit_context, current_dbname)) {
	com_err(pname, retval, "while setting active database to '%s'",
		dbname);
	exit_status++;
	return(1);
    } 
    if (retval = krb5_db_init(edit_context)) {
	com_err(pname, retval, "while initializing database");
	exit_status++;
	return(1);
    }
	    
   /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(edit_context, mkey_name, cur_realm, 0,
					 &master_princ)) {
	com_err(pname, retval, "while setting up master key name");
	exit_status++;
	return(1);
    }
    nentries = 1;
    if (retval = krb5_db_get_principal(edit_context, master_princ, &master_entry, 
				       &nentries, &more)) {
	com_err(pname, retval, "while retrieving master entry");
	exit_status++;
	(void) krb5_db_fini(edit_context);
	return(1);
    } else if (more) {
	com_err(pname, KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE,
		"while retrieving master entry");
	exit_status++;
	(void) krb5_db_fini(edit_context);
	return(1);
    } else if (!nentries) {
	com_err(pname, KRB5_KDB_NOENTRY, "while retrieving master entry");
	exit_status++;
	(void) krb5_db_fini(edit_context);
	return(1);
    }
#ifdef	notdef
    mblock.max_life = master_entry.max_life;
    mblock.max_rlife = master_entry.max_renewable_life;
    mblock.expiration = master_entry.expiration;
#endif	/* notdef */
    /* don't set flags, master has some extra restrictions */
    mblock.mkvno = master_entry.kvno;

    krb5_db_free_principal(edit_context, &master_entry, nentries);
    if (mkey_password) {
	pwd.data = mkey_password;
	pwd.length = strlen(mkey_password);
	retval = krb5_principal2salt(edit_context, master_princ, &scratch);
	if (retval) {
	    com_err(pname, retval, "while calculated master key salt");
	    return(1);
	}
	retval = krb5_string_to_key(edit_context, &master_encblock, 
				    master_keyblock.keytype,
				    &master_keyblock, &pwd, &scratch);
	if (retval) {
	    com_err(pname, retval,
		    "while transforming master key from password");
	    return(1);
	}
	free(scratch.data);
	mkey_password = 0;
    } else if (retval = krb5_db_fetch_mkey(edit_context, master_princ, 
					   &master_encblock, manual_mkey, 
					   FALSE, stash_file,
					   0, &master_keyblock)) {
	com_err(pname, retval, "while reading master key");
	com_err(pname, 0, "Warning: proceeding without master key");
	exit_status++;
	valid_master_key = 0;
	dbactive = TRUE;
	return(0);
    }
    valid_master_key = 1;
    if (retval = krb5_db_verify_master_key(edit_context, master_princ, 
					   &master_keyblock,&master_encblock)) {
	com_err(pname, retval, "while verifying master key");
	exit_status++;
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	krb5_xfree(master_keyblock.contents);
	valid_master_key = 0;
	dbactive = TRUE;
	return(1);
    }
    if (retval = krb5_process_key(edit_context, &master_encblock,
				  &master_keyblock)) {
	com_err(pname, retval, "while processing master key");
	exit_status++;
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	krb5_xfree(master_keyblock.contents);
	valid_master_key = 0;
	dbactive = TRUE;
	return(1);
    }
    if (retval = krb5_init_random_key(edit_context, &master_encblock,
				      &master_keyblock,
				      &master_random)) {
	com_err(pname, retval, "while initializing random key generator");
	exit_status++;
	(void) krb5_finish_key(edit_context, &master_encblock);
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	krb5_xfree(master_keyblock.contents);
	valid_master_key = 0;
	dbactive = TRUE;
	return(1);
    }
    dbactive = TRUE;
    return 0;
}

void enter_master_key(argc, argv)
    int argc;
    char *argv[];
{
	char	*pname = argv[0];
	krb5_error_code retval;
	
	if (!dbactive) {
		com_err(pname, 0, Err_no_database);
		exit_status++;
		return;
	}
	if (valid_master_key) {
		(void) krb5_finish_key(edit_context, &master_encblock);
		(void) krb5_finish_random_key(edit_context, &master_encblock,
					      &master_random);
		memset((char *)master_keyblock.contents, 0,
		       master_keyblock.length);
		krb5_xfree(master_keyblock.contents);
		master_keyblock.contents = NULL;
	}
	if (retval = krb5_db_fetch_mkey(edit_context, master_princ, &master_encblock,
					TRUE, FALSE, (char *) NULL,
					0, &master_keyblock)) {
		com_err(pname, retval, "while reading master key");
		exit_status++;
		return;
	}
	if (retval = krb5_db_verify_master_key(edit_context, master_princ, 
					       &master_keyblock,
					       &master_encblock)) {
		com_err(pname, retval, "while verifying master key");
		exit_status++;
		return;
	}
	if (retval = krb5_process_key(edit_context, &master_encblock,
				      &master_keyblock)) {
		com_err(pname, retval, "while processing master key");
		exit_status++;
		return;
	}
	if (retval = krb5_init_random_key(edit_context, &master_encblock,
					  &master_keyblock,
					  &master_random)) {
		com_err(pname, retval, "while initializing random key generator");
		exit_status++;
		(void) krb5_finish_key(edit_context, &master_encblock);
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

void extract_srvtab(argc, argv)
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
	exit_status++;
	return;
    }
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    exit_status++;
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    exit_status++;
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
    if (retval = krb5_kt_resolve(edit_context, ktname, &ktid)) {
	com_err(argv[0], retval, "while resolving keytab name '%s'", ktname);
	exit_status++;
	return;
    }

    for (i = 2; i < argc; i++) {
	/* iterate over the names */
	pname = malloc(strlen(argv[1])+strlen(argv[i])+strlen(cur_realm)+3);
	if (!pname) {
	    com_err(argv[0], ENOMEM,
		    "while preparing to extract key for %s/%s",
		    argv[i], argv[1]);
	    exit_status++;
	    continue;
	}
	strcpy(pname, argv[i]);
	strcat(pname, "/");
	strcat(pname, argv[1]);
	if (!strchr(argv[1], REALM_SEP)) {
	    strcat(pname, REALM_SEP_STR);
	    strcat(pname, cur_realm);
	}

	if (retval = krb5_parse_name(edit_context, pname, &princ)) {
	    com_err(argv[0], retval, "while parsing %s", pname);
	    exit_status++;
	    free(pname);
	    continue;
	}
	nentries = 1;
	if (retval = krb5_db_get_principal(edit_context, princ, &dbentry, &nentries,
					   &more)) {
	    com_err(argv[0], retval, "while retrieving %s", pname);
	    exit_status++;
	    goto cleanmost;
	} else if (more) {
	    com_err(argv[0], KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE,
		    "while retrieving %s", pname);
	    exit_status++;
	    if (nentries)
		krb5_db_free_principal(edit_context, &dbentry, nentries);
	    goto cleanmost;
	} else if (!nentries) {
	    com_err(argv[0], KRB5_KDB_NOENTRY, "while retrieving %s", pname);
	    exit_status++;
	    goto cleanmost;
	}
	if (retval = krb5_kdb_decrypt_key(edit_context, &master_encblock,
					  &dbentry.key,
					  &newentry.key)) {
	    com_err(argv[0], retval, "while decrypting key for '%s'", pname);
	    exit_status++;
	    goto cleanall;
	}
	newentry.principal = princ;
	newentry.vno = dbentry.kvno;
	if (retval = krb5_kt_add_entry(edit_context, ktid, &newentry)) {
	    com_err(argv[0], retval, "while adding key to keytab '%s'",
		    ktname);
	    exit_status++;
	} else
	    printf("'%s' added to keytab '%s'\n",
		   pname, ktname);
	memset((char *)newentry.key.contents, 0, newentry.key.length);
	krb5_xfree(newentry.key.contents);
    cleanall:
	    krb5_db_free_principal(edit_context, &dbentry, nentries);
    cleanmost:
	    free(pname);
	    krb5_free_principal(edit_context, princ);
    }
    if (retval = krb5_kt_close(edit_context, ktid)) {
	com_err(argv[0], retval, "while closing keytab");
	exit_status++;
    }
    return;
}

void extract_v4_srvtab(argc, argv)
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
	exit_status++;
	return;
    }
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    exit_status++;
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    exit_status++;
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
	exit_status++;
	return;
    }
    for (i = 2; i < argc; i++) {
	/* iterate over the names */
	pname = malloc(strlen(argv[1])+strlen(argv[i])+strlen(cur_realm)+3);
	if (!pname) {
	    com_err(argv[0], ENOMEM,
		    "while preparing to extract key for %s/%s",
		    argv[i], argv[1]);
	    exit_status++;
	    continue;
	}
	strcpy(pname, argv[i]);
	strcat(pname, "/");
	strcat(pname, argv[1]);
	if (!strchr(argv[1], REALM_SEP)) {
	    strcat(pname, REALM_SEP_STR);
	    strcat(pname, cur_realm);
	}

	if (retval = krb5_parse_name(edit_context, pname, &princ)) {
	    com_err(argv[0], retval, "while parsing %s", pname);
	    exit_status++;
	    free(pname);
	    continue;
	}
	nentries = 1;
	if (retval = krb5_db_get_principal(edit_context, princ, &dbentry, &nentries,
					   &more)) {
	    com_err(argv[0], retval, "while retrieving %s", pname);
	    exit_status++;
	    goto cleanmost;
	} else if (more) {
	    com_err(argv[0], KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE,
		    "while retrieving %s", pname);
	    exit_status++;
	    if (nentries)
		krb5_db_free_principal(edit_context, &dbentry, nentries);
	    goto cleanmost;
	} else if (!nentries) {
	    com_err(argv[0], KRB5_KDB_NOENTRY, "while retrieving %s", pname);
	    exit_status++;
	    goto cleanmost;
	}
	if (retval = krb5_kdb_decrypt_key(edit_context, &master_encblock,
					  &dbentry.key,
					  &key)) {
	    com_err(argv[0], retval, "while decrypting key for '%s'", pname);
	    exit_status++;
	    goto cleanall;
	}
	if (key.keytype != 1) {
		com_err(argv[0], 0, "%s does not have a DES key!", pname);
		exit_status++;
		memset((char *)key.contents, 0, key.length);
		krb5_xfree(key.contents);
		continue;
	}
	fwrite(argv[i], strlen(argv[i]) + 1, 1, fout); /* p.name */
	fwrite(argv[1], strlen(argv[1]) + 1, 1, fout); /* p.instance */
	fwrite(cur_realm, strlen(cur_realm) + 1, 1, fout); /* p.realm */
	fwrite((char *)&dbentry.kvno, sizeof(dbentry.kvno), 1, fout);
	fwrite((char *)key.contents, 8, 1, fout);
	printf("'%s' added to V4 srvtab '%s'\n", pname, ktname);
	memset((char *)key.contents, 0, key.length);
	krb5_xfree(key.contents);
    cleanall:
	    krb5_db_free_principal(edit_context, &dbentry, nentries);
    cleanmost:
	    free(pname);
	    krb5_free_principal(edit_context, princ);
    }
    fclose(fout);
    return;
}

int
check_print(chk_entry)
    krb5_db_entry *chk_entry;
{
    int names = 0;
    int instances = 1;
    int check1, check2;

	/* Print All Records */
    if ((num_name_tokens == 0) && (num_instance_tokens == 0)) return(1);

    if ((num_name_tokens > 0) && (num_instance_tokens == 0))
	return(check_for_match(search_name, must_be_first[0], chk_entry,
			num_name_tokens, names));

    if ((krb5_princ_size(edit_context, chk_entry->principal) > 1) &&
	(num_name_tokens == 0) && 
	(num_instance_tokens > 0))
	return(check_for_match(search_instance, must_be_first[1], chk_entry,
			num_instance_tokens, instances));

    if ((krb5_princ_size(edit_context, chk_entry->principal) > 1) &&
	(num_name_tokens > 0) && 
	(num_instance_tokens > 0)) {
	check1 = check_for_match(search_name, must_be_first[0], chk_entry, 
				 num_name_tokens, names);
	check2 = check_for_match(search_instance, must_be_first[1], chk_entry, 
				 num_instance_tokens, instances);
	if (check1 && check2) return(1);
    }
    return(0);
}

struct list_iterator_struct {
    char	*cmdname;
    int		verbose;
};

krb5_error_code
list_iterator(ptr, entry)
    krb5_pointer ptr;
    krb5_db_entry *entry;
{
    krb5_error_code retval;
    struct list_iterator_struct *lis = (struct list_iterator_struct *)ptr;
    char *name;

    if (retval = krb5_unparse_name(edit_context, entry->principal, &name)) {
	com_err(lis->cmdname, retval, "while unparsing principal");
	exit_status++;
	return retval;
    }
    if (check_print(entry)) {
	printf("entry: %s\n", name);
    }
    free(name);
    return 0;
}

/*ARGSUSED*/
void list_db(argc, argv)
    int argc;
    char *argv[];
{
    struct list_iterator_struct lis;
    char *argbuf;
    char *p;

    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    exit_status++;
	    return;
    }
    
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    exit_status++;
	    return;
    }
    lis.cmdname = argv[0];
    lis.verbose = 0;

    if (argc > 2) {
	if (!strcmp(argv[1], "-v")) {
	    lis.verbose = 1;
	    argc--;
	    argv++;
	} 
    }
    
    if (argc > 2) {
        printf("Usage: ldb [-v] {name/instance}\n");
	printf("       name and instance may contain \"*\" wildcards\n");
        return;
    }

    num_name_tokens = 0;
    num_instance_tokens = 0;
    if (argc == 2) {
	argbuf = argv[1];
	p = strchr(argbuf, '/');
	if (p) {
	    *p++ = '\0';
	    parse_token(p, &must_be_first[1], 
			&num_instance_tokens, search_instance);
	}
	parse_token(argbuf, &must_be_first[0],
			&num_name_tokens, search_name);
    }
    (void) krb5_db_iterate(edit_context, list_iterator, argv[0]);
}

void delete_entry(argc, argv)
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
	exit_status++;
	return;
    }
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    exit_status++;
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    exit_status++;
	    return;
    }
    if (retval = krb5_parse_name(edit_context, argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	exit_status++;
	return;
    }
    if (princ_exists(argv[0], newprinc) == NO_PRINC) {
	com_err(argv[0], 0, "principal '%s' is not in the database", argv[1]);
	exit_status++;
	krb5_free_principal(edit_context, newprinc);
	return;
    }
    printf("Are you sure you want to delete '%s'?\nType 'yes' to confirm:",
	   argv[1]);
    if ((fgets(yesno, sizeof(yesno), stdin) == NULL) ||
	strcmp(yesno, "yes\n")) {
	printf("NOT removing '%s'\n", argv[1]);
	krb5_free_principal(edit_context, newprinc);
	return;
    }
    printf("OK, deleting '%s'\n", argv[1]);
    if (retval = krb5_db_delete_principal(edit_context, newprinc, &one)) {
	com_err(argv[0], retval, "while deleting '%s'", argv[1]);
	exit_status++;
    } else if (one != 1) {
	com_err(argv[0], 0, "no principal deleted? unknown error");
	exit_status++;
    }
#ifdef __STDC__
    printf("\a\a\aWARNING:  Be sure to take '%s' off all access control lists\n\tbefore reallocating the name\n", argv[1]);
#else
    printf("\007\007\007WARNING:  Be sure to take '%s' off all access control lists\n\tbefore reallocating the name\n", argv[1]);
#endif

    krb5_free_principal(edit_context, newprinc);
    return;
}

/*
 * This is the guts of add_rnd_key() and change_rnd_key()
 */
void
enter_rnd_key(argc, argv, change)
    int			argc;
    char		**argv;
    int			change;
{
    krb5_error_code retval;
    krb5_keyblock *tempkey;
    krb5_principal newprinc;
    int nprincs = 1;
    krb5_db_entry entry;
    krb5_boolean more;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	exit_status++;
	return;
    }
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    exit_status++;
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    exit_status++;
	    return;
    }
    if (retval = krb5_parse_name(edit_context, argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	exit_status++;
	return;
    }
    if (retval = krb5_db_get_principal(edit_context, newprinc, &entry, 
				       &nprincs, &more)) {
	com_err(argv[0], retval, "while trying to get principal's database entry");
	exit_status++;
	return;
    }
    if (change && !nprincs) {
	com_err(argv[0], 0, "No principal '%s' exists", argv[1]);
	exit_status++;
	goto errout;
    }
    if (!change && nprincs) {
	com_err(argv[0], 0, "Principal '%s' already exists.", argv[1]);
	exit_status++;
	goto errout;
    }
    
    if (!change) {
	retval = create_db_entry(newprinc, &entry);
	if (retval) {
	    com_err(argv[0], retval, "While creating new db entry.");
	    exit_status++;
	    goto errout;
	}
	nprincs = 1;
    }
    
    if (retval = krb5_random_key(edit_context, &master_encblock, 
				 master_random, &tempkey)) {
	com_err(argv[0], retval, "while generating random key");
	exit_status++;
	return;
    }

    /*
     * Free the old key, if it exists.  Also nuke the alternative key,
     * and associated salting information, since it all doesn't apply
     * for random keys.
     */
    if (entry.key.contents) {
	memset((char *)entry.key.contents, 0, entry.key.length);
	krb5_xfree(entry.key.contents);
    }
    if (entry.alt_key.contents) {
	memset((char *)entry.alt_key.contents, 0, entry.alt_key.length);
	krb5_xfree(entry.alt_key.contents);
	entry.alt_key.contents = 0;
    }
    if (entry.salt) {
	krb5_xfree(entry.salt);
	entry.salt = 0;
    }
    if (entry.alt_salt) {
	krb5_xfree(entry.alt_salt);
	entry.alt_salt = 0;
    }
    entry.salt_type = entry.alt_salt_type = 0;
    entry.salt_length = entry.alt_salt_length = 0;

    retval = krb5_kdb_encrypt_key(edit_context, &master_encblock, 
				  tempkey, &entry.key);
    krb5_free_keyblock(edit_context, tempkey);
    if (retval) {
	com_err(argv[0], retval, "while encrypting key for '%s'", argv[1]);
	exit_status++;
	goto errout;
    }

    if (retval = krb5_db_put_principal(edit_context, &entry, &nprincs)) {
	com_err(argv[0], retval, "while storing entry for '%s'\n", argv[1]);
	exit_status++;
	goto errout;
    }
    
    if (nprincs != 1) {
	com_err(argv[0], 0, "entry not stored in database (unknown failure)");
	exit_status++;
    }
	
errout:
    krb5_free_principal(edit_context, newprinc);
    if (nprincs)
	krb5_db_free_principal(edit_context, &entry, nprincs);
    return;
}

void add_rnd_key(argc, argv)
    int argc;
    char *argv[];
{
    enter_rnd_key(argc, argv, 0);
}

void change_rnd_key(argc, argv)
    int argc;
    char *argv[];
{
    enter_rnd_key(argc, argv, 1);
}

void add_new_key(argc, argv)
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
	exit_status++;
	return;
    }
    if (!valid_master_key) {
	    com_err(cmdname, 0, Err_no_master_msg);
	    exit_status++;
	    return;
    }
    if (retval = krb5_parse_name(edit_context, argv[1], &newprinc)) {
	com_err(cmdname, retval, "while parsing '%s'", argv[1]);
	exit_status++;
	return;
    }
    if (princ_exists(cmdname, newprinc) != NO_PRINC) {
	com_err(cmdname, 0, "principal '%s' already exists", argv[1]);
	exit_status++;
	krb5_free_principal(edit_context, newprinc);
	return;
    }
    enter_pwd_key(cmdname, argv[1], newprinc, newprinc, 0, salttype);
    krb5_free_principal(edit_context, newprinc);
    return;
}

void add_v4_key(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	exit_status++;
	return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    exit_status++;
	    return;
    }
    if (retval = krb5_parse_name(edit_context, argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	exit_status++;
	return;
    }
    if (princ_exists(argv[0], newprinc) != NO_PRINC) {
	com_err(argv[0], 0, "principal '%s' already exists", argv[1]);
	exit_status++;
	krb5_free_principal(edit_context, newprinc);
	return;
    }
    enter_pwd_key(argv[0], argv[1], newprinc, newprinc, 0,
		  KRB5_KDB_SALTTYPE_V4);
    krb5_free_principal(edit_context, newprinc);
    return;
}

void change_pwd_key(argc, argv)
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
	exit_status++;
	return;
    }
    if (!dbactive) {
	    com_err(cmdname, 0, Err_no_database);
	    exit_status++;
	    return;
    }
    if (!valid_master_key) {
	    com_err(cmdname, 0, Err_no_master_msg);
	    exit_status++;
	    return;
    }
    if (retval = krb5_parse_name(edit_context, argv[1], &newprinc)) {
	com_err(cmdname, retval, "while parsing '%s'", argv[1]);
	exit_status++;
	return;
    }
    if ((vno = princ_exists(argv[0], newprinc)) == NO_PRINC) {
	com_err(cmdname, 0, "No principal '%s' exists!", argv[1]);
	exit_status++;
	krb5_free_principal(edit_context, newprinc);
	return;
    }
    enter_pwd_key(cmdname, argv[1], newprinc, newprinc, vno, salttype);
    krb5_free_principal(edit_context, newprinc);
    return;
}

void change_v4_key(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    krb5_principal newprinc;
    krb5_kvno vno;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	exit_status++;
	return;
    }
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    exit_status++;
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    exit_status++;
	    return;
    }
    if (retval = krb5_parse_name(edit_context, argv[1], &newprinc)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	exit_status++;
	return;
    }
    if ((vno = princ_exists(argv[0], newprinc)) == NO_PRINC) {
	com_err(argv[0], 0, "No principal '%s' exists!", argv[1]);
	exit_status++;
	krb5_free_principal(edit_context, newprinc);
	return;
    }
    enter_pwd_key(argv[0], argv[1], newprinc, newprinc, vno,
		  KRB5_KDB_SALTTYPE_V4);
    krb5_free_principal(edit_context, newprinc);
    return;
}

void
enter_pwd_key(cmdname, newprinc, princ, string_princ, vno, salttype)
    char * cmdname;
    char * newprinc;
    krb5_const_principal princ;
    krb5_const_principal string_princ;
    krb5_kvno vno;
    int salttype;
{
    krb5_error_code retval;
    char password[BUFSIZ];
    int pwsize = sizeof(password);
    krb5_keyblock tempkey;
    krb5_data pwd;
    struct saltblock salt;

    if (retval = krb5_read_password(edit_context, krb5_default_pwd_prompt1,
				    krb5_default_pwd_prompt2,
				    password, &pwsize)) {
	com_err(cmdname, retval, "while reading password for '%s'", newprinc);
	exit_status++;
	return;
    }
    pwd.data = password;
    pwd.length = pwsize;

    salt.salttype = salttype;

    switch (salttype) {
    case KRB5_KDB_SALTTYPE_NORMAL:
	if (retval = krb5_principal2salt(edit_context,string_princ,&salt.saltdata)) {
	    com_err(cmdname, retval,
		    "while converting principal to salt for '%s'", newprinc);
	    exit_status++;
	    return;
	}
	break;
    case KRB5_KDB_SALTTYPE_V4:
	salt.saltdata.data = 0;
	salt.saltdata.length = 0;
	break;
    case KRB5_KDB_SALTTYPE_NOREALM:
	if (retval = krb5_principal2salt_norealm(edit_context, string_princ,
						 &salt.saltdata)) {
	    com_err(cmdname, retval,
		    "while converting principal to salt for '%s'", newprinc);
	    exit_status++;
	    return;
	}
	break;
    case KRB5_KDB_SALTTYPE_ONLYREALM:
    {
	krb5_data *foo;
	if (retval = krb5_copy_data(edit_context, 
				    krb5_princ_realm(edit_context, string_princ),
				    &foo)) {
	    com_err(cmdname, retval,
		    "while converting principal to salt for '%s'", newprinc);
	    exit_status++;
	    return;
	}
	salt.saltdata = *foo;
	krb5_xfree(foo);
	break;
    }
    default:
	com_err(cmdname, 0, "Don't know how to enter salt type %d", salttype);
	exit_status++;
	return;
    }
    retval = krb5_string_to_key(edit_context, &master_encblock, 
				master_keyblock.keytype, &tempkey, 
				&pwd, &salt.saltdata);
    memset(password, 0, sizeof(password)); /* erase it */
    if (retval) {
	com_err(cmdname, retval, "while converting password to key for '%s'",
		newprinc);
	exit_status++;
	krb5_xfree(salt.saltdata.data);
	return;
    }
    add_key(cmdname, newprinc, princ, &tempkey, ++vno,
	    (salttype == KRB5_KDB_SALTTYPE_NORMAL) ? 0 : &salt);
    krb5_xfree(salt.saltdata.data);
    memset((char *)tempkey.contents, 0, tempkey.length);
    krb5_xfree(tempkey.contents);
    return;
}

char *strdur(duration)
    time_t duration;
{
    static char out[50];
    int days, hours, minutes, seconds;
    
    days = duration / (24 * 3600);
    duration %= 24 * 3600;
    hours = duration / 3600;
    duration %= 3600;
    minutes = duration / 60;
    duration %= 60;
    seconds = duration;
    sprintf(out, "%d %s %02d:%02d:%02d", days, days == 1 ? "day" : "days",
	    hours, minutes, seconds);
    return out;
}

/*
 * XXX Still under construction....
 */
void show_principal(argc, argv)
    int argc;
    char *argv[];
{
    krb5_principal princ;
    int nprincs = 1;
    krb5_db_entry entry;
    krb5_boolean more;
    krb5_error_code retval;
    char *pr_name = 0;
    char *pr_mod = 0;
    time_t tmp_date;
    int i;
    static char *prflags[32] = {
	"DISALLOW_POSTDATED",	/* 0x00000001 */
	"DISALLOW_FORWARDABLE",	/* 0x00000002 */
	"DISALLOW_TGT_BASED",	/* 0x00000004 */
	"DISALLOW_RENEWABLE",	/* 0x00000008 */
	"DISALLOW_PROXIABLE",	/* 0x00000010 */
	"DISALLOW_DUP_SKEY",	/* 0x00000020 */
	"DISALLOW_ALL_TIX",	/* 0x00000040 */
	"REQUIRES_PRE_AUTH",	/* 0x00000080 */
	"REQUIRES_HW_AUTH",	/* 0x00000100 */
	"REQUIRES_PWCHANGE",	/* 0x00000200 */
	NULL,			/* 0x00000400 */
	NULL,			/* 0x00000800 */
	"DISALLOW_SVR",		/* 0x00001000 */
	"PWCHANGE_SERVICE",	/* 0x00002000 */
	"SUPPORT_DESMD5",	/* 0x00004000 */
	/* yes abuse detail that rest are initialized to NULL */
	};

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
	exit_status++;
	return;
    }
    if (!dbactive) {
	    com_err(argv[0], 0, Err_no_database);
	    exit_status++;
	    return;
    }
    if (!valid_master_key) {
	    com_err(argv[0], 0, Err_no_master_msg);
	    exit_status++;
	    return;
    }
    if (retval = krb5_parse_name(edit_context, argv[1], &princ)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	exit_status++;
	return;
    }

    if (retval = krb5_db_get_principal(edit_context,princ,&entry,&nprincs,&more)) {
	com_err(argv[0], retval, 
		"while trying to get principal's database entry");
	exit_status++;
	goto errout;
    }

    if (!nprincs) {
	com_err(argv[0], 0, "Principal %s not found.", argv[1]);
	exit_status++;
	goto errout;
    }
    
    if (retval = krb5_unparse_name(edit_context, entry.principal, &pr_name)) {
	com_err(argv[0], retval, "while unparsing principal");
	exit_status++;
	goto errout;
    }

    if (retval = krb5_unparse_name(edit_context, entry.mod_name, &pr_mod)) {
	com_err(argv[0], retval, "while unparsing 'modified by' principal");
	exit_status++;
	goto errout;
    }

    printf("Name: %s\n", pr_name);
    printf("Key version: %d\n", entry.kvno);
    printf("Maximum life: %s\n", strdur(entry.max_life));
    printf("Maximum renewable life: %s\n", strdur(entry.max_renewable_life));
    printf("Master key version: %d\n", entry.mkvno);
    tmp_date = (time_t) entry.expiration;
    printf("Expiration: %s", ctime(&tmp_date));
    tmp_date = (time_t) entry.pw_expiration;
    printf("Password expiration: %s", ctime(&tmp_date));
    tmp_date = (time_t) entry.last_pwd_change;
    printf("Last password change: %s", ctime(&tmp_date));
    tmp_date = (time_t) entry.last_success;
    printf("Last successful password: %s", ctime(&tmp_date));
    tmp_date = (time_t) entry.last_failed;
    printf("Last failed password attempt: %s", ctime(&tmp_date));
    printf("Failed password attempts: %d\n", entry.fail_auth_count);
    tmp_date = (time_t) entry.mod_date;
    printf("Last modified by %s on %s", pr_mod, ctime(&tmp_date));
    printf("Attributes:");
    for (i = 0; i < 32; i++) {
	if (entry.attributes & (krb5_flags) 1 << i)
	    if (prflags[i])
		printf(" %s", prflags[i]);
	    else
		printf("UNKNOWN_0x%08X", (krb5_flags) 1 << i);
    }
    printf("\n");
    printf("Salt: %d\n", entry.salt_type);
    printf("Alt salt: %d\n", entry.salt_type);
    
    if (!nprincs) {
	com_err(argv[0], 0, "Principal '%s' does not exist", argv[1]);
	exit_status++;
	goto errout;
    }
    
errout:
    krb5_free_principal(edit_context, princ);
    if (nprincs)
	krb5_db_free_principal(edit_context, &entry, nprincs);
}

int parse_princ_args(argc, argv, entry, pass, randkey, caller)
    int argc;
    char *argv[];
    krb5_db_entry *entry;
    char **pass;
    int *randkey;
    char *caller;
{
    int i, j, attrib_set;
    time_t date;
    struct timeb now;
    krb5_error_code retval;
    
    static struct pflag flags[] = {
    {"allow_postdated",	15,	KRB5_KDB_DISALLOW_POSTDATED,	1},
    {"allow_forwardable",17,	KRB5_KDB_DISALLOW_FORWARDABLE,	1},
    {"allow_tgs_req",	13,	KRB5_KDB_DISALLOW_TGT_BASED,	1},
    {"allow_renewable",	15,	KRB5_KDB_DISALLOW_RENEWABLE,	1},
    {"allow_proxiable",	15,	KRB5_KDB_DISALLOW_PROXIABLE,	1},
    {"allow_dup_skey",	14,	KRB5_KDB_DISALLOW_DUP_SKEY,	1},
    {"allow_tix",	9,	KRB5_KDB_DISALLOW_ALL_TIX,	1},
    {"requires_preauth",16,	KRB5_KDB_REQUIRES_PRE_AUTH,	0},
    {"requires_hwauth",	15,	KRB5_KDB_REQUIRES_HW_AUTH,	0},
    {"needchange",	10,	KRB5_KDB_REQUIRES_PWCHANGE,	0},
    {"allow_svr",	9,	KRB5_KDB_DISALLOW_SVR,		1},
    {"password_changing_service",25,KRB5_KDB_PWCHANGE_SERVICE,	0},
    {"support_desmd5",  14,     KRB5_KDB_SUPPORT_DESMD5,        0}
    };
    
    *pass = NULL;
    ftime(&now);
    *randkey = 0;
    for (i = 1; i < argc - 1; i++) {
	attrib_set = 0;
	if (strlen(argv[i]) == 5 &&
	    !strcmp("-kvno", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		entry->kvno = atoi(argv[i]);
		continue;
	    }
	}
	if (strlen(argv[i]) == 8 &&
	    !strcmp("-maxlife", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		entry->max_life = get_date(argv[i], now) - now.time;
		continue;
	    }
	}
	if (strlen(argv[i]) == 7 &&
	    !strcmp("-expire", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		date = get_date(argv[i], now);
		entry->expiration = date == (time_t) -1 ? 0 : date;
		continue;
	    }
	}
	if (strlen(argv[i]) == 9 &&
	    !strcmp("-pwexpire", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		date = get_date(argv[i], now);
		entry->pw_expiration = date == (time_t) -1 ? 0 : date;
		continue;
	    }
	}
	if (strlen(argv[i]) == 3 &&
	    !strcmp("-pw", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		*pass = argv[i];
		continue;
	    }
	}
	if (strlen(argv[i]) == 8 &&
	    !strcmp("-randkey", argv[i])) {
	    ++*randkey;
	    continue;
	}
	for (j = 0; j < sizeof (flags) / sizeof (struct pflag); j++) {
	    if (strlen(argv[i]) == flags[j].flaglen + 1 &&
		!strcmp(flags[j].flagname,
			&argv[i][1] /* strip off leading + or - */)) {
		if (flags[j].set && argv[i][0] == '-' ||
		    !flags[j].set && argv[i][0] == '+') {
		    entry->attributes |= flags[j].theflag;
		    attrib_set++;
		    break;
		} else if (flags[j].set && argv[i][0] == '+' ||
			   !flags[j].set && argv[i][0] == '-') {
		    entry->attributes &= ~flags[j].theflag;
		    attrib_set++;
		    break;
		} else {
		    return -1;
		}
	    }
	}
	if (!attrib_set)
	    return -1;		/* nothing was parsed */
    }
    if (i != argc - 1) {
	fprintf(stderr, "%s: parser lost count!\n", caller);
	return -1;
    }
    retval = krb5_parse_name(edit_context, argv[i], &entry->principal);
    if (retval) {
	com_err(caller, retval, "while parsing principal");
	return -1;
    }
    return 0;
}

void modent(argc, argv)
    int argc;
    char *argv[];
{
    krb5_db_entry entry, oldentry;
    krb5_principal kprinc;
    krb5_error_code retval;
    krb5_boolean more;
    char *pass, *canon;
    int one = 1, nprincs = 1, randkey = 0;
    
    retval = krb5_parse_name(edit_context, argv[argc - 1], &kprinc);
    if (retval) {
	com_err("modify_principal", retval, "while parsing principal");
	return;
    }
    retval = krb5_unparse_name(edit_context, kprinc, &canon);
    if (retval) {
	com_err("modify_principal", retval,
		"while canonicalizing principal");
	krb5_free_principal(edit_context, kprinc);
	return;
    }
    retval = krb5_db_get_principal(edit_context, kprinc, &oldentry,
				   &nprincs, &more);
    krb5_free_principal(edit_context, kprinc);
    if (retval) {
	com_err("modify_entry", retval, "while getting \"%s\".",
		canon);
	free(canon);
	return;
    }
    if (!nprincs) {
	com_err(argv[0], 0, "No principal \"%s\" exists", canon);
	exit_status++;
	free(canon);
	return;
    }
    memcpy((krb5_pointer) &entry, (krb5_pointer) &oldentry,
	   sizeof (krb5_db_entry));
    retval = parse_princ_args(argc, argv,
			      &entry, &pass, &randkey,
			      "modify_principal");
    if (retval) {
	fprintf(stderr, "modify_principal: bad arguments\n");
	krb5_free_principal(edit_context, entry.principal);
	free(canon);
	return;
    }
    if (randkey) {
	fprintf(stderr, "modify_principal: -randkey not allowed\n");
	krb5_free_principal(edit_context, entry.principal);
	free(canon);
	return;
    }
    entry.mod_name = master_princ;
    if (retval = krb5_timeofday(edit_context, &entry.mod_date)) {
	com_err(argv[0], retval, "while fetching date");
	krb5_free_principal(edit_context, entry.principal);
	exit_status++;
	free(canon);
	return;
    }
    retval = krb5_db_put_principal(edit_context, &entry, &one);
    krb5_free_principal(edit_context, entry.principal);
    if (retval) {
	com_err("modify_principal", retval,
		"while modifying \"%s\".", canon);
	free(canon);
	return;
    }
    if (one != 1) {
	com_err(argv[0], 0, "entry not stored in database (unknown failure)");
	exit_status++;
    }
    printf("Principal \"%s\" modified.\n", canon);
    free(canon);
}

#ifdef HAVE_GETCWD
#define getwd(x) getcwd(x,MAXPATHLEN)
#endif

void change_working_dir(argc, argv)
	int	argc;
	char	**argv;
{
	if (argc != 2) {
		com_err(argv[0], 0, "Usage: %s directory", argv[0]);
		exit_status++;
		return;
	}
	if (chdir(argv[1])) {
		com_err(argv[0], errno,
			"Couldn't change directory to %s", argv[1]);
		exit_status++;
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
		exit_status++;
		return;
	}
	puts(buf);
}

#ifdef HAVE_GETCWD
#undef getwd
#endif

int 
quit()
{
    krb5_error_code retval;
    static krb5_boolean finished = 0;

    if (finished)
	return 0;
    if (valid_master_key) {
	    (void) krb5_finish_key(edit_context, &master_encblock);
	    (void) krb5_finish_random_key(edit_context, &master_encblock, 
					  &master_random);
    }
    retval = krb5_db_fini(edit_context);
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    finished = TRUE;
    if (retval && retval != KRB5_KDB_DBNOTINITED) {
	com_err(progname, retval, "while closing database");
	exit_status++;
	return 1;
    }
    return 0;
}

#ifndef HAVE_FTIME
ftime(tp)
	register struct timeb *tp;
{
	struct timeval t;
	struct timezone tz;

	if (gettimeofday(&t, &tz) < 0)
		return (-1);
	tp->time = t.tv_sec;
	tp->millitm = t.tv_usec / 1000;
	tp->timezone = tz.tz_minuteswest;
	tp->dstflag = tz.tz_dsttime;
}
#endif
