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
#include "kdb5_edit.h"

struct mblock mblock = {				/* XXX */
    KRB5_KDB_MAX_LIFE,
    KRB5_KDB_MAX_RLIFE,
    KRB5_KDB_EXPIRATION,
    KRB5_KDB_DEF_FLAGS,
    0
};

krb5_key_salt_tuple ks_tuple_default[] = {{ ENCTYPE_DES_CBC_CRC, 0 }};

krb5_key_salt_tuple *std_ks_tuple = ks_tuple_default;
int std_ks_tuple_count = 1;

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

/*
 * Script input, specified by -s.
 */
FILE *scriptfile = (FILE *) NULL;

static void
usage(who, status)
    char *who;
    int status;
{
    fprintf(stderr,
	    "usage: %s [-d dbpathname] [-r realmname] [-R request ]\n",
	    who);
    fprintf(stderr, "\t [-k enctype] [-M mkeyname]\n");
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
    int enctypedone = 0;
    extern krb5_kt_ops krb5_ktf_writable_ops;
    char	*request = NULL;
    krb5_realm_params *rparams;

    retval = krb5_init_context(&edit_context);
    if (retval) {
	    fprintf(stderr, "krb5_init_context failed with error #%ld\n",
		    (long) retval);
	    exit(1);
    }
    krb5_init_ets(edit_context);

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    progname = argv[0];

    while ((optchar = getopt(argc, argv, "P:d:r:R:k:M:e:ms:")) != EOF) {
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
	    if (!krb5_string_to_enctype(optarg, &master_keyblock.enctype))
		enctypedone++;
	    else
		com_err(argv[0], 0, "%s is an invalid enctype", optarg);
	    break;
	case 'M':			/* master key name in DB */
	    mkey_name = optarg;
	    break;
	case 'm':
	    manual_mkey = TRUE;
	    break;
	case 's':
	    /* Open the script file */
	    if (!(scriptfile = fopen(optarg, "r"))) {
		com_err(argv[0], errno, "while opening script file %s",
			optarg);
		exit(1);
	    }
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
	if (rparams->realm_enctype_valid && !enctypedone) {
	    master_keyblock.enctype = rparams->realm_enctype;
	    enctypedone++;
	}

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

	/* Get the value of the supported key/salt pairs */
	if (rparams->realm_num_keysalts) {
	    std_ks_tuple_count = rparams->realm_num_keysalts;
	    std_ks_tuple = rparams->realm_keysalts;
	    rparams->realm_num_keysalts = 0;
	    rparams->realm_keysalts = (krb5_key_salt_tuple *) NULL;
	}


	krb5_free_realm_params(edit_context, rparams);
    }

    /* Dump creates files which should not be world-readable.  It is easiest
       to do a single umask call here; any shells run by the ss command
       interface will have umask = 77 but that is not a serious problem. */
    (void) umask(077);

    if ((retval = krb5_kt_register(edit_context, &krb5_ktf_writable_ops))) {
	com_err(progname, retval,
		"while registering writable key table functions");
	exit(1);
    }

    /* Handle defaults */
    if (!dbname)
	dbname = DEFAULT_KDB_FILE;

    if (!enctypedone)
	master_keyblock.enctype = DEFAULT_KDC_ENCTYPE;

    if (!valid_enctype(master_keyblock.enctype)) {
	char tmp[32];
	if (krb5_enctype_to_string(master_keyblock.enctype, tmp, sizeof(tmp)))
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP,
		    "while setting up enctype %d", master_keyblock.enctype);
	else
	    com_err(argv[0], KRB5_PROG_KEYTYPE_NOSUPP, tmp);
	exit(1);
    }

    krb5_use_enctype(edit_context, &master_encblock, master_keyblock.enctype);

    if (cur_realm) {
	if ((retval = krb5_set_default_realm(edit_context, cur_realm))) {
	    com_err(progname, retval, "while setting default realm name");
	    exit(1);
        }
    } else {
	if ((retval = krb5_get_default_realm(edit_context, &defrealm))) {
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
    int i, nprincs = 1;
    krb5_db_entry entry;
    krb5_boolean more;
    krb5_error_code retval;
    krb5_kvno vno = 0;

    if ((retval = krb5_db_get_principal(edit_context, principal, &entry, 
					&nprincs, &more))) {
	com_err(pname, retval, 
		"while attempting to verify principal's existence");
	exit_status++;
	return 0;
    }
    if (!nprincs)
	    return NO_PRINC;
    for (i = 0; i < entry.n_key_data; i++) 
	if (vno < entry.key_data[i].key_data_kvno)
	    vno = entry.key_data[i].key_data_kvno;
    krb5_db_free_principal(edit_context, &entry, nprincs);
    return(vno);
}

int create_db_entry(principal, newentry)
    krb5_principal 	  principal;
    krb5_db_entry  	* newentry;
{
    krb5_tl_mod_princ	  mod_princ;
    int	retval;

    memset(newentry, 0, sizeof(krb5_db_entry));
    
    newentry->len = KRB5_KDB_V1_BASE_LENGTH;
    newentry->mkvno = mblock.mkvno;
    newentry->attributes = mblock.flags;
    newentry->max_life = mblock.max_life;
    newentry->max_renewable_life = mblock.max_rlife;
    newentry->expiration = mblock.expiration;

    if ((retval = krb5_copy_principal(edit_context, principal,
				      &newentry->princ)))
	return retval;

    if ((retval = krb5_timeofday(edit_context, &mod_princ.mod_date)))
	goto create_db_entry_error;

    if ((retval = krb5_copy_principal(edit_context, master_princ, 
				      &mod_princ.mod_princ)))
	goto create_db_entry_error;

    retval = krb5_dbe_encode_mod_princ_data(edit_context, &mod_princ, newentry);
    krb5_xfree(mod_princ.mod_princ->data);

    if (!retval)
    	return 0;

create_db_entry_error:
    krb5_dbe_free_contents(edit_context, newentry);
    exit_status++;
    return retval;
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
    int nentries, i;
    krb5_boolean more;
    krb5_data scratch, pwd;

    if (current_dbname)
	    free(current_dbname);
    if (!(current_dbname = malloc(strlen(dbname)+1))) {
	    com_err(pname, 0, "Out of memory while trying to store dbname");
	    exit(1);
    }
    strcpy(current_dbname, dbname);
    if ((retval = krb5_db_set_name(edit_context, current_dbname))) {
	com_err(pname, retval, "while setting active database to '%s'",
		dbname);
	exit_status++;
	return(1);
    } 
    if ((retval = krb5_db_init(edit_context))) {
	com_err(pname, retval, "while initializing database");
	exit_status++;
	return(1);
    }
	    
   /* assemble & parse the master key name */

    if ((retval = krb5_db_setup_mkey_name(edit_context, mkey_name, cur_realm,
					  0, &master_princ))) {
	com_err(pname, retval, "while setting up master key name");
	exit_status++;
	return(1);
    }
    nentries = 1;
    if ((retval = krb5_db_get_principal(edit_context, master_princ, 
					&master_entry, &nentries, &more))) {
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
    for (mblock.mkvno = 1, i = 0; i < master_entry.n_key_data; i++) 
	if (mblock.mkvno < master_entry.key_data[i].key_data_kvno)
	    mblock.mkvno = master_entry.key_data[i].key_data_kvno;

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
				    master_keyblock.enctype,
				    &master_keyblock, &pwd, &scratch);
	if (retval) {
	    com_err(pname, retval,
		    "while transforming master key from password");
	    return(1);
	}
	free(scratch.data);
	mkey_password = 0;
    } else if ((retval = krb5_db_fetch_mkey(edit_context, master_princ, 
					    &master_encblock, manual_mkey, 
					    FALSE, stash_file,
					    0, &master_keyblock))) {
	com_err(pname, retval, "while reading master key");
	com_err(pname, 0, "Warning: proceeding without master key");
	exit_status++;
	valid_master_key = 0;
	dbactive = TRUE;
	return(0);
    }
    valid_master_key = 1;
    if ((retval = krb5_db_verify_master_key(edit_context, master_princ, 
					    &master_keyblock,&master_encblock))
	) {
	com_err(pname, retval, "while verifying master key");
	exit_status++;
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	krb5_xfree(master_keyblock.contents);
	valid_master_key = 0;
	dbactive = TRUE;
	return(1);
    }
    if ((retval = krb5_process_key(edit_context, &master_encblock,
				   &master_keyblock))) {
	com_err(pname, retval, "while processing master key");
	exit_status++;
	memset((char *)master_keyblock.contents, 0, master_keyblock.length);
	krb5_xfree(master_keyblock.contents);
	valid_master_key = 0;
	dbactive = TRUE;
	return(1);
    }
    if ((retval = krb5_init_random_key(edit_context, &master_encblock,
				       &master_keyblock,
				       &master_random))) {
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
	if ((retval = krb5_db_fetch_mkey(edit_context, master_princ,
					 &master_encblock,
					TRUE, FALSE, (char *) NULL,
					0, &master_keyblock))) {
		com_err(pname, retval, "while reading master key");
		exit_status++;
		return;
	}
	if ((retval = krb5_db_verify_master_key(edit_context, master_princ, 
						&master_keyblock,
						&master_encblock))) {
		com_err(pname, retval, "while verifying master key");
		exit_status++;
		return;
	}
	if ((retval = krb5_process_key(edit_context, &master_encblock,
				       &master_keyblock))) {
		com_err(pname, retval, "while processing master key");
		exit_status++;
		return;
	}
	if ((retval = krb5_init_random_key(edit_context, &master_encblock,
					   &master_keyblock,
					   &master_random))) {
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
    if ((retval = krb5_kt_resolve(edit_context, ktname, &ktid))) {
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

	if ((retval = krb5_parse_name(edit_context, pname, &princ))) {
	    com_err(argv[0], retval, "while parsing %s", pname);
	    exit_status++;
	    free(pname);
	    continue;
	}
	nentries = 1;
	if ((retval = krb5_db_get_principal(edit_context, princ, &dbentry,
					    &nentries, &more))) {
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
	if ((retval = krb5_dbekd_decrypt_key_data(edit_context,
						  &master_encblock,
						  &dbentry.key_data[0],
						  &newentry.key, NULL))) {
	    com_err(argv[0], retval, "while decrypting key for '%s'", pname);
	    exit_status++;
	    goto cleanall;
	}
	newentry.principal = princ;
	newentry.vno = dbentry.key_data[0].key_data_kvno;
	if ((retval = krb5_kt_add_entry(edit_context, ktid, &newentry))) {
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
    if ((retval = krb5_kt_close(edit_context, ktid))) {
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
	unsigned char kvno;

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

	if ((retval = krb5_parse_name(edit_context, pname, &princ))) {
	    com_err(argv[0], retval, "while parsing %s", pname);
	    exit_status++;
	    free(pname);
	    continue;
	}
	nentries = 1;
	if ((retval = krb5_db_get_principal(edit_context, princ, &dbentry,
					    &nentries, &more))) {
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
	if ((retval = krb5_dbekd_decrypt_key_data(edit_context,
						  &master_encblock,
						  &dbentry.key_data[0],
						  &key, NULL))) {
	    com_err(argv[0], retval, "while decrypting key for '%s'", pname);
	    exit_status++;
	    goto cleanall;
	}
	if (key.enctype != 1) {
		com_err(argv[0], 0, "%s does not have a DES key!", pname);
		exit_status++;
		memset((char *)key.contents, 0, key.length);
		krb5_xfree(key.contents);
		continue;
	}
	fwrite(argv[i], strlen(argv[i]) + 1, 1, fout); /* p.name */
	fwrite(argv[1], strlen(argv[1]) + 1, 1, fout); /* p.instance */
	fwrite(cur_realm, strlen(cur_realm) + 1, 1, fout); /* p.realm */
        kvno = (unsigned char) dbentry.key_data[0].key_data_kvno;
        fwrite((char *)&kvno, sizeof(kvno), 1, fout);
	fwrite((char *)key.contents, 8, 1, fout);
	printf("'%s' added to V4 srvtab '%s'\n", pname, ktname);
	memset((char *)key.contents, 0, key.length);
	krb5_xfree(key.contents);
    cleanall:
	    krb5_db_free_principal(edit_context, &dbentry, nentries);
    cleanmost:
	    krb5_free_principal(edit_context, princ);
	    free(pname);
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

    if ((krb5_princ_size(edit_context, chk_entry->princ) > 1) &&
	(num_name_tokens == 0) && 
	(num_instance_tokens > 0))
	return(check_for_match(search_instance, must_be_first[1], chk_entry,
			num_instance_tokens, instances));

    if ((krb5_princ_size(edit_context, chk_entry->princ) > 1) &&
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

    if ((retval = krb5_unparse_name(edit_context, entry->princ, &name))) {
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
    if ((retval = krb5_parse_name(edit_context, argv[1], &newprinc))) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	exit_status++;
	return;
    }
    if (princ_exists(argv[0], newprinc) == NO_PRINC) {
	com_err(argv[0], 0, "principal '%s' is not in the database", argv[1]);
	krb5_free_principal(edit_context, newprinc);
	exit_status++;
	return;
    }
    if (!scriptfile) {
	/* Only confirm if we're interactive */
	printf("Are you sure you want to delete '%s'?\nType 'yes' to confirm:",
	       argv[1]);
	if ((fgets(yesno, sizeof(yesno), stdin) == NULL) ||
	    strcmp(yesno, "yes\n")) {
	    printf("NOT removing '%s'\n", argv[1]);
	    krb5_free_principal(edit_context, newprinc);
	    return;
	}
	printf("OK, deleting '%s'\n", argv[1]);
    }
    if ((retval = krb5_db_delete_principal(edit_context, newprinc, &one))) {
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

static char *
strdur(deltat)
    krb5_deltat deltat;
{
    static char deltat_buffer[128];

    (void) krb5_deltat_to_string(deltat, deltat_buffer, sizeof(deltat_buffer));
    return(deltat_buffer);
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
    char buffer[256];
    int i;

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
    if ((retval = krb5_parse_name(edit_context, argv[1], &princ))) {
	com_err(argv[0], retval, "while parsing '%s'", argv[1]);
	exit_status++;
	return;
    }

    if ((retval = krb5_db_get_principal(edit_context,princ,&entry,
					&nprincs,&more))) {
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
    
    if ((retval = krb5_unparse_name(edit_context, entry.princ, &pr_name))) {
	com_err(argv[0], retval, "while unparsing principal");
	exit_status++;
	goto errout;
    }

    printf("Name: %s\n", pr_name);
    printf("Maximum life: %s\n", strdur(entry.max_life));
    printf("Maximum renewable life: %s\n", strdur(entry.max_renewable_life));
    printf("Master key version: %d\n", entry.mkvno);
    (void) krb5_timestamp_to_string(entry.expiration, buffer, sizeof(buffer));
    printf("Expiration: %s\n", buffer);
    (void) krb5_timestamp_to_string(entry.pw_expiration,
				    buffer, sizeof(buffer));
    printf("Password expiration: %s\n", buffer);
/*    (void) krb5_timestamp_to_string(entry.last_pw_change,
				    buffer, sizeof(buffer)); */
/*    printf("Last password change: %s\n", buffer); */
    (void) krb5_timestamp_to_string(entry.last_success,
				    buffer, sizeof(buffer));
    printf("Last successful password: %s\n", buffer);
    (void) krb5_timestamp_to_string(entry.last_failed,
				    buffer, sizeof(buffer));
    printf("Last failed password attempt: %s\n", buffer);
    printf("Failed password attempts: %d\n", entry.fail_auth_count);
/*    tmp_date = (time_t) entry.mod_date; */
/*    printf("Last modified by %s on %s", pr_mod, ctime(&tmp_date)); */
    (void) krb5_flags_to_string(entry.attributes, ", ",
				buffer, sizeof(buffer));
    printf("Attributes: %s\n", buffer);

    printf("Number of keys: %d\n", entry.n_key_data);
    for (i = 0; i < entry.n_key_data; i++) {
	char enctype[64], salttype[32];
	krb5_keyblock key;
	krb5_keysalt salt;

	if ((retval = krb5_dbekd_decrypt_key_data(edit_context,
						  &master_encblock,
						  &entry.key_data[i],
						  &key, &salt))) {
	    com_err(argv[0], retval, "while reading key information");
	    continue;
	}

	/* Paranoia... */
	memset((char *)key.contents, 0, key.length);
	krb5_xfree(key.contents);

	if (krb5_enctype_to_string(key.enctype, enctype, sizeof(enctype)))
	    sprintf(enctype, "<Encryption type 0x%x>", key.enctype);
	if (krb5_salttype_to_string(salt.type, salttype, sizeof(salttype)))
	    sprintf(salttype, "<Salt type 0x%x>", salt.type);
	
	printf("Key: Version %d, Type %s/%s\n",
	       entry.key_data[i].key_data_kvno, enctype, salttype);
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
    int i, attrib_set;
    krb5_timestamp date;
    krb5_error_code retval;
    
    *pass = NULL;
    *randkey = 0;
    for (i = 1; i < argc - 1; i++) {
	attrib_set = 0;
/*
	if (strlen(argv[i]) == 5 &&
	    !strcmp("-kvno", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		entry->kvno = atoi(argv[i]);
		continue;
	    }
	}
*/
	if (strlen(argv[i]) == 8 &&
	    !strcmp("-maxlife", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		(void) krb5_string_to_deltat(argv[i], &entry->max_life);
		continue;
	    }
	}
	if (strlen(argv[i]) == 7 &&
	    !strcmp("-expire", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		(void) krb5_string_to_timestamp(argv[i], &date);
		entry->expiration = date == (time_t) -1 ? 0 : date;
		continue;
	    }
	}
	if (strlen(argv[i]) == 9 &&
	    !strcmp("-pwexpire", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		(void) krb5_string_to_timestamp(argv[i], &date);
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
	if (!krb5_string_to_flags(argv[i], "+", "-", &entry->attributes))
	    attrib_set++;
	if (!attrib_set)
	    return -1;		/* nothing was parsed */
    }
    if (i != argc - 1) {
	fprintf(stderr, "%s: parser lost count!\n", caller);
	return -1;
    }
    retval = krb5_parse_name(edit_context, argv[i], &entry->princ);
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
    krb5_tl_mod_princ mod_princ;
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
	krb5_free_principal(edit_context, entry.princ);
	free(canon);
	return;
    }
    if (randkey) {
	fprintf(stderr, "modify_principal: -randkey not allowed\n");
	krb5_free_principal(edit_context, entry.princ);
	free(canon);
	return;
    }
    mod_princ.mod_princ = master_princ;
    if ((retval = krb5_timeofday(edit_context, &mod_princ.mod_date))) {
	com_err(argv[0], retval, "while fetching date");
	krb5_free_principal(edit_context, entry.princ);
	exit_status++;
	free(canon);
	return;
    }
    if ((retval=krb5_dbe_encode_mod_princ_data(edit_context,
					       &mod_princ,&entry))) {
	com_err(argv[0], retval, "while setting mod_prince and mod_date");
	krb5_free_principal(edit_context, entry.princ);
	exit_status++;
	free(canon);
	return;
    }
    retval = krb5_db_put_principal(edit_context, &entry, &one);
    krb5_free_principal(edit_context, entry.princ);
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
