/*
 * admin/edit/cpw.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * Change passwords for a KDC db entry.
 */

#include "k5-int.h"
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"
#include <stdio.h>
#include <time.h>

#include "kdb5_edit.h"

extern char	*Err_no_master_msg;
extern char	*Err_no_database;
extern char	*current_dbname;

/*
 * I can't figure out any way for this not to be global, given how ss
 * works.
 */
extern int exit_status;
extern krb5_context edit_context;
extern krb5_keyblock master_keyblock;
extern krb5_principal master_princ;
extern krb5_db_entry master_entry;
extern krb5_encrypt_block master_encblock;
extern int	valid_master_key;
extern char *krb5_default_pwd_prompt1, *krb5_default_pwd_prompt2;
extern krb5_boolean dbactive;
extern FILE *scriptfile;

static krb5_key_salt_tuple ks_tuple_rnd_def[] = {{ KEYTYPE_DES, 0 }};
static int ks_tuple_rnd_def_count = 1;

static void
enter_rnd_key(argc, argv, entry)
    int			  argc;
    char	       ** argv;
    krb5_db_entry 	* entry;
{
    krb5_error_code 	  retval;
    int 		  nprincs = 1;
    
    if ((retval = krb5_dbe_crk(edit_context, &master_encblock,
			       ks_tuple_rnd_def,
			       ks_tuple_rnd_def_count, entry))) {
	com_err(argv[0], retval, "while generating random key");
        krb5_db_free_principal(edit_context, entry, nprincs);
	exit_status++;
	return;
    }

    if ((retval = krb5_db_put_principal(edit_context, entry, &nprincs))) {
	com_err(argv[0], retval, "while storing entry for '%s'\n", argv[1]);
        krb5_db_free_principal(edit_context, entry, nprincs);
	exit_status++;
	return;
    }
    
    krb5_db_free_principal(edit_context, entry, nprincs);

    if (nprincs != 1) {
	com_err(argv[0], 0, "entry not stored in database (unknown failure)");
	exit_status++;
    }
	
}

static int
pre_key(argc, argv, newprinc, entry)
    int 	 	  argc;
    char 	       ** argv;
    krb5_principal 	* newprinc;
    krb5_db_entry 	* entry;
{
    krb5_boolean 	  more;
    krb5_error_code 	  retval;
    int 		  nprincs = 1;

    if (!dbactive) {
	com_err(argv[0], 0, Err_no_database);
    } else if (!valid_master_key) {
	com_err(argv[0], 0, Err_no_master_msg);
    } else if ((retval = krb5_parse_name(edit_context,
					 argv[argc-1],
					 newprinc))) {
	com_err(argv[0], retval, "while parsing '%s'", argv[argc-1]);
    } else if ((retval = krb5_db_get_principal(edit_context, *newprinc, entry, 
					       &nprincs, &more))) {
        com_err(argv[0],retval,"while trying to get principal's db entry");
    } else if ((nprincs > 1) || (more)) {
	krb5_db_free_principal(edit_context, entry, nprincs);
    	krb5_free_principal(edit_context, *newprinc);
    } else if (nprincs) 
	return(1);
    else 
	return(0);
    return(-1);
}

void add_rnd_key(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code 	  retval;
    krb5_principal 	  newprinc;
    krb5_db_entry 	  entry;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
    	exit_status++;
	return;
    }
    switch (pre_key(argc, argv, &newprinc, &entry)) {
    case 0:
	if ((retval = create_db_entry(newprinc, &entry))) {
	    com_err(argv[0], retval, "While creating new db entry.");
	    exit_status++;
	    return;
	}
    	krb5_free_principal(edit_context, newprinc);
        enter_rnd_key(argc, argv, &entry);
	return;
    case 1:
	com_err(argv[0], 0, "Principal '%s' already exists.", argv[1]);
        krb5_db_free_principal(edit_context, &entry, 1);
        krb5_free_principal(edit_context, newprinc);
    default:
    	exit_status++;
	break;
    }
}

void change_rnd_key(argc, argv)
    int argc;
    char *argv[];
{
    krb5_principal 	  newprinc;
    krb5_db_entry 	  entry;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s principal", argv[0]);
    	exit_status++;
	return;
    }
    switch (pre_key(argc, argv, &newprinc, &entry)) {
    case 1:
    	krb5_free_principal(edit_context, newprinc);
        enter_rnd_key(argc, argv, &entry);
	break;
    case 0:
    	com_err(argv[0], 0, "No principal '%s' exists", argv[1]);
    default:
        exit_status++;
	break;
    }
}

static krb5_key_salt_tuple ks_tuple_default[] = {{ KEYTYPE_DES, 0 }};
static int ks_tuple_count_default = 1;

void 
enter_pwd_key(cmdname, princ, ks_tuple, ks_tuple_count, entry)
    char 		* cmdname;
    char 		* princ;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    krb5_db_entry 	* entry;
{
    char 		  password[KRB5_ADM_MAX_PASSWORD_LEN];
    int 		  pwsize = KRB5_ADM_MAX_PASSWORD_LEN;
    krb5_error_code 	  retval;
    int			  one = 1;
  
    /* Prompt for password only if interactive */
    if (!scriptfile) {
	if ((retval = krb5_read_password(edit_context,
					 krb5_default_pwd_prompt1,
					 krb5_default_pwd_prompt2,
					 password, &pwsize))) {
	    com_err(cmdname, retval, "while reading password for '%s'", princ);
	    goto errout;
	}
    }
    else {
	if (!fgets(password, pwsize, scriptfile)) {
	    com_err(cmdname, errno, "while reading password for '%s'", princ);
	    retval = errno;
	    goto errout;
	}
	else {
	    pwsize = strlen(password);
	    if (password[pwsize-1] == '\n') {
		password[pwsize-1] = '\0';
		pwsize--;
	    }
	}
    }
    
    if (ks_tuple_count == 0) {
	ks_tuple_count = ks_tuple_count_default;
	ks_tuple = ks_tuple_default;
    }
    if ((retval = krb5_dbe_cpw(edit_context, &master_encblock, ks_tuple,
			       ks_tuple_count, password, entry))) {
	com_err(cmdname, retval, "while storing entry for '%s'\n", princ);
        memset(password, 0, sizeof(password)); /* erase it */
	krb5_dbe_free_contents(edit_context, entry);
	goto errout;
    }
    memset(password, 0, sizeof(password)); /* erase it */

    /* Write the entry back out and we're done */
    if ((retval = krb5_db_put_principal(edit_context, entry, &one))) {
	com_err(cmdname, retval, "while storing entry for '%s'\n", princ);
    }

    if (one != 1) {
        com_err(cmdname, 0, "entry not stored in database (unknown failure)");
        exit_status++;
    }

errout:;
    krb5_db_free_principal(edit_context, entry, one);
    if (retval)
        exit_status++;
    return;
}

void change_pwd_key(argc, argv)
    int argc;
    char *argv[];
{
    krb5_key_salt_tuple	* ks_tuple = NULL;
    krb5_int32		  n_ks_tuple = 0;
    krb5_principal 	  newprinc;
    krb5_db_entry	  entry;

    int			  i;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s [<key_type[:<salt_type>]>] principal",
		argv[0]);
    	exit_status++;
	return;
    }

    for (i = 1; i < (argc - 1); i++) {
	if (krb5_string_to_keysalts(argv[i],
				    "",
				    ":",
				    0,
				    &ks_tuple,
				    &n_ks_tuple)) {
	    com_err(argv[0], 0, "Unrecognized key/salt type %s", argv[i]);
	    exit_status++;
	    return;
	}
    }

    switch (pre_key(argc, argv, &newprinc, &entry)) {
    case 1:
        /* Done with principal */ 
        krb5_free_principal(edit_context, newprinc);
        enter_pwd_key(argv[0], argv[i], ks_tuple, n_ks_tuple, &entry);
	break;
    case 0:
    	com_err(argv[0], 0, "No principal '%s' exists", argv[i]);
    default:
        exit_status++;
	break;
    }

    if (ks_tuple) {
	free(ks_tuple);
    }
}

void add_new_key(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code 	  retval;
    krb5_principal 	  newprinc;
    krb5_db_entry	  entry;

    if (argc < 2) {
	com_err(argv[0], 0, "Too few arguments");
	com_err(argv[0], 0, "Usage: %s [<key_type[:<salt_type>]>] principal",
		argv[0]);
    	exit_status++;
	return;
    }
    switch (pre_key(argc, argv, &newprinc, &entry)) {
    case 0:
	if ((retval = create_db_entry(newprinc, &entry))) {
	    com_err(argv[0], retval, "While creating new db entry.");
	    exit_status++;
	    return;
	}
        enter_pwd_key(argv[0], argv[argc - 1], NULL, 0, &entry);
    	krb5_free_principal(edit_context, newprinc);
	return;
    case 1:
	com_err(argv[0], 0, "Principal '%s' already exists.", argv[argc - 1]);
        krb5_db_free_principal(edit_context, &entry, 1);
        krb5_free_principal(edit_context, newprinc);
    default:
    	exit_status++;
	break;
    }
}

