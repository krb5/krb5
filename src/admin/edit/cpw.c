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
 * XXX Ick, ick, ick.  These global variables shouldn't be global....
 */
/*
static char search_name[40];
static int num_name_tokens;
static char search_instance[40];
static int num_instance_tokens;
static int must_be_first[2];
static char *mkey_password = 0;
static char *stash_file = (char *) NULL;
*/

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
extern krb5_pointer master_random;
extern int	valid_master_key;

extern char *krb5_default_pwd_prompt1, *krb5_default_pwd_prompt2;

extern char *progname;
extern char *cur_realm;
extern char *mkey_name;
extern krb5_boolean manual_mkey;
extern krb5_boolean dbactive;

/*
 * This is the guts of add_rnd_key() and change_rnd_key()
 */
void
enter_rnd_key(argc, argv, change)
    int			  argc;
    char	       ** argv;
    int			  change;
{
    krb5_error_code 	  retval;
    krb5_keyblock 	* tempkey;
    krb5_principal 	  newprinc;
    krb5_key_data 	* key_data;
    krb5_db_entry 	  entry;
    krb5_boolean 	  more;
    int 		  nprincs = 1;
    int			  vno;

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
	if (retval = create_db_entry(newprinc, &entry)) {
	    com_err(argv[0], retval, "While creating new db entry.");
	    exit_status++;
	    goto errout;
	}
	if (retval = krb5_dbe_create_key_data(edit_context, &entry)) {
	    com_err(argv[0], retval, "While creating key_data for db_entry.");
	    exit_status++;
	    goto errout;
	}
	nprincs = 1;
	vno = 1;
    } else {
	vno = entry.key_data[0].key_data_kvno++;
    }
    /* For now we only set the first key_data */
    key_data = entry.key_data;
    
    if (retval = krb5_random_key(edit_context, &master_encblock, 
				 master_random, &tempkey)) {
	com_err(argv[0], retval, "while generating random key");
	exit_status++;
	return;
    }

    /* Encoding over an old key_data will free old key contents */
    retval = krb5_dbekd_encrypt_key_data(edit_context, &master_encblock, 
				         tempkey, NULL, vno, key_data);
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

krb5_key_salt_tuple ks_tuple_default = { KEYTYPE_DES, 0 };
void change_pwd_key(argc, argv)
    int argc;
    char *argv[];
{
    krb5_key_salt_tuple	* ks_tuple = NULL;
    krb5_db_entry	  db_entry;
    krb5_error_code 	  retval;
    krb5_principal 	  princ;
    krb5_boolean	  more;
    krb5_kvno 		  vno;
    int			  one;
    int			  i;

    char password[KRB5_ADM_MAX_PASSWORD_LEN];
    int pwsize = KRB5_ADM_MAX_PASSWORD_LEN;
  
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

    if (argc < 2) {
	com_err(argv[0], 0, "Usage: % [-<key_type[:<salt_type>]> principal",
		argv[0]);
	exit_status++;
	return;
    }

    for (i = 1; i < (argc - 1); i++) {
        char * salt_type_name;

	if (!ks_tuple) {
	    ks_tuple = (krb5_key_salt_tuple *)malloc(
		sizeof(krb5_key_salt_tuple));
	} else {
	    ks_tuple = (krb5_key_salt_tuple *)realloc(ks_tuple,
	      sizeof(krb5_key_salt_tuple) * i);
	}
	if (!ks_tuple) {
	    com_err(argv[0], 0, "Insufficient memory to proceed");
	    exit_status++;
	    return;
	}

	while (salt_type_name = strchr(argv[i], ':')) {
	    *salt_type_name++ = '\0';
            if (!strcmp(salt_type_name, "v4")) {
		ks_tuple[i - 1].ks_salttype = KRB5_KDB_SALTTYPE_V4;
		break;
	    }
            if (!strcmp(salt_type_name, "normal")) {
		ks_tuple[i - 1].ks_salttype = KRB5_KDB_SALTTYPE_NORMAL;
		break;
	    }
            if (!strcmp(salt_type_name, "norealm")) {
		ks_tuple[i - 1].ks_salttype = KRB5_KDB_SALTTYPE_NOREALM;
		break;
	    }
            if (!strcmp(salt_type_name, "onlyrealm")) {
		ks_tuple[i - 1].ks_salttype = KRB5_KDB_SALTTYPE_ONLYREALM;
		break;
	    }
	    com_err(argv[0], 0, "Unknown salt type %s", salt_type_name);
	    exit_status++;
	    return;
	}
	    
        if (!strcmp(argv[i], "des")) {
	    ks_tuple[i - 1].ks_keytype = KRB5_KDB_SALTTYPE_ONLYREALM;
	    continue;
	}
	com_err(argv[0], 0, "Unknown key type %s", argv[i]);
	goto change_pwd_key_error;
    }

    if (retval = krb5_parse_name(edit_context, argv[i], &princ)) {
	com_err(argv[0], retval, "while parsing '%s'", argv[i]);
	goto change_pwd_key_error;
    }
    if ((retval = krb5_db_get_principal(edit_context, princ, &db_entry,
				        &one, &more)) || (!one) || (more)) {
	com_err(argv[0], 0, "No principal '%s' exists!", argv[i]);
        krb5_free_principal(edit_context, princ);
	goto change_pwd_key_error;
    }

   /* Done with principal */ 
    krb5_free_principal(edit_context, princ);

    if (retval = krb5_read_password(edit_context, krb5_default_pwd_prompt1,
				    krb5_default_pwd_prompt2,
				    password, &pwsize)) {
        com_err(argv[0], retval, "while reading password for '%s'", argv[i]);
	goto change_pwd_key_error;
    }
    
    if (retval = krb5_dbe_cpw(edit_context, &master_encblock, &db_entry,
			      ks_tuple ? ks_tuple : &ks_tuple_default,
			      i, password)) {
	com_err(argv[0], retval, "while storing entry for '%s'\n", argv[i]);
	krb5_dbe_free_contents(edit_context, &db_entry);
	goto change_pwd_key_error;
    }

    /* Write the entry back out and we're done */
    if (retval = krb5_db_put_principal(edit_context, &db_entry, &one)) {
	com_err(argv[0], retval, "while storing entry for '%s'\n", argv[i]);
    }

change_pwd_key_error:;
    krb5_xfree(ks_tuple);
    if (retval)
        exit_status++;
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
    if ((vno = princ_exists(argv[0], newprinc)) == 0) {
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
    krb5_keysalt salt;
    krb5_data pwd;

    if (retval = krb5_read_password(edit_context, krb5_default_pwd_prompt1,
				    krb5_default_pwd_prompt2,
				    password, &pwsize)) {
	com_err(cmdname, retval, "while reading password for '%s'", newprinc);
	exit_status++;
	return;
    }
    pwd.data = password;
    pwd.length = pwsize;

    switch (salt.type = salttype) {
    case KRB5_KDB_SALTTYPE_NORMAL:
	if (retval = krb5_principal2salt(edit_context,string_princ,&salt.data)){
	    com_err(cmdname, retval,
		    "while converting principal to salt for '%s'", newprinc);
	    exit_status++;
	    return;
	}
	break;
    case KRB5_KDB_SALTTYPE_V4:
	salt.data.length = 0;
	salt.data.data = 0;
	break;
    case KRB5_KDB_SALTTYPE_NOREALM: 
	if (retval = krb5_principal2salt_norealm(edit_context, string_princ,
						 &salt.data)) {
	    com_err(cmdname, retval,
		    "while converting principal to salt for '%s'", newprinc);
	    exit_status++;
	    return;
	}
	break;
    case KRB5_KDB_SALTTYPE_ONLYREALM: {
	krb5_data * saltdata;
	if (retval = krb5_copy_data(edit_context, 
				    krb5_princ_realm(edit_context,string_princ),
				    &saltdata)) {
	    com_err(cmdname, retval,
		    "while converting principal to salt for '%s'", newprinc);
	    exit_status++;
	    return;
	}
	salt.data = *saltdata;
	krb5_xfree(saltdata);
	break;
    }
    default:
	com_err(cmdname, 0, "Don't know how to enter salt type %d", salttype);
	exit_status++;
	return;
    }
    retval = krb5_string_to_key(edit_context, &master_encblock, 
				master_keyblock.keytype, &tempkey, 
				&pwd, &salt.data);
    memset(password, 0, sizeof(password)); /* erase it */
    if (retval) {
	com_err(cmdname, retval, "while converting password to key for '%s'",
		newprinc);
	if (salt.data.data) 
	    krb5_xfree(salt.data.data);
	exit_status++;
	return;
    }
    add_key(cmdname, newprinc, princ, &tempkey, ++vno,
	    (salttype == KRB5_KDB_SALTTYPE_NORMAL) ? NULL : &salt);
    memset((char *)tempkey.contents, 0, tempkey.length);
    if (salt.data.data) 
	krb5_xfree(salt.data.data);
    krb5_xfree(tempkey.contents);
    return;
}

