/*
 * kadmin/server/adm_funcs.c
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
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 * 
 * Modify the Kerberos Database
 */

#include "com_err.h"
#include <sys/types.h>
 
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif

#include "k5-int.h"
#include "adm_err.h"
#include "adm_extern.h"

struct saltblock {
    int salttype;
    krb5_data saltdata;
};

extern krb5_encrypt_block master_encblock;
extern krb5_keyblock master_keyblock;

typedef unsigned char des_cblock[8];

krb5_error_code adm_get_rnd_key PROTOTYPE((char *,
			krb5_ticket *,
			krb5_authenticator *,
			krb5_principal,
			int,
			krb5_db_entry *));

static krb5_error_code adm_modify_kdb 
	PROTOTYPE((krb5_context,
		   char const *, 
		   char const *, 
		   krb5_const_principal,
		   const krb5_keyblock *,  
		   const krb5_keyblock *,
		   int, 
		   struct saltblock *,
		   struct saltblock *,
		   krb5_db_entry *));


krb5_kvno
adm_princ_exists(context, cmdname, principal, entry, nprincs)
    krb5_context context;
    char *cmdname;
    krb5_principal principal;
    krb5_db_entry *entry;
    int *nprincs;
{
    krb5_boolean more;
    krb5_error_code retval;

    if (retval = krb5_db_get_principal(context, principal, entry, 
				       nprincs, &more)) {
	com_err("adm_princ_exists", retval, 
		"while attempting to verify principal's existence");
	return(0);
    }

    if (! *nprincs) return(0);

    return(*nprincs);
}

static krb5_error_code
adm_modify_kdb(context, cmdname, newprinc, principal, key, alt_key, req_type,
               salt, altsalt, entry)
    krb5_context context;
    char const * cmdname;
    char const * newprinc;
    krb5_const_principal principal;
    const krb5_keyblock * key;
    const krb5_keyblock * alt_key;
    int req_type;
    struct saltblock * salt;
    struct saltblock * altsalt;
    krb5_db_entry * entry;
{
    krb5_error_code retval;
    int one = 1;

    krb5_kvno KDB5_VERSION_NUM = 1;
    extern krb5_flags NEW_ATTRIBUTES;

    if (!req_type) { /* New entry - initialize */
	memset((char *) entry, 0, sizeof(krb5_db_entry));
	retval = krb5_copy_principal(context, principal, &entry->princ);
	if (retval)
		return retval;
        entry->max_life = master_entry.max_life;
        entry->max_renewable_life = master_entry.max_renewable_life;
        entry->expiration = master_entry.expiration;
#ifdef	notdef
        entry->kvno = KDB5_VERSION_NUM;
        entry->mkvno = master_entry.mkvno;
	retval = krb5_copy_principal(context, master_princ, &entry->mod_name);
	if (retval) {
	    krb5_free_principal(context, entry->principal);
	    entry->principal = 0;
	    return retval;
	}
#endif	/* notdef */
    } else { /* Modify existing entry */
#ifdef SANDIA
	entry->attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;
#endif
#ifdef	notdef
	entry->kvno++;
	retval = krb5_copy_principal(context, principal, &entry->mod_name);
	if (retval)
		return retval;
#endif	/* notdef */
    }

#ifdef	notdef
    if (key && key->length) {
	retval = krb5_kdb_encrypt_key(context, &master_encblock,
				      key,
				      &entry->key);
	if (retval) {
	    com_err("adm_modify_kdb", retval, 
		    "while encrypting key for '%s'", newprinc);
	    return(KADM_NO_ENCRYPT);
	}
    }

    if (alt_key && alt_key->length) {
	retval = krb5_kdb_encrypt_key(context, &master_encblock,
				      alt_key,
				      &entry->alt_key);
	if (retval) {
	    if (entry->key.contents) {
		memset((char *) entry->key.contents, 0, entry->key.length);
		krb5_xfree(entry->key.contents);
		entry->key.contents = 0;
	    }
	    com_err("adm_modify_kdb", retval, 
		    "while encrypting alt_key for '%s'", newprinc);
	    return(KADM_NO_ENCRYPT);
	}
    }

    if (retval = krb5_timeofday(context, &entry->mod_date)) {
	com_err("adm_modify_kdb", retval, "while fetching date");
	if (entry->key.contents) {
	    memset((char *) entry->key.contents, 0, entry->key.length);
	    krb5_xfree(entry->key.contents);
	    entry->key.contents = 0;
	}
	if (entry->alt_key.contents) {
	    krb5_xfree(entry->alt_key.contents);
	    memset((char *) entry->alt_key.contents, 0, entry->alt_key.length);
	    entry->alt_key.contents = 0;
	}
	return(KRB_ERR_GENERIC);
    }

    if (!req_type) {
        if (salt->salttype == KRB5_KDB_SALTTYPE_V4) {
            entry->attributes = (KRB5_KDB_DISALLOW_DUP_SKEY | NEW_ATTRIBUTES)
#ifdef SANDIA
	      & ~KRB5_KDB_REQUIRES_PRE_AUTH & ~KRB5_KDB_REQUIRES_HW_AUTH
#endif
		;
        } else {
            entry->attributes = NEW_ATTRIBUTES;
        }
 
#ifdef SANDIA
        entry->last_pwd_change = entry->mod_date;
        entry->last_success = entry->mod_date;
        entry->fail_auth_count = 0;
#endif
	
	if (salt) {
	    entry->salt_type = salt->salttype;
	    entry->salt_length = salt->saltdata.length;
	    entry->salt = (krb5_octet *) salt->saltdata.data;
	} else {
	    entry->salt_type = KRB5_KDB_SALTTYPE_NORMAL;
	    entry->salt_length = 0;
	    entry->salt = 0;
	}
	
	/* Set up version 4 alt key and alt salt info.....*/
	if (altsalt) {
	    entry->alt_salt_type = altsalt->salttype;
	    entry->alt_salt_length = altsalt->saltdata.length;
	    entry->alt_salt = (krb5_octet *) altsalt->saltdata.data;
	} else {
	    entry->alt_salt_type = KRB5_KDB_SALTTYPE_NORMAL;
	    entry->alt_salt_length = 0;
	    entry->alt_salt = 0;
	}
    } else {
	if (retval = krb5_timeofday(context, &entry->last_pwd_change)) {
	    com_err("adm_modify_kdb", retval, "while fetching date");
	    if (entry->key.contents) {
		memset((char *) entry->key.contents, 0, entry->key.length);
		krb5_xfree(entry->key.contents);
		entry->key.contents = 0;
	    }
	    if (entry->alt_key.contents) {
		memset((char *) entry->alt_key.contents, 0,
		       entry->alt_key.length);
		krb5_xfree(entry->alt_key.contents);
		entry->alt_key.contents = 0;
	    }
	    return(5);
	}
    }
#endif	/* notdef */

    retval = krb5_db_put_principal(context, entry, &one);

    if (retval) {
	com_err("adm_modify_kdb", retval, 
		"while storing entry for '%s'\n", newprinc);
	return(kdb5_err_base + retval);
    }

    if (one != 1)
	com_err("adm_modify_kdb", 0, "entry not stored in database (unknown failure)");
    return(0);
}

krb5_error_code
adm_enter_pwd_key(context, cmdname, newprinc, princ, string_princ, req_type,
	          salttype, new_password, entry)
    krb5_context context;
    char * cmdname;
    char * newprinc;
    krb5_const_principal princ;
    krb5_const_principal string_princ;
    int req_type;
    int salttype;
    char * new_password;
    krb5_db_entry * entry;
{
    krb5_error_code retval;
    krb5_keyblock tempkey;
    krb5_data pwd;
    struct saltblock salt;
    struct saltblock altsalt;
    krb5_keyblock alttempkey;

    pwd.data = new_password;
    pwd.length = strlen((char *) new_password);

    salt.salttype = salttype;

    tempkey.contents = alttempkey.contents = 0;
    retval = KRB_ERR_GENERIC;

    switch (salttype) {
    case KRB5_KDB_SALTTYPE_NORMAL:
	if (retval = krb5_principal2salt(context,string_princ,&salt.saltdata)) {
	    com_err("adm_enter_pwd_key", retval,
		    "while converting principal to salt for '%s'", newprinc);
	    goto cleanup;
	}

	altsalt.salttype = KRB5_KDB_SALTTYPE_V4;
	altsalt.saltdata.data = 0;
	altsalt.saltdata.length = 0;
	break;

    case KRB5_KDB_SALTTYPE_V4:
	salt.saltdata.data = 0;
	salt.saltdata.length = 0;
        if (retval = krb5_principal2salt(context, string_princ, 
					 &altsalt.saltdata)) {
            com_err("adm_enter_pwd_key", retval,
                    "while converting principal to altsalt for '%s'", newprinc);
	    goto cleanup;
        }

	altsalt.salttype = KRB5_KDB_SALTTYPE_NORMAL;
	break;

    case KRB5_KDB_SALTTYPE_NOREALM:
	if (retval = krb5_principal2salt_norealm(context, string_princ,
						 &salt.saltdata)) {
	    com_err("adm_enter_pwd_key", retval,
		    "while converting principal to salt for '%s'", newprinc);
	    goto cleanup;
	}

	altsalt.salttype = KRB5_KDB_SALTTYPE_V4;
	altsalt.saltdata.data = 0;
	altsalt.saltdata.length = 0;
	break;

    case KRB5_KDB_SALTTYPE_ONLYREALM:
    {
	krb5_data *foo;
	if (retval = krb5_copy_data(context, 
				    krb5_princ_realm(context, string_princ),
				    &foo)) {
	    com_err("adm_enter_pwd_key", retval,
		    "while converting principal to salt for '%s'", newprinc);
	    goto cleanup;
	}

	salt.saltdata = *foo;
	krb5_xfree(foo);
	altsalt.salttype = KRB5_KDB_SALTTYPE_V4;
	altsalt.saltdata.data = 0;
	altsalt.saltdata.length = 0;
	break;
    }

    default:
	com_err("adm_enter_pwd_key", 0, 
		"Don't know how to enter salt type %d", salttype);
	goto cleanup;
    }

    if (retval = krb5_string_to_key(context, &master_encblock, 
				master_keyblock.keytype,
                                &tempkey,
                                &pwd,
                                &salt.saltdata)) {
	com_err("adm_enter_pwd_key", retval, 
		"while converting password to key for '%s'", newprinc);
	goto cleanup;
    }

    if (retval = krb5_string_to_key(context, &master_encblock, 
				master_keyblock.keytype,
                                &alttempkey,
                                &pwd,
                                &altsalt.saltdata)) {
	com_err("adm_enter_pwd_key", retval, 
		"while converting password to alt_key for '%s'", newprinc);
	goto cleanup;
    }

    memset((char *) new_password, 0, sizeof(new_password)); /* erase it */

    retval = adm_modify_kdb(context, "adm_enter_pwd_key", 
			newprinc, 
			princ, 
			&tempkey,
			&alttempkey, 
			req_type, 
			&salt, 
			&altsalt,
			entry);

cleanup:
    if (salt.saltdata.data)
	krb5_xfree(salt.saltdata.data);
    if (altsalt.saltdata.data)
	krb5_xfree(altsalt.saltdata.data);
    if (tempkey.contents) {
	memset((char *) tempkey.contents, 0, tempkey.length);
	krb5_xfree(tempkey.contents);
    }
    if (alttempkey.contents) {
	memset((char *) alttempkey.contents, 0, alttempkey.length);
	krb5_xfree(alttempkey.contents);
    }
    memset((char *) new_password, 0, pwd.length); /* erase password */
    return(retval);
}

krb5_error_code
adm5_change(context, auth_context, prog, newprinc)
    krb5_context context;
    krb5_auth_context auth_context;
    char *prog;
    krb5_principal newprinc;
{
    krb5_db_entry entry;
    int nprincs = 1;

    krb5_error_code retval;
    char *composite_name;
    char new_passwd[ADM_MAX_PW_LENGTH + 1];

    if (!(adm_princ_exists(context, "adm5_change", newprinc,
		&entry, &nprincs))) {
	com_err("adm5_change", 0, "No principal exists!");
	krb5_free_principal(context, newprinc);
	return(1);
    }

    memset((char *) new_passwd, 0, ADM_MAX_PW_LENGTH + 1);

		/* Negotiate for New Key */
    if (retval = adm_negotiate_key(context, auth_context, "adm5_change", 
				   new_passwd)) {
	krb5_db_free_principal(context, &entry, nprincs);
	krb5_free_principal(context, newprinc);
	return(1);
    }

    if (retval = krb5_unparse_name(context, newprinc, &composite_name)) {
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return retval;
    }

#ifdef	notdef
    if (entry.salt_type == KRB5_KDB_SALTTYPE_V4) {
	entry.salt_type = KRB5_KDB_SALTTYPE_NORMAL;
	entry.alt_salt_type = KRB5_KDB_SALTTYPE_V4;
	com_err("adm5_change", 0, "Converting v4user to v5user");
    }
#endif	/* notdef */
 
    retval = adm_enter_pwd_key(context, "adm5_change",              
                                composite_name,
                                newprinc,
                                newprinc,
                                1,	/* change */
                                KRB5_KDB_SALTTYPE_NORMAL,
                                new_passwd,
				&entry);
    (void) memset(new_passwd, 0, strlen(new_passwd));
    krb5_free_principal(context, newprinc);
    krb5_db_free_principal(context, &entry, nprincs);
    free(composite_name);
    return(retval);
}

#ifdef SANDIA
krb5_error_code
adm5_create_rnd(prog, change_princ, client_auth_data, client_creds)
char *prog;
krb5_principal change_princ;
krb5_authenticator *client_auth_data;
krb5_ticket *client_creds;
{
    krb5_db_entry entry;
    int nprincs = 1;

    krb5_error_code retval;

    if (!(adm_princ_exists("adm5_create_rnd", 
			change_princ,
			&entry, 
			&nprincs))) {
        com_err("adm5_create_rnd", 0, "No principal exists!");
        krb5_free_principal(change_princ);
        return(1);
    }   

    if (retval = adm_get_rnd_key("adm5_create_rnd", 
			client_creds, 
			client_auth_data, 
			change_princ, 
			1,	/* change */
			&entry)) {
	krb5_db_free_principal(&entry, nprincs);
        krb5_free_principal(change_princ);
        return(retval);
    }

    krb5_free_principal(change_princ);
    krb5_db_free_principal(&entry, nprincs);
    return(0);
}
#endif
#define MAXMSGSZ	255

krb5_error_code
adm_enter_rnd_pwd_key(context, cmdname, change_princ, req_type, entry)
    krb5_context context;
    char * cmdname;
    krb5_principal change_princ;
    int req_type;
    krb5_db_entry * entry;
{
    krb5_error_code retval;
    krb5_keyblock *tempkey;
    krb5_pointer master_random;
    int salttype = KRB5_KDB_SALTTYPE_NORMAL;
    struct saltblock salt;
    char	*principal_name; 
     
#ifdef	notdef
    salt.salttype = salttype;
    entry->salt_type = salttype;
#endif	/* notdef */

    if (retval = krb5_init_random_key(context, &master_encblock,
                                      &master_keyblock,
                                      &master_random)) {
        com_err("adm_enter_rnd_pwd_key", 0, "Unable to Initialize Random Key");
        (void) krb5_finish_key(context, &master_encblock);
        memset((char *)master_keyblock.contents, 0, master_keyblock.length);
        krb5_xfree(master_keyblock.contents);
        goto finish;
    }

	/* Get Random Key */
    if (retval = krb5_random_key(context, &master_encblock, 
				 master_random, 
				 &tempkey)) {
        com_err("adm_enter_rnd_pwd_key", 0, "Unable to Obtain Random Key");
        goto finish;
    }

	/* Tie the Random Key to the Principal */
    if (retval = krb5_principal2salt(context, change_princ, &salt.saltdata)) {
        com_err("adm_enter_rnd_pwd_key", 0, "Principal2salt Failure");
        goto finish;
    }

    if (retval = krb5_unparse_name(context, change_princ, &principal_name))
	goto finish;
    
		/* Modify Database */
    retval = adm_modify_kdb(context, "adm_enter_rnd_pwd_key", 
			    principal_name, 
			    change_princ, 
			    tempkey,
			    tempkey,
			    req_type, 
			    &salt, 
			    &salt,
			    entry);
    free(principal_name);
    
    if (retval) {
        com_err("adm_enter_rnd_pwd_key", 0, "Database Modification Failure");
	retval = 2;
        goto finish;
    }

    finish:

    if (tempkey->contents) {
	memset((char *) tempkey->contents, 0, tempkey->length);
	krb5_free_keyblock(context, tempkey);
    }

    return(retval);
}
