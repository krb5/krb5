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
#include "adm.h"

struct saltblock {
    int salttype;
    krb5_data saltdata;
};

static const krb5_key_salt_tuple	keysalts[] = {
{ ENCTYPE_DES_CBC_MD5, KRB5_KDB_SALTTYPE_NORMAL },
{ ENCTYPE_DES_CBC_CRC, KRB5_KDB_SALTTYPE_V4 }
};
static const krb5_int32			n_keysalts =
	sizeof(keysalts) / sizeof(keysalts[0]);

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
		   int, 
		   krb5_boolean, 
		   char *,
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
adm_modify_kdb(context, cmdname, newprinc, principal, req_type, is_rand,
	       pwd, entry)
    krb5_context context;
    char const * cmdname;
    char const * newprinc;
    krb5_const_principal principal;
    int req_type;
    krb5_boolean is_rand;
    char * pwd;
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
    } else { /* Modify existing entry */
#ifdef SANDIA
	entry->attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;
#endif
    }

    if (adm_update_tl_attrs(context, entry, master_princ, 1)) {
	krb5_free_principal(context, entry->princ);
	entry->princ = 0;
	return retval;
    }

    /*
     * Do the change or add password operation.
     */
    if (!is_rand) {
	retval = (req_type)
	    ? krb5_dbe_cpw(context,
			   &master_encblock,
			   (krb5_key_salt_tuple *) keysalts,
			   n_keysalts,
			   pwd,
			   entry)
		: krb5_dbe_apw(context,
			       &master_encblock,
			       (krb5_key_salt_tuple *) keysalts,
			       n_keysalts,
			       pwd,
			       entry);
    }
    else {
	retval = (req_type)
	    ? krb5_dbe_crk(context,
			   &master_encblock,
			   (krb5_key_salt_tuple *) keysalts,
			   n_keysalts,
			   entry)
		: krb5_dbe_ark(context,
			       &master_encblock,
			       (krb5_key_salt_tuple *) keysalts,
			       n_keysalts,
			       entry);
    }
    if (retval) {
	com_err("adm_modify_kdb", retval, 
		"updating keys for '%s'\n", newprinc);
	krb5_free_principal(context, entry->princ);
	entry->princ = (krb5_principal) NULL;
	return retval;
    }
    
    entry->len = KRB5_KDB_V1_BASE_LENGTH;
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
    retval = adm_modify_kdb(context, "adm_enter_pwd_key", 
			    newprinc, 
			    princ, 
			    req_type, 
			    0,
			    new_password,
			    entry);

    memset((char *) new_password, 0, strlen(new_password));
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
    char	*principal_name; 
     

    if (retval = krb5_unparse_name(context, change_princ, &principal_name))
	goto finish;
    
		/* Modify Database */
    retval = adm_modify_kdb(context, "adm_enter_rnd_pwd_key", 
			    principal_name, 
			    change_princ, 
			    req_type, 
			    1,
			    (char *) NULL,
			    entry);
    free(principal_name);
    
    if (retval) {
        com_err("adm_enter_rnd_pwd_key", 0, "Database Modification Failure");
	retval = 2;
        goto finish;
    }

    finish:

    return(retval);
}

krb5_error_code
adm_update_tl_attrs(kcontext, dbentp, mod_name, is_pwchg)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_principal	mod_name;
    krb5_boolean	is_pwchg;
{
    krb5_error_code	kret;

    kret = 0 ;

    /*
     * Handle modification principal.
     */
    if (mod_name) {
	krb5_tl_mod_princ	mprinc;

	memset(&mprinc, 0, sizeof(mprinc));
	if (!(kret = krb5_copy_principal(kcontext,
					 mod_name,
					 &mprinc.mod_princ)) &&
	    !(kret = krb5_timeofday(kcontext, &mprinc.mod_date)))
	    kret = krb5_dbe_encode_mod_princ_data(kcontext,
						  &mprinc,
						  dbentp);
	if (mprinc.mod_princ)
	    krb5_free_principal(kcontext, mprinc.mod_princ);
    }

    /*
     * Handle last password change.
     */
    if (!kret && is_pwchg) {
	krb5_tl_data	*pwchg;
	krb5_timestamp	now;
	krb5_boolean	linked;

	/* Find a previously existing entry */
	for (pwchg = dbentp->tl_data;
	     (pwchg) && (pwchg->tl_data_type != KRB5_TL_LAST_PWD_CHANGE);
	     pwchg = pwchg->tl_data_next);

	/* Check to see if we found one. */
	linked = 0;
	if (!pwchg) {
	    /* No, allocate a new one */
	    if (pwchg = (krb5_tl_data *) malloc(sizeof(krb5_tl_data))) {
		memset(pwchg, 0, sizeof(krb5_tl_data));
		if (!(pwchg->tl_data_contents =
		      (krb5_octet *) malloc(sizeof(krb5_timestamp)))) {
		    free(pwchg);
		    pwchg = (krb5_tl_data *) NULL;
		}
		else {
		    pwchg->tl_data_type = KRB5_TL_LAST_PWD_CHANGE;
		    pwchg->tl_data_length =
			(krb5_int16) sizeof(krb5_timestamp);
		}
	    }
	}
	else
	    linked = 1;

	/* Do we have an entry? */
	if (pwchg && pwchg->tl_data_contents) {
	    /* Yes, do the timestamp */
	    if (!(kret = krb5_timeofday(kcontext, &now))) {
		/* Encode it */
		krb5_kdb_encode_int32(now, pwchg->tl_data_contents);
		/* Link it in if necessary */
		if (!linked) {
		    pwchg->tl_data_next = dbentp->tl_data;
		    dbentp->tl_data = pwchg;
		    dbentp->n_tl_data++;
		}
	    }
	}
	else
	    kret = ENOMEM;
    }

    return(kret);
}

