/*
 * kadmin/v5server/passwd.c
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
 */

/*
 * passwd.c - handle server password-related functions.
 */

#include "k5-int.h"
#include "com_err.h"
#include "kadm5_defs.h"
#include "adm.h"

/*
 * These defines turn on various checking in passwd_check_npass_ok.
 */
#define	KPWD_CHECK_LENGTH	1
#define	KPWD_CHECK_WEAKNESS	1

#define	KPWD_MIN_PWD_LENGTH	8

extern char *programname;
static const char *pwd_bad_old_pwd = "\004incorrect old password for %s";
static const char *pwd_perm_denied = "\004ACL entry prevents password change for %s";
static const char *pwd_changed_pwd = "\007changed password for %s";

/*
 * passwd_check_princ()	- Check if the principal specified in the ticket is ok
 */
static krb5_error_code
passwd_check_princ(kcontext, debug_level, ticket,
		   princp, namep, db_entp, db_numentp, db_morep)
    krb5_context	kcontext;
    int			debug_level;
    krb5_ticket		*ticket;
    krb5_principal	*princp;
    char		**namep;
    krb5_db_entry	*db_entp;
    int			*db_numentp;
    krb5_boolean	*db_morep;
{
    krb5_error_code	kret;

    DPRINT(DEBUG_CALLS, debug_level, ("* passwd_check_princ()\n"));
    *princp = (krb5_principal) NULL;
    *namep = (char *) NULL;

    /* Copy principal out of ticket */
    if (kret = krb5_copy_principal(kcontext,
				   ticket->enc_part2->client,
				   princp))
	goto cleanup;

    /* Flatten name */
    if (kret = krb5_unparse_name(kcontext, *princp, namep))
	goto cleanup;

    /* Get database entry */
    if (kret = krb5_db_get_principal(kcontext,
				     *princp,
				     db_entp,
				     db_numentp,
				     db_morep))
	goto cleanup;

    if (*db_numentp == 0)
	kret = KRB5_KDB_NOENTRY;

 cleanup:
    if (kret) {
	if (*namep) {
	    krb5_xfree(*namep);
	    *namep = (char *) NULL;
	}
	if (*princp) {
	    krb5_free_principal(kcontext, *princp);
	    *princp = (krb5_principal) NULL;
	}
    }

    DPRINT(DEBUG_CALLS, debug_level, ("X passwd_check_princ() = %d\n", kret));
    return(kret);
}

/*
 * passwd_check_opass_ok()	- Check of specified old password is good.
 */
krb5_boolean
passwd_check_opass_ok(kcontext, debug_level, princ, dbentp, pwdata)
    krb5_context	kcontext;
    int			debug_level;
    krb5_principal	princ;
    krb5_db_entry	*dbentp;
    krb5_data		*pwdata;
{
    krb5_boolean	pwret;
    krb5_int32		num_keys, num_dkeys;
    krb5_key_data	*key_list, *dkey_list, *kent, *tmp;
    krb5_key_salt_tuple	keysalt;
    krb5_error_code	kret;
    int			i;

    DPRINT(DEBUG_CALLS, debug_level, ("* passwd_check_opass_ok()\n"));
    pwret = 1;

    /* Initialize */
    num_keys = num_dkeys = 0;
    key_list = dkey_list = (krb5_key_data *) NULL;

    /* Make key(s) using alleged old password */
    kret = key_string_to_keys(kcontext,
			      dbentp,
			      pwdata,
			      0,
			      (krb5_key_salt_tuple *) NULL,
			      &num_keys,
			      &key_list);

    /* Now decrypt database entries */
    num_dkeys = dbentp->n_key_data;
    if (!kret)
	kret = key_decrypt_keys(kcontext,
				dbentp,
				&num_dkeys,
				dbentp->key_data,
				&dkey_list);
    if (kret)
	goto cleanup;

    /*
     * Compare decrypted keys.  If they differ, then we're wrong!
     */
    tmp = dbentp->key_data;
    dbentp->key_data = dkey_list;
    for (i=0; i<num_keys; i++) {
	keysalt.ks_keytype = (krb5_keytype) key_list[i].key_data_type[0];
	keysalt.ks_salttype = (krb5_int32) key_list[i].key_data_type[1];
	if (!key_name_to_data(dbentp, &keysalt, -1, &kent)) {
	    if ((key_list[i].key_data_length[0] != kent->key_data_length[0]) ||
		memcmp(key_list[i].key_data_contents[0],
		       kent->key_data_contents[0],
		       kent->key_data_length[0])) {
		pwret = 0;
		break;
	    }
	}
    }
    dbentp->key_data = tmp;

 cleanup:
    if (kret)
	pwret = 0;
    if (num_keys && key_list)
	key_free_key_data(key_list, num_keys);
    if (num_dkeys && dkey_list)
	key_free_key_data(dkey_list, num_dkeys);
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X passwd_check_opass_ok() = %d\n", pwret));
    return(pwret);
}

/*
 * passwd_set_npass()	- Set new password
 */
static krb5_error_code
passwd_set_npass(kcontext, debug_level, princ, dbentp, pwdata)
    krb5_context	kcontext;
    int			debug_level;
    krb5_principal	princ;
    krb5_db_entry	*dbentp;
    krb5_data		*pwdata;
{
    krb5_error_code	kret;
    krb5_db_entry	entry2write;
    krb5_int32		num_keys;
    krb5_key_data	*key_list;
    krb5_tl_data	*pwchg;
    krb5_tl_mod_princ	modent;
    int			nwrite;
    krb5_timestamp	now;

    DPRINT(DEBUG_CALLS, debug_level, ("* passwd_set_npass()\n"));

    /* Initialize */
    num_keys = 0;
    key_list = (krb5_key_data *) NULL;

    /* Make key(s) using the new password */
    if (kret = key_string_to_keys(kcontext,
				  dbentp,
				  pwdata,
				  0,
				  (krb5_key_salt_tuple *) NULL,
				  &num_keys,
				  &key_list))
	goto cleanup;

    /* Copy our database entry */
    memcpy((char *) &entry2write, (char *) dbentp, sizeof(krb5_db_entry));

    /*
     * Zap stuff which we're not going to use.
     *
     * We're going to recreate the whole tl_data and key_data structures,
     * so blast what we copied from above.
     */
    entry2write.tl_data = (krb5_tl_data *) NULL;
    entry2write.n_tl_data = 0;
    entry2write.key_data = (krb5_key_data *) NULL;
    entry2write.n_key_data = 0;

    /* Encrypt the new keys to the database entry. */
    if (kret = key_encrypt_keys(kcontext,
				&entry2write,
				&num_keys,
				key_list,
				&entry2write.key_data))
	goto cleanup;
    entry2write.n_key_data = num_keys;

    if ((pwchg = (krb5_tl_data *) malloc(sizeof(krb5_tl_data))) &&
	(pwchg->tl_data_contents = (krb5_octet *)
	 malloc(sizeof(krb5_timestamp)))) {

	pwchg->tl_data_type = KRB5_TL_LAST_PWD_CHANGE;
	pwchg->tl_data_length = sizeof(krb5_timestamp);
	pwchg->tl_data_next = (krb5_tl_data *) NULL;
	entry2write.tl_data = pwchg;
	entry2write.n_tl_data++;
	/* Set the time for last successful password change */
	if (kret = krb5_timeofday(kcontext, &now))
	    goto cleanup;
	krb5_kdb_encode_int32(now, pwchg->tl_data_contents);
    }
    else {
	kret = ENOMEM;
	goto cleanup;
    }


    /* Set entry modifier and modification time. */
    modent.mod_date = now;
    if (!(kret = krb5_copy_principal(kcontext,
				     entry2write.princ, 
				     &modent.mod_princ))) {
	kret = krb5_dbe_encode_mod_princ_data(kcontext, &modent, &entry2write);
	krb5_free_principal(kcontext, modent.mod_princ);
    }

    /* Now write the entry */
    nwrite = 1;
    if (kret = krb5_db_put_principal(kcontext, &entry2write, &nwrite))
	goto cleanup;

    if (nwrite != 1)
	kret = KRB5KRB_ERR_GENERIC;

    (void) krb5_db_free_principal(kcontext, &entry2write, 1);

 cleanup:
    if (num_keys && key_list)
	key_free_key_data(key_list, num_keys);
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X passwd_set_npass() = %d\n", kret));
    return(kret);
}

/*
 * passwd_check()	- Check if a password is ok.
 */
krb5_int32
passwd_check(kcontext, debug_level, auth_context, ticket, pwdata, supp)
    krb5_context	kcontext;
    int			debug_level;
    krb5_auth_context	auth_context;
    krb5_ticket		*ticket;
    krb5_data		*pwdata;
    krb5_int32		*supp;
{
    krb5_int32		pwret;
    krb5_error_code	kret;
    krb5_principal	client;
    char		*canon_name;
    krb5_db_entry	tmp_entry;
    int			tmp_nents;
    krb5_boolean	tmp_more;

    DPRINT(DEBUG_CALLS, debug_level, ("* passwd_check()\n"));
    pwret = KRB5_ADM_SUCCESS;
    client = (krb5_principal) NULL;
    canon_name = (char *) NULL;

    /*
     * Check out our principal
     */
    tmp_nents = 1;
    if (kret = passwd_check_princ(kcontext,
				  debug_level,
				  ticket,
				  &client,
				  &canon_name,
				  &tmp_entry,
				  &tmp_nents,
				  &tmp_more)) {
	*supp = KADM_BAD_PRINC;
	goto cleanup;
    }

    DPRINT(DEBUG_REQUESTS, debug_level,
	   ("> Checking password for client \"%s\"\n", canon_name));

    /*
     * And check out our password.
     */
    if (!passwd_check_npass_ok(kcontext,
			       debug_level,
			       client,
			       &tmp_entry,
			       pwdata,
			       supp))
	pwret = KRB5_ADM_PW_UNACCEPT;

 cleanup:
    if (kret) {
	pwret = KRB5_ADM_PW_UNACCEPT;
    }
    if (tmp_nents > 0)
	krb5_db_free_principal(kcontext, &tmp_entry, tmp_nents);
    if (canon_name)
	krb5_xfree(canon_name);
    if (client)
	krb5_free_principal(kcontext, client);

 done:
    DPRINT(DEBUG_CALLS, debug_level, ("X passwd_check() = %d\n", pwret));
    return(pwret);
}

/*
 * passwd_change()	- Change a password.
 */
krb5_int32
passwd_change(kcontext, debug_level, auth_context, ticket,
	      olddata, newdata, supp)
    krb5_context	kcontext;
    int			debug_level;
    krb5_auth_context	auth_context;
    krb5_ticket		*ticket;
    krb5_data		*olddata;
    krb5_data		*newdata;
    krb5_int32		*supp;
{
    krb5_int32		pwret;
    krb5_error_code	kret;
    krb5_principal	client;
    char		*canon_name;
    krb5_db_entry	tmp_entry;
    int			tmp_nents;
    krb5_boolean	tmp_more;

    DPRINT(DEBUG_CALLS, debug_level, ("* passwd_change()\n"));
    pwret = KRB5_ADM_SUCCESS;
    client = (krb5_principal) NULL;
    canon_name = (char *) NULL;

    /* Make sure the ticket is initial, otherwise don't trust it */
    if ((ticket->enc_part2->flags & TKT_FLG_INITIAL) == 0) {
	pwret = KRB5_ADM_NOT_IN_TKT;
	goto done;
    }

    /*
     * Check out our principal
     */
    tmp_nents = 1;
    if (kret = passwd_check_princ(kcontext,
				  debug_level,
				  ticket,
				  &client,
				  &canon_name,
				  &tmp_entry,
				  &tmp_nents,
				  &tmp_more)) {
	*supp = KADM_BAD_PRINC;
	goto cleanup;
    }

    /*
     * Check if we're restricted by an ACL from changing our own password.
     */
    if (!acl_op_permitted(kcontext, client, ACL_CHANGE_OWN_PW)) {
	com_err(programname, 0, pwd_perm_denied, canon_name);
	pwret = KRB5_ADM_CANT_CHANGE;
	*supp = KADM_NOT_ALLOWED;
	goto cleanup;
    }

    DPRINT(DEBUG_REQUESTS, debug_level,
	   ("> Changing password for client \"%s\"\n", canon_name));

    /*
     * Check out our old password.
     */
    if (!passwd_check_opass_ok(kcontext,
			       debug_level,
			       client,
			       &tmp_entry,
			       olddata)) {
	com_err(programname, 0, pwd_bad_old_pwd, canon_name);
	pwret = KRB5_ADM_BAD_PW;
	goto cleanup;
    }

    /*
     * Check out the new password.
     */
    if (!passwd_check_npass_ok(kcontext,
			       debug_level,
			       client,
			       &tmp_entry,
			       newdata,
			       supp)) {
	pwret = KRB5_ADM_PW_UNACCEPT;
	goto cleanup;
    }

    /* Now set the new entry */
    kret = passwd_set_npass(kcontext,
			    debug_level,
			    client,
			    &tmp_entry,
			    newdata);
    if (!kret) {
	com_err(programname, 0, pwd_changed_pwd, canon_name);
    }

 cleanup:
    if (kret) {
	pwret = KRB5_ADM_CANT_CHANGE;
    }
    if (tmp_nents > 0)
	krb5_db_free_principal(kcontext, &tmp_entry, tmp_nents);
    if (canon_name)
	krb5_xfree(canon_name);
    if (client)
	krb5_free_principal(kcontext, client);

 done:
    DPRINT(DEBUG_CALLS, debug_level, ("X passwd_change() = %d\n", pwret));
    return(pwret);
}

/*
 * passwd_check_npass_ok()	- Check if new password is ok.
 */
krb5_boolean
passwd_check_npass_ok(kcontext, debug_level, princ, dbentp, pwdata, supp)
    krb5_context	kcontext;
    int			debug_level;
    krb5_principal	princ;
    krb5_db_entry	*dbentp;
    krb5_data		*pwdata;
    krb5_int32		*supp;
{
    krb5_boolean	pwret;

    DPRINT(DEBUG_CALLS, debug_level, ("* passwd_check_npass_ok()\n"));
    pwret = 1;

    /*
     * Check whether a new password is good.
     */
#if	KPWD_CHECK_LENGTH
    /* Check length */
    if (pwdata->length < KPWD_MIN_PWD_LENGTH) {
	pwret = 0;
	*supp = KADM_PWD_TOO_SHORT;
	DPRINT(DEBUG_CALLS, debug_level,
	       ("* passwd_check_npass_ok() - TOO SHORT\n"));
    }
#endif	/* KPWD_CHECK_LENGTH */

#if	KPWD_CHECK_WEAKNESS
    /* Check weakness of keys generated by password */
    if (key_pwd_is_weak(kcontext,
			dbentp,
			pwdata)) {
	pwret = 0;
	*supp = KADM_PWD_WEAK;
	DPRINT(DEBUG_CALLS, debug_level,
	       ("* passwd_check_npass_ok() - WEAK\n"));
    }
#endif	/* KPWD_CHECK_WEAKNESS */

    DPRINT(DEBUG_CALLS, debug_level,
	   ("X passwd_check_npass_ok() = %d\n", pwret));
    return(pwret);
}
