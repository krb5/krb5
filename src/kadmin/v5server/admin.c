/*
 * kadmin/v5server/admin.c
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
 * admin.c	- Handle administrative requests.
 */

#include "k5-int.h"
#include "kadm5_defs.h"
#include "adm.h"
#include "adm_proto.h"

/*
 * Data structure used to pass information in and out of krb5_db_iterate.
 */
struct inq_context {
    krb5_context	ic_context;	/* in */
    int			ic_level;	/* in */
    krb5_principal	ic_who;		/* in */
    krb5_boolean	ic_entry_found;	/* out */
    krb5_int32		*ic_ncomps;	/* out */
    krb5_data		**ic_clist;	/* out */
    char		*ic_next;	/* out */
};

static krb5_db_entry admin_def_dbent;

static const char *admin_perm_denied_fmt = "\004ACL entry prevents %s operation on %s by %s";
static const char *admin_db_write_err_fmt = "\004database write failed during %s operation by %s";
static const char *admin_db_success_fmt = "\007%s operation for %s successfully issued by %s";
static const char *admin_db_read_err_fmt = "\004database read failed during %s operation by %s";
static const char *admin_no_cl_ident_fmt = "\004cannot get client identity from ticket for %s operation";
static const char *admin_db_rename_fmt = "\007%s operation from %s to %s successfully issued by %s";
static const char *admin_db_key_op_fmt = "\007%s operation for %s successfully issued by %s";
static const char *admin_db_del_err_fmt = "\004database delete entry(%s) failed during %s operation by %s";
static const char *admin_key_dec_err_fmt = "\004key decode failed for %s's key during %s operation by %s";

static const char *admin_add_principal_text = "Add Principal";
static const char *admin_modify_principal_text = "Modify Principal";
static const char *admin_delete_principal_text = "Delete Principal";
static const char *admin_rename_principal_text = "Rename Principal";
static const char *admin_change_pwd_text = "Change Password";
static const char *admin_change_rpwd_text = "Change Random Password";
static const char *admin_inquire_text = "Inquire";
static const char *admin_extract_key_text = "Extract Key";
static const char *admin_add_key_text = "Add Keytype";
static const char *admin_delete_key_text = "Delete Keytype";

static const char *admin_fentry_text = "first entry";

extern char *programname;

/*
 * admin_init_def_dbent()	- Initialize the default database entry.
 */
static void
admin_init_def_dbent(mlife, mrlife, evalid, e, fvalid, f)
    krb5_deltat		mlife;
    krb5_deltat		mrlife;
    krb5_boolean	evalid;
    krb5_timestamp	e;
    krb5_boolean	fvalid;
    krb5_flags		f;
{
    /* Zero it all out, and fill in non-zero defaults */
    memset((char *) &admin_def_dbent, 0, sizeof(admin_def_dbent));
    admin_def_dbent.max_life = (mlife > 0) ? mlife : KRB5_KDB_MAX_LIFE;
    admin_def_dbent.max_renewable_life = 
	(mrlife > 0) ? mrlife : KRB5_KDB_MAX_RLIFE;
    admin_def_dbent.expiration = (evalid) ? e : KRB5_KDB_EXPIRATION;
    admin_def_dbent.attributes = (fvalid) ? f : KRB5_KDB_DEF_FLAGS;
    admin_def_dbent.len = KRB5_KDB_V1_BASE_LENGTH;
}

/*
 * admin_client_identity()	- Determine client identity from ticket
 */
static krb5_error_code
admin_client_identity(kcontext, debug_level, ticket, clientp, clnamep)
    krb5_context	kcontext;
    int			debug_level;
    krb5_ticket		*ticket;
    krb5_principal	*clientp;
    char		**clnamep;
{
    krb5_error_code	kret = 0;

    DPRINT(DEBUG_CALLS, debug_level, ("* admin_client_identity()\n"));
    *clientp = (krb5_principal) NULL;
    *clnamep = (char *) NULL;

    /* Copy principal out of ticket */
    if (!(kret = krb5_copy_principal(kcontext,
				     ticket->enc_part2->client,
				     clientp))) {
	/* Flatten name */
	if (kret = krb5_unparse_name(kcontext, *clientp, clnamep)) {
	    krb5_free_principal(kcontext, *clientp);
	    *clientp = (krb5_principal) NULL;
	}
    }

    DPRINT(DEBUG_CALLS, debug_level, ("X admin_client_identity()=%d\n", kret));
    return(kret);
}

/*
 * admin_merge_keys()	- Merge two keylists.
 *
 * Fold "in1" into "in2" and put the results in "outp"
 */
static krb5_error_code
admin_merge_keys(kcontext, dbentp, unique,
		 nkeys1, in1, nkeys2, in2, nkeysout, outp)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_boolean	unique;
    krb5_int32		nkeys1;
    krb5_key_data	*in1;
    krb5_int32		nkeys2;
    krb5_key_data	*in2;
    krb5_int32		*nkeysout;
    krb5_key_data	**outp;
{
    krb5_error_code	kret;
    int			i;
    krb5_int32		numout;
    krb5_key_salt_tuple	*kslist;
    krb5_int32		nksents;
    krb5_key_data	*keylist;
    krb5_db_entry	xxx1,xxx2;
    krb5_key_data	*kp1, *kp2;

    keylist = (krb5_key_data *) NULL;
    kret = 0;
    numout = 0;
    if ((keylist = (krb5_key_data *) malloc(sizeof(krb5_key_data) *
					    (nkeys1+nkeys2)))) {
	memset(keylist, 0, sizeof(krb5_key_data) * (nkeys1+nkeys2));
	if (!unique) {
	    /* The easy case */
	    /*
	     * Start with "in1" - it's newer.
	     */
	    for (i=0; i<nkeys1; i++) {
		if ((keylist[numout].key_data_contents[0] = 
		     (krb5_octet *) malloc(in1[i].key_data_length[0])) &&
		     (!in1[i].key_data_length[1] ||
		      (keylist[numout].key_data_contents[1] = 
		       (krb5_octet *) malloc(in1[i].key_data_length[1])))) {
		    keylist[numout].key_data_ver = in1[i].key_data_ver;
		    keylist[numout].key_data_kvno = in1[i].key_data_kvno;
		    keylist[numout].key_data_type[0] = in1[i].key_data_type[0];
		    keylist[numout].key_data_type[1] = in1[i].key_data_type[1];
		    if (keylist[numout].key_data_length[0] =
			in1[i].key_data_length[0])
			memcpy(keylist[numout].key_data_contents[0],
			       in1[i].key_data_contents[0],
			       in1[i].key_data_length[0]);
		    if (keylist[numout].key_data_length[1] =
			in1[i].key_data_length[1])
			memcpy(keylist[numout].key_data_contents[1],
			       in1[i].key_data_contents[1],
			       in1[i].key_data_length[1]);
		    numout++;
		}
	    }
	    /*
	     * Now put "in2"
	     */
	    for (i=0; i<nkeys2; i++) {
		if ((keylist[numout].key_data_contents[0] = 
		     (krb5_octet *) malloc(in2[i].key_data_length[0])) &&
		     (!in2[i].key_data_length[1] ||
		      (keylist[numout].key_data_contents[1] = 
		       (krb5_octet *) malloc(in2[i].key_data_length[1])))) {
		    keylist[numout].key_data_ver = in2[i].key_data_ver;
		    keylist[numout].key_data_kvno = in2[i].key_data_kvno;
		    keylist[numout].key_data_type[0] = in2[i].key_data_type[0];
		    keylist[numout].key_data_type[1] = in2[i].key_data_type[1];
		    if (keylist[numout].key_data_length[0] =
			in2[i].key_data_length[0])
			memcpy(keylist[numout].key_data_contents[0],
			       in2[i].key_data_contents[0],
			       in2[i].key_data_length[0]);
		    if (keylist[numout].key_data_length[1] =
			in2[i].key_data_length[1])
			memcpy(keylist[numout].key_data_contents[1],
			       in2[i].key_data_contents[1],
			       in2[i].key_data_length[1]);
		    numout++;
		}
	    }
	}
	else {
	    /* Generate a unique list */
	    memset(&xxx1, 0, sizeof(krb5_db_entry));
	    memcpy(keylist, in2, sizeof(krb5_key_data) * nkeys2);
	    memcpy(&keylist[nkeys2], in1, sizeof(krb5_key_data) * nkeys1);
	    xxx1.n_key_data = (krb5_int16) (nkeys1+nkeys2);
	    xxx1.key_data = keylist;
	    numout = 0;
	    if (!key_dbent_to_keysalts(&xxx1, &nksents, &kslist)) {
		memset(&xxx1, 0, sizeof(krb5_db_entry));
		memset(&xxx2, 0, sizeof(krb5_db_entry));
		memset(keylist, 0, sizeof(krb5_key_data) * (nkeys1+nkeys2));
		xxx1.n_key_data = nkeys1;
		xxx1.key_data = in1;
		xxx2.n_key_data = nkeys2;
		xxx2.key_data = in2;
		for (i=0; i<nksents; i++) {
		    kp1 = 0; kp2 = 0;
		    (void) krb5_dbe_find_enctype(kcontext,
						 &xxx1,
						 kslist[i].ks_enctype,
						 kslist[i].ks_salttype,
						 -1,
						 &kp1);
		    (void) krb5_dbe_find_enctype(kcontext,
						 &xxx2,
						 kslist[i].ks_enctype,
						 kslist[i].ks_salttype,
						 -1,
						 &kp2);
		    if (kp1 && kp2) {
			if (kp2->key_data_kvno > kp1->key_data_kvno)
			    kp1 = kp2;
		    }
		    else {
			if (!kp1)
			    kp1 = kp2;
			if (!kp1) {
			    kret = KRB5KRB_ERR_GENERIC;
			    break;
			}
		    }
		    if ((keylist[numout].key_data_contents[0] = 
			 (krb5_octet *) malloc(kp1->key_data_length[0])) &&
			(!kp1->key_data_length[1] ||
			 (keylist[numout].key_data_contents[1] = 
			  (krb5_octet *) malloc(kp1->key_data_length[1])))) {
			keylist[numout].key_data_ver = kp1->key_data_ver;
			keylist[numout].key_data_kvno = kp1->key_data_kvno;
			keylist[numout].key_data_type[0] =
			    kp1->key_data_type[0];
			keylist[numout].key_data_type[1] =
			    kp1->key_data_type[1];
			if (keylist[numout].key_data_length[0] =
			    kp1->key_data_length[0])
			    memcpy(keylist[numout].key_data_contents[0],
				   kp1->key_data_contents[0],
				   kp1->key_data_length[0]);
			if (keylist[numout].key_data_length[1] =
			    kp1->key_data_length[1])
			    memcpy(keylist[numout].key_data_contents[1],
				   kp1->key_data_contents[1],
				   kp1->key_data_length[1]);
			numout++;
		    }
		}
		krb5_xfree(kslist);
	    }
	}
    }
    else
	kret = ENOMEM;

    if (!kret) {
	if (*outp && *nkeysout)
	    key_free_key_data(*outp, *nkeysout);
	*outp = keylist;
	*nkeysout = numout;
    }
    else {
	if (keylist) {
	    if (numout)
		key_free_key_data(keylist, numout);
	    else
		free(keylist);
	}
    }
    return(kret);
}

/*
 * admin_merge_dbentries()	- Merge two database entries and a password.
 */
static krb5_error_code
admin_merge_dbentries(kcontext, debug_level, who, defaultp,
		      valid, dbentp, password, is_pwchange)
    krb5_context	kcontext;
    int			debug_level;
    krb5_principal	who;
    krb5_db_entry	*defaultp;
    krb5_ui_4		valid;
    krb5_db_entry	*dbentp;
    char		*password;
    krb5_boolean	is_pwchange;
{
    krb5_error_code	kret = 0;
    krb5_int32		num_keys, num_ekeys, num_rkeys;
    krb5_key_data	*key_list;
    krb5_key_data	*ekey_list;
    DPRINT(DEBUG_CALLS, debug_level, ("* admin_merge_dbentries()\n"));

    /*
     * Ensure that there's a principal,
     * 	we have the current t-o-d,
     * 	and that we don't have a password and the random-password option.
     */
    kret = EINVAL;
    num_keys = num_ekeys = num_rkeys = 0;
    key_list = (krb5_key_data *) NULL;
    ekey_list = (krb5_key_data *) NULL;
    if (!dbentp->princ) {
      DPRINT(DEBUG_OPERATION, debug_level, ("> no principal supplied???"));
      goto bailout;
    }
    if (password && (valid & KRB5_ADM_M_RANDOMKEY)) {
      DPRINT(DEBUG_OPERATION, debug_level, ("> password and randomkey???"));
      goto bailout;
    }
    /*
     * Now fill in unsupplied values from defaults.
     */
    if ((valid & KRB5_ADM_M_MAXLIFE) == 0)
      dbentp->max_life = defaultp->max_life;
    if ((valid & KRB5_ADM_M_MAXRENEWLIFE) == 0)
      dbentp->max_renewable_life = defaultp->max_renewable_life;
    if ((valid & KRB5_ADM_M_EXPIRATION) == 0)
      dbentp->expiration = defaultp->expiration;
    if ((valid & KRB5_ADM_M_PWEXPIRATION) == 0)
      dbentp->pw_expiration = defaultp->pw_expiration;
    if ((valid & KRB5_ADM_M_FLAGS) == 0)
      dbentp->attributes = defaultp->attributes;

    /*
     * Now fill in un-suppliable values from our data.
     */
    dbentp->last_success = defaultp->last_success;
    dbentp->last_failed = defaultp->last_failed;
    dbentp->fail_auth_count = defaultp->fail_auth_count;

    dbentp->len = defaultp->len;
    kret = 0;

    /*
     * Update last password change (if appropriate) and modification
     * date and principal.
     */
    kret = key_update_tl_attrs(kcontext, dbentp, who, 
			       (password || is_pwchange));
    if (kret) {
      DPRINT(DEBUG_OPERATION, debug_level, ("> update_tl_attrs FAILED???"));
      goto bailout;
    }
    /* See if this is a random key or not */
    if (password) {
      krb5_data		pwdata;
      DPRINT(DEBUG_OPERATION, debug_level, ("> string-to-key\n"));
      /*
       * Now handle string-to-key and salt.
       */
      pwdata.data = password;
      pwdata.length = strlen(password);

      /* Convert password string to key */
      kret = key_string_to_keys(kcontext, ((is_pwchange) ? defaultp : dbentp),
				&pwdata, 0, (krb5_key_salt_tuple *) NULL,
				&num_keys, &key_list);
      if (kret) {
	DPRINT(DEBUG_OPERATION, debug_level, ("> pw true, key_string_to_keys FAILED???"));
	goto bailout2;
      }
      /* Encrypt the keys */
      DPRINT(DEBUG_OPERATION, debug_level, ("> encode\n"));
      num_ekeys = num_keys;
      kret = key_encrypt_keys(kcontext, defaultp, &num_ekeys, 
			      key_list, &ekey_list);
      if (kret) {
	DPRINT(DEBUG_OPERATION, debug_level, ("> pw true, key_encrypt_keys FAILED???"));
	goto bailout2;
      }

      num_rkeys = (krb5_int32) dbentp->n_key_data;
      kret = admin_merge_keys(kcontext, defaultp,
			      1,
			      num_ekeys, ekey_list,
			      (krb5_int32) defaultp->n_key_data,
			      defaultp->key_data,
			      &num_rkeys, &dbentp->key_data);
      dbentp->n_key_data = (krb5_int16) num_rkeys;

    } else if (valid & KRB5_ADM_M_RANDOMKEY) {
      /* Random key */
      DPRINT(DEBUG_OPERATION, debug_level, ("> random key\n"));
      kret = key_random_key(kcontext, ((is_pwchange) ? defaultp : dbentp),
			    &num_keys, &key_list);
      if (kret) {
	DPRINT(DEBUG_OPERATION, debug_level, ("> pw false, key_random_key FAILED???"));
	goto bailout2;
      }

      /* Encrypt the keys */
      DPRINT(DEBUG_OPERATION, debug_level, ("> encode\n"));
      num_ekeys = num_keys;
      kret = key_encrypt_keys(kcontext, defaultp, &num_ekeys, key_list,
			      &ekey_list);
      if (kret) {
	DPRINT(DEBUG_OPERATION, debug_level, ("> pw false, key_encrypt_keys FAILED???"));
	goto bailout2;
      }
      num_rkeys = (krb5_int32) dbentp->n_key_data;
      kret = admin_merge_keys(kcontext, defaultp,
			      0,
			      num_ekeys, ekey_list,
			      (krb5_int32) defaultp->n_key_data,
			      defaultp->key_data,
			      &num_rkeys, &dbentp->key_data);
      dbentp->n_key_data = (krb5_int16) num_rkeys;
    } else {
      DPRINT(DEBUG_OPERATION, debug_level, ("> simple modify\n"));
      kret = admin_merge_keys(kcontext, defaultp,
			      0, /* only one list, so don't need unique */
			      0, 0, /* no keys in one list */
			      (krb5_int32) defaultp->n_key_data,
			      defaultp->key_data,
			      &num_rkeys, &dbentp->key_data);
      dbentp->n_key_data = (krb5_int16) num_rkeys;
    }
  bailout2:
    
    /*
     * Finally, if this is a password change, clear the password-change
     * required bit.
     */
    if (password || is_pwchange)
      dbentp->attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;

  bailout:
    if (key_list)
	key_free_key_data(key_list, num_keys);
    if (ekey_list)
	key_free_key_data(ekey_list, num_ekeys);
    DPRINT(DEBUG_CALLS, debug_level, ("X admin_merge_dbentries()=%d\n", kret));
    return(kret);
}

/*
 * admin_add_modify()	- Adds or modifies a database entry.
 *
 * Does all the work for add_principal, modify_principal, change_opwd,
 * and change_orandpwd.
 *
 * Supplied argument list must contain at least one entry, the name of the
 * target principal.
 */
static krb5_int32
admin_add_modify(kcontext, debug_level, ticket, nargs, arglist,
		 should_exist, pwd_supplied, supp_pwd)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_int32		nargs;		/* # rem. arguments	*/ /* In */
    krb5_data		*arglist;	/* Remaining arguments	*/ /* In */
    krb5_boolean	should_exist;	/* Should it exist?	*/ /* In */
    krb5_boolean	pwd_supplied;	/* Password supplied?	*/ /* In */
    char		*supp_pwd;	/* Supplied password	*/ /* In */
{
    krb5_int32		retval = KRB5_ADM_SUCCESS;
    krb5_error_code	kret = 0;
    krb5_principal	client;
    char		*client_name;
    krb5_ui_4		valid_mask;
    krb5_db_entry	new_dbentry;
    krb5_db_entry	cur_dbentry;
    krb5_principal	principal;
    char		*new_password;
    krb5_int32		operation;
    const char		*op_msg;
#ifdef	DEBUG
    char		*dbg_op_msg;
#endif	/* DEBUG */
    int		how_many;
    krb5_boolean	more;
    krb5_data	pword_data;
    krb5_int32	temp;
    krb5_db_entry	*merge;
    int		nument;

    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_add_modify(%s)\n", arglist[0].data));
    /* Initialize */
    client = (krb5_principal) NULL;
    client_name = (char *) NULL;
    valid_mask = 0;
    memset((char *) &new_dbentry, 0, sizeof(new_dbentry));
    memset((char *) &cur_dbentry, 0, sizeof(cur_dbentry));
    principal = (krb5_principal) NULL;
    new_password = (char *) NULL;

    /* Determine what our operation is based on should_exist/pwd_supplied */
    if (should_exist) {
	if (pwd_supplied) {
	    operation = ACL_CHANGEPW;
	    op_msg = (supp_pwd) ? admin_change_pwd_text :
		admin_change_rpwd_text;
#ifdef	DEBUG
	    dbg_op_msg = (supp_pwd) ? "CHANGE PASSWORD" :
		"CHANGE RANDOM PASSWORD";
#endif	/* DEBUG */
	} else {
	    operation = ACL_MODIFY_PRINCIPAL;
	    op_msg = admin_modify_principal_text;
#ifdef	DEBUG
	    dbg_op_msg = "MODIFY PRINCIPAL";
#endif	/* DEBUG */
	}
    } else {
	if (pwd_supplied) {
	    return(KRB5_ADM_SYSTEM_ERROR);
	} else {
	    operation = ACL_ADD_PRINCIPAL;
	    op_msg = admin_add_principal_text;
#ifdef	DEBUG
	    dbg_op_msg = "ADD PRINCIPAL";
#endif	/* DEBUG */
	}
    }

    /* Get the identity of our client */
    kret = admin_client_identity(kcontext, debug_level, ticket,
				 &client, &client_name);
    if (kret) {
	/* We really choked here. */
	com_err(programname, kret, admin_no_cl_ident_fmt, op_msg);
	retval = KRB5_ADM_SYSTEM_ERROR;
	goto bailout;
    }

    /* See if this client can perform this operation. */
    if (!acl_op_permitted(kcontext, client, operation, arglist[0].data)) {
      /* ACL check failed */
      com_err(programname, 0, admin_perm_denied_fmt,
	      op_msg, arglist[0].data, client_name);
      retval = KRB5_ADM_NOT_AUTHORIZED;
      goto bailout2;
    }

    /* Parse the specified principal name */
    kret = krb5_parse_name(kcontext, arglist[0].data, &principal);
    if (kret)  {
      /* Principal name parse failed */
      DPRINT(DEBUG_OPERATION, debug_level,
	     ("> bad principal string \"%s\"\n", arglist[0].data));
      retval = (should_exist) ? KRB5_ADM_P_DOES_NOT_EXIST :
	KRB5_ADM_BAD_OPTION;
      goto bailout2;
    }

    how_many = 1;
    /* Try to get the entry */
    kret = krb5_db_get_principal(kcontext, principal, &cur_dbentry,
				 &how_many, &more);

    /*
     * If we're modifying, there'd better be an entry.
     * If we're adding, there'd better not be an entry.
     */
    if (kret) {
      /* Database entry failed or yielded unexpected results */
      DPRINT(DEBUG_OPERATION, debug_level, ("> database read error\n"));
      com_err(programname, kret,
	      admin_db_read_err_fmt, op_msg, client_name);
      retval = KRB5_ADM_SYSTEM_ERROR;
      goto bailout3;
    }
    if (should_exist && !how_many) {
      DPRINT(DEBUG_OPERATION, debug_level, 
	     ("> principal %s not in database\n", arglist[0].data));
      retval = KRB5_ADM_P_DOES_NOT_EXIST;
      goto bailout3;
    }
    if (!should_exist && how_many) {
      DPRINT(DEBUG_OPERATION, debug_level,
	     ("> principal %s already in database\n", arglist[0].data));
      retval = KRB5_ADM_P_ALREADY_EXISTS;
      goto bailout3;
    }

    /* We need to have a principal */
    /* new_dbentry.princ = principal; */
    krb5_copy_principal(kcontext, principal, &(new_dbentry.princ));
      
    /*
     * Parse the argument list and make sure that only valid
     * options are set.
     */
    kret = krb5_adm_proto_to_dbent(kcontext,
				   nargs-1, &arglist[1], &valid_mask,
				   &new_dbentry, &new_password);
    if (kret ||	(valid_mask & ~KRB5_ADM_M_SET_VALID)) {
      /* Argument list parse failed or bad options */
      DPRINT(DEBUG_PROTO, debug_level,
	     ("= argument list bad for %s\n", dbg_op_msg));
      retval = KRB5_ADM_BAD_OPTION;
      goto bailout4;
    }
    
    pword_data.data = (pwd_supplied) ? supp_pwd : new_password;
    pword_data.length = (pword_data.data) ? strlen(pword_data.data) : 0;
	
    /*
     * Check viability of options specified.  One
     * of the following must be true:
     *	1) randomkey was specified and no password.
     *	2) randomkey is not specified and there
     *	   is a password to change/set and it is
     *	   is suitable.
     *	3) randomkey is not specified and there is
     *	   no password to change and this is
     *	   is a modify entry request.
     *
     * Check the suitability of the new password, if
     * one was supplied.
     */

    if ((valid_mask & KRB5_ADM_M_RANDOMKEY) && pword_data.data) {
      /* claimed random key but gave a password */
      DPRINT(DEBUG_PROTO, debug_level, 
	     ("= conflicting options for %s\n", dbg_op_msg));
      retval = KRB5_ADM_BAD_OPTION;
      goto bailout5;
    }
    if (!(valid_mask & KRB5_ADM_M_RANDOMKEY)
	&& pword_data.data
	&& !passwd_check_npass_ok(kcontext, debug_level,
				  new_dbentry.princ, &new_dbentry,
				  &pword_data, &temp)
	) {
      DPRINT(DEBUG_PROTO, debug_level,
	     ("= bad password for %s\n", dbg_op_msg));
      retval = KRB5_ADM_PW_UNACCEPT;
      goto bailout5;
    }
	  
    merge = (should_exist) ? &cur_dbentry : &admin_def_dbent;
	  
    /* Merge the specified entries with the defaults */
    kret = admin_merge_dbentries(kcontext, debug_level,
				 client, merge, valid_mask,
				 &new_dbentry, pword_data.data,
				 pwd_supplied);
    if (kret) { /* Option merge failed */
      DPRINT(DEBUG_PROTO, debug_level,
	     ("= option merge failed for %s\n", dbg_op_msg));
      retval = KRB5_ADM_BAD_OPTION;
      goto bailout5;
    } 
    nument = 1;
			       
    /* Write the entry. */
    kret = krb5_db_put_principal(kcontext, &new_dbentry, &nument);
    if (kret || (nument != 1)) {
      /* Ultimate failure */
      com_err(programname, kret, admin_db_write_err_fmt, op_msg, client_name);
      DPRINT(DEBUG_OPERATION, debug_level,
	     ("> db write failed for %s\n", dbg_op_msg));
      retval = KRB5_ADM_SYSTEM_ERROR;
    } else {
      /* Ultimate success */
      com_err(programname, 0, admin_db_success_fmt, 
	      op_msg, arglist[0].data, client_name);
    }
    
  bailout5:	
    /* Clean up droppings from krb5_adm_proto_to_dbent */
    if (new_password) {
      krb5_xfree(new_password);
      new_password = 0;
    }
       
  bailout4:
    if (should_exist)
      krb5_db_free_principal(kcontext, &cur_dbentry, 1);
    krb5_db_free_principal(kcontext, &new_dbentry, 1);
    principal = (krb5_principal) NULL;
    
  bailout3:
    /* Clean up from krb5_parse_name (If left over) */
    if (principal)
      krb5_free_principal(kcontext, principal);
    
  bailout2:
    /* Clean up admin_client_identity droppings */
    krb5_xfree(client_name);
    krb5_free_principal(kcontext, client);

  bailout:
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_add_modify() = %d\n", retval));
    return(retval);
}

/*
 * admin_delete_rename()	- Delete or rename a named principal.
 */
static krb5_int32
admin_delete_rename(kcontext, debug_level, ticket, original, new)
    krb5_context	kcontext;
    int			debug_level;
    krb5_ticket		*ticket;
    char		*original;
    char		*new;
{
    krb5_int32		retval = 0;
    krb5_error_code	kret;
    krb5_principal	client;
    char		*client_name;
    krb5_db_entry	orig_entry;
    krb5_principal	orig_principal;
    krb5_int32		operation;
    const char *	op_msg;

    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_delete_rename(%s,%s)\n",
	    original,((new) ? new : "(null)")));

    /* Initialize */
    client = (krb5_principal) NULL;
    client_name = (char *) NULL;
    memset((char *) &orig_entry, 0, sizeof(orig_entry));
    orig_principal = (krb5_principal) NULL;
    operation = (new) ? ACL_RENAME_PRINCIPAL : ACL_DELETE_PRINCIPAL;
    op_msg = (new) ? admin_rename_principal_text : admin_delete_principal_text;

    /* Get the identity of our client */
    if (!(kret = admin_client_identity(kcontext,
				       debug_level,
				       ticket,
				       &client,
				       &client_name))) {

	/* See if this client can perform this operation. */
	if (acl_op_permitted(kcontext, client, operation, original)) {

	    /* Parse the specified principal name */
	    if (!(kret = krb5_parse_name(kcontext,
					 original,
					 &orig_principal))) {
		int		how_many;
		krb5_boolean	more;

		how_many = 1;

		/* Try to get the entry */
		if (!(kret = krb5_db_get_principal(kcontext,
						   orig_principal,
						   &orig_entry,
						   &how_many,
						   &more))
		    && how_many) {

		    /*
		     * We've got the entry.  If we're renaming, we have
		     * to make sure that the new entry's not there.  Then
		     * we can put the new entry.  If we're deleting or
		     * renaming, we delete the entry last.
		     */
		    if (new) {
			krb5_principal	new_principal;

			if (!(kret = krb5_parse_name(kcontext,
						     new,
						     &new_principal))) {
			    int			n_howmany;
			    krb5_boolean	n_more;
			    krb5_db_entry	xxx_dbentry;

			    n_howmany = 1;

			    /* Try to get the entry */
			    if (!(kret = krb5_db_get_principal(kcontext,
							       new_principal,
							       &xxx_dbentry,
							       &n_howmany,
							       &n_more))
				&& !n_howmany) {
				/* Change our name */
				krb5_free_principal(kcontext,
						    orig_entry.princ);
				orig_entry.princ = new_principal;

				/* Update our stats */
				if (!(kret = key_update_tl_attrs(kcontext,
								 &orig_entry,
								 client,
								 0))) {
				    n_howmany = 1;
				    if ((kret = krb5_db_put_principal(kcontext,
								      &orig_entry,
								      &n_howmany))
					|| (n_howmany != 1)) {
					retval = KRB5_ADM_SYSTEM_ERROR;
				    }
				    else {
					com_err(programname, 0,
						admin_db_rename_fmt,
						op_msg, original, new,
						client_name);
				    }
				}
				else {
				    retval = KRB5_ADM_SYSTEM_ERROR;
				}
				orig_entry.princ = (krb5_principal) NULL;
			    }
			    else {
				if (kret) {
				    com_err(programname, kret,
					    admin_db_read_err_fmt,
					    op_msg,
					    client_name);
				    retval = KRB5_ADM_SYSTEM_ERROR;
				}
				else {
				    DPRINT(DEBUG_OPERATION, debug_level,
					   ("> principal \"%s\" already exists\n", 
					    new));
				    retval = KRB5_ADM_P_ALREADY_EXISTS;
				}
				if (!kret)
				    krb5_db_free_principal(kcontext,
							   &xxx_dbentry,
							   n_howmany);
			    }
			    /* Clean up from krb5_parse_name */
			    krb5_free_principal(kcontext, new_principal);
			}
			else {
			    DPRINT(DEBUG_OPERATION, debug_level,
				   ("> bad principal string \"%s\"\n", 
				    new));
			    retval = KRB5_ADM_BAD_OPTION;
			}
		    }
		    /*
		     * If we've fallen through, or if the new addition was
		     * successful, delete the original entry.
		     */
		    if (!kret && !retval) {
			int num2do = 1;
			/* Delete operation */
			kret = krb5_db_delete_principal(kcontext,
							orig_principal,
							&num2do);
			if ((kret != 0) || (num2do != 1)) {
			    if (kret) {
				com_err(programname, kret,
					admin_db_del_err_fmt,
					original, op_msg, client_name);
			    }
			    retval = KRB5_ADM_SYSTEM_ERROR;
			}
			else {
			    if (!new)
				com_err(programname, 0,
					admin_db_success_fmt,
					op_msg, original, client_name);
			}
		    }
		    krb5_db_free_principal(kcontext, &orig_entry, 1);
		}
		else {
		    /* Database lookup failed or returned unexpected result */
		    if (kret) {
			com_err(programname, kret,
				admin_db_read_err_fmt, op_msg, client_name);
			retval = KRB5_ADM_SYSTEM_ERROR;
		    }
		    else {
			DPRINT(DEBUG_OPERATION, debug_level,
			       ("> principal %s not in database\n",
				original));
			retval = KRB5_ADM_P_DOES_NOT_EXIST;
		    }
		}

		/* Clean up from krb5_parse_name */
		krb5_free_principal(kcontext, orig_principal);
	    }
	    else {
		/* Principal name parse failed */
		DPRINT(DEBUG_OPERATION, debug_level,
		       ("> bad principal string \"%s\"\n", original));
		retval = KRB5_ADM_P_DOES_NOT_EXIST;
	    }
	}
	else {
	    /* ACL check failed */
	    com_err(programname, 0, admin_perm_denied_fmt,
		    op_msg, original, client_name);
	    retval = KRB5_ADM_NOT_AUTHORIZED;
	}

	/* Clean up admin_client_identity droppings */
	krb5_xfree(client_name);
	krb5_free_principal(kcontext, client);
    }
    else {
	/* We really choked here. */
	com_err(programname, kret, admin_no_cl_ident_fmt, op_msg);
	retval = KRB5_ADM_SYSTEM_ERROR;
    }
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_delete_rename() = %d\n", retval));
    return(retval);
}

/*
 * admin_keysalt_parse()	- Parse a list of <key>:<salt>[:<kvno>].
 */
static krb5_int32
admin_keysalt_parse(kcontext, debug_level, nents, entries, dups,
		    nksp, kslistp, kvnolistp)
    krb5_context	kcontext;
    int			debug_level;
    krb5_int32		nents;
    krb5_data		*entries;
    krb5_boolean	dups;
    krb5_int32		*nksp;
    krb5_key_salt_tuple	**kslistp;
    krb5_int32		**kvnolistp;
{
    krb5_int32		retval;
    krb5_key_salt_tuple	*keysalts;
    krb5_int32		*kvnolist;
    krb5_int32		ndone;
    int			i,j;
    char		*kvnop;
    int			ncolon;
    krb5_int32		nparsed, onparsed;

    DPRINT(DEBUG_CALLS, debug_level, ("* admin_keysalt_parse()\n"));
    retval = 0;
    ndone = 0;
    keysalts = (krb5_key_salt_tuple *) NULL;
    nparsed = 0;
    if (kvnolist = (krb5_int32 *) malloc(nents * sizeof(krb5_int32))) {
	for (i=0; i<nents; i++)
	    kvnolist[i] = -1;

	for (i=0; i<nents; i++) {
	    /*
	     * Count the number of colon separators.  If there is one, then
	     * there is only key:salt.  If there are two, then it is key:salt:
	     * kvno.  Otherwise there's surely something wrong.
	     */
	    ncolon = 0;
	    for (j=0; j<entries[i].length; j++) {
		if (entries[i].data[j] == ':') {
		    ncolon++;
		    kvnop = &entries[i].data[j];
		}
	    }
	    if (ncolon == 1) {
		kvnop = (char *) NULL;
	    }
	    else if (ncolon == 2) {
		/* Separate it */
		*kvnop = '\0';
		kvnop++;
	    }
	    else {
		retval = KRB5_ADM_BAD_OPTION;
		break;
	    }

	    /*
	     * Parse the string.  Don't allow more than one pair per entry,
	     * but allow duplicate entries if we're told so.
	     */
	    onparsed = nparsed;
	    if (!krb5_string_to_keysalts(entries[i].data,
					 "",
					 ":",
					 dups,
					 &keysalts,
					 &nparsed)) {
		if (nparsed == (onparsed+1)) {
		    if (kvnop) {
			if (sscanf(kvnop,"%d", &kvnolist[ndone]) != 1) {
			    retval = KRB5_ADM_BAD_OPTION;
			    break;
			}
		    }
		    ndone++;
		}
		else {
		    retval = KRB5_ADM_BAD_OPTION;
		    break;
		}
	    }
	    else {
		retval = KRB5_ADM_BAD_OPTION;
		break;
	    }
	}
	if (retval) {
	    ndone = 0;
	    krb5_xfree(keysalts);
	    keysalts = (krb5_key_salt_tuple *) NULL;
	    krb5_xfree(kvnolist);
	    kvnolist = (krb5_int32 *) NULL;
	}
    }
    else
	retval = KRB5_ADM_SYSTEM_ERROR;
    *nksp = ndone;
    *kslistp = keysalts;
    *kvnolistp = kvnolist;
    DPRINT(DEBUG_CALLS, debug_level, ("X admin_keysalt_parse() = %d\n",
				     retval));
    return(retval);
}

/*
 * admin_keysalt_verify()	- Verify the disposition of the key/salts
 */
static krb5_int32
admin_keysalt_verify(kcontext, debug_level, dbentp, should_be_there,
		     nksents, kslist, kvnolist)
    krb5_context	kcontext;
    int			debug_level;
    krb5_db_entry	*dbentp;
    krb5_boolean	should_be_there;
    krb5_int32		nksents;
    krb5_key_salt_tuple	*kslist;
    krb5_int32		*kvnolist;
{
    krb5_int32		retval = 0;
    int			i;
    krb5_key_data	*kdata;

    DPRINT(DEBUG_CALLS, debug_level, ("* admin_keysalt_verify()\n"));
    for (i=0; i<nksents; i++) {
	kdata = (krb5_key_data *) NULL;
	(void) krb5_dbe_find_enctype(kcontext,
				     dbentp,
				     kslist[i].ks_enctype,
				     kslist[i].ks_salttype,
				     kvnolist[i],
				     &kdata);
	if (should_be_there && !kdata) {
	    retval = KRB5_ADM_KEY_DOES_NOT_EXIST;
	    break;
	}
	else if (!should_be_there && kdata) {
	    retval = KRB5_ADM_KEY_ALREADY_EXISTS;
	    break;
	}
    }
    DPRINT(DEBUG_CALLS, debug_level, ("X admin_keysalt_verify() = %d\n",
				     retval));
    return(retval);
}

/*
 * admin_keysalt_operate()	- Perform keysalt surgery
 */
static krb5_int32
admin_keysalt_operate(kcontext, debug_level, dbentp, password, keyectomy,
		      nksents, kslist, kvnolist)
    krb5_context	kcontext;
    int			debug_level;
    krb5_db_entry	*dbentp;
    krb5_data		*password;
    krb5_boolean	keyectomy;
    krb5_int32		nksents;
    krb5_key_salt_tuple	*kslist;
    krb5_int32		*kvnolist;
{
    krb5_int32		retval = 0;
    int			i, j;
    krb5_key_data	*kdata, *ekdata;
    krb5_int32		num_keys, num_ekeys;
    krb5_int16		count;
    krb5_db_entry	tmpent;

    DPRINT(DEBUG_CALLS, debug_level, ("* admin_keysalt_operate()\n"));
    memset(&tmpent, 0, sizeof(krb5_db_entry));
    tmpent.princ = dbentp->princ;	/* Needed for salts in string2key */
    if (keyectomy) {
	count = dbentp->n_key_data;
	for (i=0; i<nksents; i++) {
	    if (!krb5_dbe_find_enctype(kcontext,
				       dbentp,
				       kslist[i].ks_enctype,
				       kslist[i].ks_salttype,
				       kvnolist[i],
				       &kdata)) {
		if (kdata->key_data_contents[0])
		    krb5_xfree(kdata->key_data_contents[0]);
		if (kdata->key_data_contents[1])
		    krb5_xfree(kdata->key_data_contents[1]);
		memset(kdata, 0, sizeof(krb5_key_data));
		count--;
	    }
	    else {
		retval = KRB5_ADM_SYSTEM_ERROR;
		break;
	    }
	}
	kdata = dbentp->key_data;
	if (dbentp->key_data = (krb5_key_data *) malloc(count *
							sizeof(krb5_key_data))
	    ) {
	    j = 0;
	    for (i = 0; i<dbentp->n_key_data; i++) {
		if (kdata[i].key_data_ver ||
		    kdata[i].key_data_kvno ||
		    kdata[i].key_data_type[0] ||
		    kdata[i].key_data_type[1] ||
		    kdata[i].key_data_length[0] ||
		    kdata[i].key_data_length[1] ||
		    kdata[i].key_data_contents[0] ||
		    kdata[i].key_data_contents[1]) {
		    memcpy(&dbentp->key_data[j],
			   &kdata[i],
			   sizeof(krb5_key_data));
		    j++;
		}
	    }
	    krb5_xfree(kdata);
	    dbentp->n_key_data = count;
	}
	else {
	    dbentp->key_data = kdata;
	    retval = KRB5_ADM_SYSTEM_ERROR;
	}
    }
    else {
	/* Convert the string to key for the new key types */
	kdata = ekdata = (krb5_key_data *) NULL;
	if (!key_string_to_keys(kcontext,
				&tmpent,
				password,
				nksents,
				kslist,
				&num_keys,
				&kdata) &&
	    !key_encrypt_keys(kcontext,
			      &tmpent,
			      &num_keys,
			      kdata,
			      &ekdata)) {
	    num_ekeys = (krb5_int32) dbentp->n_key_data;
	    if (admin_merge_keys(kcontext,
				 dbentp,
				 0,
				 num_keys,
				 ekdata,
				 (krb5_int32) dbentp->n_key_data,
				 dbentp->key_data,
				 &num_ekeys,
				 &dbentp->key_data)) {
		retval = KRB5_ADM_SYSTEM_ERROR;
	    }
	    else
		dbentp->n_key_data = (krb5_int16) num_ekeys;
	}
	if (kdata && num_keys)
	    key_free_key_data(kdata, num_keys);
	if (ekdata && num_keys)
	    key_free_key_data(ekdata, num_keys);
	if (tmpent.key_data && tmpent.n_key_data)
	    key_free_key_data(tmpent.key_data, tmpent.n_key_data);
    }
    DPRINT(DEBUG_CALLS, debug_level, ("X admin_keysalt_operate() = %d\n",
				     retval));
    return(retval);
}

/*
 * admin_key_op()	- Handle an add_key or delete_key request.
 */
static krb5_int32
admin_key_op(kcontext, debug_level, ticket, nargs, arglist, is_delete)
    krb5_context	kcontext;
    int			debug_level;
    krb5_ticket		*ticket;
    krb5_int32		nargs;
    krb5_data		*arglist;
    krb5_boolean	is_delete;
{
    krb5_int32		retval = 0;
    krb5_error_code	kret;
    krb5_principal	client;
    char		*client_name;
    krb5_db_entry	entry;
    krb5_principal	principal;
    krb5_int32		operation;
    const char *	op_msg;
    krb5_int32		nkeysalts;
    krb5_key_salt_tuple	*keysalt_list;
    krb5_int32		*kvno_list;
    int			n_howmany;

    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_key_op(%s,%d)\n", arglist[0].data, is_delete));

    /* Initialize */
    client = (krb5_principal) NULL;
    client_name = (char *) NULL;
    memset((char *) &entry, 0, sizeof(entry));
    principal = (krb5_principal) NULL;
    operation = ACL_MODIFY_PRINCIPAL;
    op_msg = (is_delete) ? admin_delete_key_text : admin_add_key_text;
    keysalt_list = (krb5_key_salt_tuple *) NULL;
    kvno_list = (krb5_int32 *) NULL;

    /* Get the identity of our client */
    if (!(kret = admin_client_identity(kcontext,
				       debug_level,
				       ticket,
				       &client,
				       &client_name))) {

	/* See if this client can perform this operation. */
	if (acl_op_permitted(kcontext, client, operation, arglist[0].data)) {

	    /* Parse the specified principal name */
	    if (!(kret = krb5_parse_name(kcontext,
					 arglist[0].data,
					 &principal))) {
		int		how_many;
		krb5_boolean	more;

		how_many = 1;

		/* Try to get the entry */
		if (!(kret = krb5_db_get_principal(kcontext,
						   principal,
						   &entry,
						   &how_many,
						   &more))
		    && how_many) {

		    /* See if the supplied old password is good */
		    if (passwd_check_opass_ok(kcontext,
					      debug_level,
					      principal,
					      &entry,
					      &arglist[1])) {

			if (
			    /* Parse the keysalt arguments */
			    !(retval = admin_keysalt_parse(kcontext,
							   debug_level,
							   nargs-2,
							   &arglist[2],
							   is_delete,
							   &nkeysalts,
							   &keysalt_list,
							   &kvno_list)) &&
			    /* Verify the disposition */
			    !(retval = admin_keysalt_verify(kcontext,
							    debug_level,
							    &entry,
							    is_delete,
							    nkeysalts,
							    keysalt_list,
							    kvno_list)) &&
			    /* Perform the surgery */
			    !(retval = admin_keysalt_operate(kcontext,
							     debug_level,
							     &entry,
							     &arglist[1],
							     is_delete,
							     nkeysalts,
							     keysalt_list,
							     kvno_list)) &&
			    /* Update our statistics */
			    !(retval = key_update_tl_attrs(kcontext,
							   &entry,
							   client,
							   0))) {
			    n_howmany = 1;
			    if ((kret = krb5_db_put_principal(kcontext,
							      &entry,
							      &n_howmany))
				|| (n_howmany != 1)) {
				retval = KRB5_ADM_SYSTEM_ERROR;
			    }
			    else {
				com_err(programname, 0,
					admin_db_key_op_fmt,
					op_msg, arglist[0].data,
					client_name);
			    }
			}
			else {
			    if (kret)
				retval = KRB5_ADM_SYSTEM_ERROR;
			}
			if (keysalt_list)
			    krb5_xfree(keysalt_list);
			if (kvno_list)
			    free(kvno_list);
		    }
		    else
			retval = KRB5_ADM_BAD_PW;
		    krb5_db_free_principal(kcontext, &entry, 1);
		}
		else {
		    /* Database lookup failed or returned unexpected result */
		    if (kret) {
			com_err(programname, kret,
				admin_db_read_err_fmt, op_msg, client_name);
			retval = KRB5_ADM_SYSTEM_ERROR;
		    }
		    else {
			DPRINT(DEBUG_OPERATION, debug_level,
			       ("> principal %s not in database\n",
				arglist[0].data));
			retval = KRB5_ADM_P_DOES_NOT_EXIST;
		    }
		}

		/* Clean up from krb5_parse_name */
		krb5_free_principal(kcontext, principal);
	    }
	    else {
		/* Principal name parse failed */
		DPRINT(DEBUG_OPERATION, debug_level,
		       ("> bad principal string \"%s\"\n", arglist[0].data));
		retval = KRB5_ADM_P_DOES_NOT_EXIST;
	    }
	}
	else {
	    /* ACL check failed */
	    com_err(programname, 0, admin_perm_denied_fmt,
		    op_msg, arglist[0].data, client_name);
	    retval = KRB5_ADM_NOT_AUTHORIZED;
	}

	/* Clean up admin_client_identity droppings */
	krb5_xfree(client_name);
	krb5_free_principal(kcontext, client);
    }
    else {
	/* We really choked here. */
	com_err(programname, kret, admin_no_cl_ident_fmt, op_msg);
	retval = KRB5_ADM_SYSTEM_ERROR;
    }
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_key_op() = %d\n", retval));
    return(retval);
}

/*
 * admin_inq_iterator()	- Routine called by krb5_db_iterate to scan through the
 *			  database for a particular entry and its next entry.
 */
static krb5_error_code
admin_inq_iterator(pointer, dbentp)
    krb5_pointer	pointer;
    krb5_db_entry	*dbentp;
{
    krb5_error_code	kret;
    struct inq_context	*iargp;

    kret = 0;
    iargp = (struct inq_context *) pointer;
    /*
     * See if we have found a target of our search.
     */
    if (!iargp->ic_entry_found) {
	/*
	 * No, now we are looking for a particular entry.
	 */
	if (!iargp->ic_who ||
	    krb5_principal_compare(iargp->ic_context,
				   iargp->ic_who,
				   dbentp->princ)) {
	    if (iargp->ic_who) {
		DPRINT(DEBUG_OPERATION, iargp->ic_level,
		       ("> found entry\n"));
		kret = krb5_adm_dbent_to_proto(iargp->ic_context,
					       KRB5_ADM_M_GET_VALID,
					       dbentp,
					       (char *) NULL,
					       iargp->ic_ncomps,
					       iargp->ic_clist);
		if (!kret) {
		    iargp->ic_entry_found = 1;
		    DPRINT(DEBUG_OPERATION, iargp->ic_level,
			   ("> converted entry to protocol\n"));
		}
		else {
		    DPRINT(DEBUG_OPERATION, iargp->ic_level,
			   ("> convert entry to protocol failed\n"));
		}
	    }
	    else {
		iargp->ic_entry_found = 1;
		*(iargp->ic_ncomps) = 0;
		*(iargp->ic_clist) = (krb5_data *) NULL;
		if (!iargp->ic_next) {
		    kret = krb5_unparse_name(iargp->ic_context,
					     dbentp->princ,
					     &iargp->ic_next);
		    if (kret) {
			DPRINT(DEBUG_OPERATION, iargp->ic_level,
			       ("> unparse next entry failed\n"));
		    }
		    else {
			DPRINT(DEBUG_OPERATION, iargp->ic_level,
			       ("> next entry is %s\n", iargp->ic_next));
		    }
		}
	    }
	}
    }
    else {
	if (!iargp->ic_next) {
	    kret = krb5_unparse_name(iargp->ic_context,
				     dbentp->princ,
				     &iargp->ic_next);
	    if (kret) {
		DPRINT(DEBUG_OPERATION, iargp->ic_level,
		       ("> unparse next entry failed\n"));
	    }
	    else {
		DPRINT(DEBUG_OPERATION, iargp->ic_level,
		       ("> next entry is %s\n", iargp->ic_next));
	    }
	}
    }
    return(kret);
}

/*
 * admin_add_principal()	- Add a principal with the specified attributes
 */
krb5_int32
admin_add_principal(kcontext, debug_level, ticket, nargs, arglist)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_int32		nargs;		/* # rem. arguments	*/ /* In */
    krb5_data		*arglist;	/* Remaining arguments	*/ /* In */
{
    krb5_int32		retval;

    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_add_principal(%s)\n", arglist[0].data));
    retval = admin_add_modify(kcontext,
			      debug_level,
			      ticket,
			      nargs,
			      arglist,
			      0, /* should exist */
			      0, /* passwd supplied */
			      (char *) NULL);
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_add_principal() = %d\n", retval));
    return(retval);
}

/*
 * admin_delete_principal()	- Delete the specified principal.
 */
krb5_int32
admin_delete_principal(kcontext, debug_level, ticket, principal)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_data		*principal;	/* Principal to delete	*/ /* In */
{
    krb5_int32	retval;
    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_delete_principal(%s)\n", principal->data));
    retval = admin_delete_rename(kcontext,
				 debug_level,
				 ticket,
				 principal->data,
				 (char *) NULL);
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_delete_principal() = %d\n", retval));
    return(retval);
}

/*
 * admin_rename_principal()	- Rename the original principal to the
 *				  specified principal.
 */
krb5_int32
admin_rename_principal(kcontext, debug_level, ticket, original, new)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_data		*original;	/* Original principal 	*/ /* In */
    krb5_data		*new;		/* New Principal 	*/ /* In */
{
    krb5_int32	retval;
    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_rename_principal(%s)\n", original->data));
    retval = admin_delete_rename(kcontext,
				 debug_level,
				 ticket,
				 original->data,
				 new->data);
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_rename_principal() = %d\n", retval));
    return(retval);
}

/*
 * admin_modify_principal()	- Modify the specified principal with the
 *				  specifed attributes using the existing
 *				  entry as a template.
 */
krb5_int32
admin_modify_principal(kcontext, debug_level, ticket, nargs, arglist)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_int32		nargs;		/* # rem. arguments	*/ /* In */
    krb5_data		*arglist;	/* Remaining arguments	*/ /* In */
{
    krb5_int32	retval;

    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_modify_principal(%s)\n", arglist[0].data));
    retval = admin_add_modify(kcontext,
			      debug_level,
			      ticket,
			      nargs,
			      arglist,
			      1, /* should exist */
			      0, /* passwd supplied */
			      (char *) NULL);
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_modify_principal() = %d\n", retval));
    return(retval);
}

/*
 * admin_change_opwd()	- Change the password of a principal.
 */
krb5_int32
admin_change_opwd(kcontext, debug_level, ticket, principal, password)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_data		*principal;	/* Principal 		*/ /* In */
    krb5_data		*password;	/* New Password 	*/ /* In */
{
    krb5_int32	retval;
    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_change_opw(%s)\n", principal->data));
    retval = admin_add_modify(kcontext,
			      debug_level,
			      ticket,
			      1,
			      principal,
			      1, /* should exist */
			      1, /* passwd supplied */
			      password->data);
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_change_opw() = %d\n", retval));
    return(retval);
}

/*
 * admin_change_orandpwd()	- Change the random key of a principal.
 */
krb5_int32
admin_change_orandpwd(kcontext, debug_level, ticket, principal)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_data		*principal;	/* Principal 		*/ /* In */
{
    krb5_int32	retval = 0;
    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_change_orandpw(%s)\n", principal->data));
    retval = admin_add_modify(kcontext,
			      debug_level,
			      ticket,
			      1,
			      principal,
			      1, /* should exist */
			      1, /* passwd supplied */
			      (char *) NULL);
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_change_orandpw() = %d\n", retval));
    return(retval);
}

/*
 * admin_inquire()	- Retrieve the attributes of a principal.
 */
krb5_int32
admin_inquire(kcontext, debug_level, ticket, principal, ncompp, complistp)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_data		*principal;	/* Principal 		*/ /* In */
    krb5_int32		*ncompp;	/* # reply components	*/ /* Out */
    krb5_data		**complistp;	/* Reply component list	*/ /* Out */
{
    krb5_int32		retval = KRB5_ADM_SUCCESS;
    krb5_error_code	kret = 0;
    krb5_principal	client;
    krb5_principal	target;
    char		*client_name;

    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_inquire(%s)\n", principal->data));
    /* Initialize */
    client = target = (krb5_principal) NULL;
    client_name = (char *) NULL;

    /* Get the identity of our client */
    if (!(kret = admin_client_identity(kcontext,
				       debug_level,
				       ticket,
				       &client,
				       &client_name))) {

	/* See if this client can perform this operation. */
	if (acl_op_permitted(kcontext, client, ACL_INQUIRE, principal->data)) {

	    /* Parse the specified principal name */
	    if (!principal->length ||
		!(kret = krb5_parse_name(kcontext,
					 principal->data,
					 &target))) {
		struct inq_context	iargs;
		krb5_data	*tmplistp;
		krb5_int32	tmpncomp;

		/*
		 * Now - if we had a "find/findnext" set of database operators
		 * then we could do this easily, but here we're going to have
		 * to iterate through the whole database and find our entry.
		 * If we find it, continue to the next entry so that we can
		 * return it.
		 */
		DPRINT(DEBUG_OPERATION, debug_level,
		       ("> Find entry %s\n", 
			((principal->length) ? principal->data : "(null)")));
		iargs.ic_context = kcontext;
		iargs.ic_level = debug_level;
		iargs.ic_who = (principal->length) ? target :
		  (krb5_principal) NULL;
		iargs.ic_entry_found = 0;
		iargs.ic_ncomps = &tmpncomp;
		iargs.ic_clist = &tmplistp;
		iargs.ic_next = (char *) NULL;
		if (!(kret = krb5_db_iterate(kcontext,
					     admin_inq_iterator,
					     &iargs))) {

		    /* After scanning, did we find it? */
		    if (iargs.ic_entry_found) {

			/*
			 * How inconvenient.  We have the list already
			 * packaged up, but we have to insert our next
			 * element first.
			 */
			if (*complistp = (krb5_data *)
			    malloc((size_t) (tmpncomp+1) * sizeof(krb5_data))
			    ) {
			    memset((char *) &(*complistp)[0], 0,
				   sizeof(krb5_data));
			    if (iargs.ic_next) {
				(*complistp)[0].data = iargs.ic_next;
				(*complistp)[0].length =
				    strlen((*complistp)[0].data);
			    }
			    memcpy(&(*complistp)[1], &tmplistp[0],
				   (size_t) tmpncomp * sizeof(krb5_data));
			    *ncompp = tmpncomp+1;
			    krb5_xfree(tmplistp);
			}
			else {
			    /* Could not get memory for new component list */
			    DPRINT(DEBUG_OPERATION, debug_level,
				   ("> could not get memory\n"));
			    retval = KRB5_ADM_SYSTEM_ERROR;
			}
		    }
		    else {
			/* Could not find principal */
			DPRINT(DEBUG_OPERATION, debug_level,
			       ("> cannot find principal \"%s\"\n",
				principal->data));
			retval = KRB5_ADM_P_DOES_NOT_EXIST;
		    }
		}
		else {
		    /* Could not iterate */
		    DPRINT(DEBUG_OPERATION, debug_level,
			   ("> could not iterate database\n"));
		    retval = KRB5_ADM_SYSTEM_ERROR;
		}
		/* Cleanup */
		krb5_free_principal(kcontext, target);
	    }
	    else {
		/* Could not parse principal name */
		DPRINT(DEBUG_OPERATION, debug_level,
		       ("> bad principal string \"%s\"\n", principal->data));
		retval = KRB5_ADM_P_DOES_NOT_EXIST;
	    }
	}
	else {
	    /* Not authorized to perform this function */
	    com_err(programname, 0, admin_perm_denied_fmt,
		    admin_inquire_text,
		    (principal->length) ? principal->data : admin_fentry_text,
		    client_name);
	    retval = KRB5_ADM_NOT_AUTHORIZED;
	}

	/* Clean up */
	krb5_xfree(client_name);
	krb5_free_principal(kcontext, client);
    }
    else {
	/* Something is really wrong here. */
	com_err(programname, kret, admin_no_cl_ident_fmt, admin_inquire_text);
	retval = KRB5_ADM_SYSTEM_ERROR;
    }
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_inquire() = %d\n", retval));
    return(retval);
}

/*
 * admin_extract_key()	- Extract the service key entry for this name/instance
 */
krb5_int32
admin_extract_key(kcontext, debug_level, ticket,
		  instance, name, ncompp, complistp)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_data		*instance;	/* Instance of principal*/ /* In */
    krb5_data		*name;		/* Name of principal 	*/ /* In */
    krb5_int32		*ncompp;	/* # reply components	*/ /* Out */
    krb5_data		**complistp;	/* Reply component list	*/ /* Out */
{
    krb5_int32		retval = KRB5_ADM_SUCCESS;
    krb5_error_code	kret = 0;
    krb5_principal	client;
    char		*client_name;
    char		*realm;
    char		*princname;
    krb5_principal	principal;
    krb5_db_entry	dbentry;
    int			nentries;
    krb5_boolean	more;
    krb5_keytab_entry	ktabentry;
    krb5_int32		num_keys;
    krb5_key_data	*dkey_list;
    
    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_extract_key(%s/%s)\n", name->data, instance->data));
    
    /* Get the identity of our client */
    if (!(kret = admin_client_identity(kcontext,
				       debug_level,
				       ticket,
				       &client,
				       &client_name))) {

	realm = key_master_realm();
	if (princname = (char *) malloc((size_t) name->length + 1 +
					instance->length + 1 +
					strlen(realm) + 1)) {

	    /* Formulate the name of our target */
	    sprintf(princname, "%s/%s@%s", name->data,
		    instance->data, realm);
		
	    /* See if it's a valid name */
	    if (!(kret = krb5_parse_name(kcontext,
					 princname,
					 &principal))) {

		/* See if this client can perform this operation. */
		if (acl_op_permitted(kcontext, client, ACL_EXTRACT,
				     princname)) {

		    /* Get the database entry */
		    nentries = 1;
		    if (!(kret = krb5_db_get_principal(kcontext,
						       principal,
						       &dbentry,
						       &nentries,
						       &more)) &&
			(nentries == 1) && (!more)) {

			/* Decrypt the key entries. */
			memset((char *) &ktabentry, 0, sizeof(ktabentry));
			num_keys = (krb5_int32) dbentry.n_key_data;
			if (!(kret = key_decrypt_keys(kcontext,
						      &dbentry,
						      &num_keys,
						      dbentry.key_data,
						      &dkey_list))) {
			    ktabentry.principal = principal;
			    ktabentry.vno = dkey_list[0].key_data_kvno;
			    ktabentry.key.enctype =
				dkey_list[0].key_data_type[0];
			    ktabentry.key.length = 
				dkey_list[0].key_data_length[0];
			    ktabentry.key.contents =
				dkey_list[0].key_data_contents[0];

			    /* Pack the response */
			    if (kret = krb5_adm_ktent_to_proto(kcontext,
							       &ktabentry,
							       ncompp,
							       complistp)) {
				DPRINT(DEBUG_OPERATION, debug_level,
				       ("> cannot package keytab protocol\n"));
				retval = KRB5_ADM_SYSTEM_ERROR;
			    }

			    /* Cleanup from key_decrypt_keys */
			    if (num_keys && dkey_list)
				key_free_key_data(dkey_list, num_keys);
			}
			else {
			    /* key_decrypt_keys failed */
			    com_err(programname, kret,
				    admin_key_dec_err_fmt,
				    princname, admin_extract_key_text,
				    client_name);
			    retval = KRB5_ADM_SYSTEM_ERROR;
			}
			krb5_db_free_principal(kcontext, &dbentry, nentries);
		    }
		    else {
			/*
			 * Database lookup failed or produced unexpected 
			 * results.
			 */
			if (kret) {
			    com_err(programname, kret,
				    admin_db_read_err_fmt,
				    admin_extract_key_text,
				    client_name);
			    retval = KRB5_ADM_SYSTEM_ERROR;
			}
			else {
			    if (nentries == 0) {
				DPRINT(DEBUG_OPERATION, debug_level,
				       ("> principal \"%s\" does not exist\n", 
					    princname));
				retval = KRB5_ADM_P_DOES_NOT_EXIST;
			    }
			    else {
				DPRINT(DEBUG_OPERATION, debug_level,
				       ("> principal \"%s\" not unique\n", 
					    princname));
				retval = KRB5_ADM_SYSTEM_ERROR;
				krb5_db_free_principal(kcontext,
						       &dbentry,
						       nentries);
			    }
			}
		    }
		    krb5_free_principal(kcontext, principal);
		}
		else {
		    /* Not authorized to perform this operation */
		    com_err(programname, 0, admin_perm_denied_fmt,
			    admin_extract_key_text, princname, client_name);
		    retval = KRB5_ADM_NOT_AUTHORIZED;
		}
	    }
	    else {
		/* Name parse failed */
		DPRINT(DEBUG_OPERATION, debug_level,
		       ("> bad principal string \"%s\"\n", princname));
		retval = KRB5_ADM_P_DOES_NOT_EXIST;
	    }
	    free(princname);
	}
	else {
	    /* No memory. */
	    DPRINT(DEBUG_OPERATION, debug_level,
		   ("> no memory for principal name\n"));
	    retval = KRB5_ADM_SYSTEM_ERROR;
	}

	/* Clean up */
	krb5_xfree(client_name);
	krb5_free_principal(kcontext, client);
    }
    else {
	/* Cannot get our identity */
	com_err(programname, kret, admin_no_cl_ident_fmt,
		admin_extract_key_text);
	retval = KRB5_ADM_SYSTEM_ERROR;
    }
    DPRINT(DEBUG_CALLS, debug_level,
	   ("X admin_extract_key() = %d\n", retval));
    return(retval);
}

/*
 * admin_add_key()	- Add new enctypes for the given principal.
 */
krb5_int32
admin_add_key(kcontext, debug_level, ticket, nargs, arglist)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_int32		nargs;		/* # rem. arguments	*/ /* In */
    krb5_data		*arglist;	/* Remaining arguments	*/ /* In */
{
    krb5_int32	retval;

    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_add_key(%s)\n", arglist[0].data));
    retval = admin_key_op(kcontext,
			  debug_level,
			  ticket,
			  nargs,
			  arglist,
			  0);
    DPRINT(DEBUG_CALLS, debug_level, ("X admin_add_key() = %d\n", retval));
    return(retval);
}

/*
 * admin_delete_key()	- Delete enctypes for the given principal.
 */
krb5_int32
admin_delete_key(kcontext, debug_level, ticket, nargs, arglist)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    int			debug_level;	/* Debug level		*/ /* In */
    krb5_ticket		*ticket;	/* Kerberos ticket	*/ /* In */
    krb5_int32		nargs;		/* # rem. arguments	*/ /* In */
    krb5_data		*arglist;	/* Remaining arguments	*/ /* In */
{
    krb5_int32	retval;

    DPRINT(DEBUG_CALLS, debug_level,
	   ("* admin_delete_key(%s)\n", arglist[0].data));
    retval = admin_key_op(kcontext,
			  debug_level,
			  ticket,
			  nargs,
			  arglist,
			  1);
    DPRINT(DEBUG_CALLS, debug_level, ("X admin_delete_key() = %d\n", retval));
    return(retval);
}

void
admin_init(max_life, max_renew_life, e_valid, e, f_valid, f)
    krb5_deltat		max_life;
    krb5_deltat		max_renew_life;
    krb5_boolean	e_valid;
    krb5_timestamp	e;
    krb5_boolean	f_valid;
    krb5_flags		f;
{
    admin_init_def_dbent(max_life, max_renew_life, e_valid, e, f_valid, f);
}
