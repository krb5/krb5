/*
 * kadmin/v5server/srv_key.c
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
 * srv_key.c - Handle Kerberos key related functions.
 */
#include "k5-int.h"
#include "adm.h"
#include "com_err.h"
#include "kadm5_defs.h"

struct keysalt_iterate_args {
    krb5_context	context;
    krb5_data		*string;
    krb5_db_entry	*dbentry;
    krb5_key_data	*keys;
    krb5_int32		index;
};

/*
 * These control the maximum [renewable] life of the changepw principal, if
 * it is created by us.
 */
#define	KEY_DEF_MAX_LIFE	(2*60*60)
#define	KEY_DEF_MAX_RLIFE	(2*60*60)

static const char *key_cpw_ufokey_fmt = "%s: no keys in database entry for %s.\n";
static const char *key_cpw_decerr_fmt = "%s: cannot decode keys for %s.\n";
static const char *key_add_cpw_err_fmt = "%s: cannot add entry for %s (%s).\n";
static const char *key_add_cpw_succ_fmt = "Added password changing service principal (%s).";
static const char *key_cpw_encerr_fmt = "%s: cannot encode keys for %s.\n";
static const char *key_cpw_rkeyerr_fmt = "%s: cannot make random key for %s.\n";
static const char *key_cpw_uniqerr_fmt = "%s: database entry for %s is not unique.\n";
static const char *key_cpw_parserr_fmt = "%s: cannot parse %s.\n";
static const char *key_keytab_fmt = "%s: cannot resolve keytab %s (%s).\n";
static const char *key_bad_etype_fmt = "%s: bad etype %d (%s).\n";
static const char *key_def_realm_fmt = "%s: cannot find default realm (%s).\n";
static const char *key_setup_mkey_fmt = "%s: cannot setup master key name (%s).\n";
static const char *key_get_mkey_fmt = "%s: cannot retrieve master key (%s).\n";
static const char *key_vfy_mkey_fmt = "%s: cannot verify master key (%s).\n";
static const char *key_proc_mkey_fmt = "%s: cannot process master key (%s).\n";
static const char *key_kgen_initf_fmt = "%s: disabling key type %d because initialization failed (%s).\n";
static const char *key_bad_name_fmt = "%s: cannot set database name to %s (%s).\n";
static const char *key_cant_init_fmt = "%s: cannot initialize database (%s).\n";
static const char *key_vmast_key_fmt = "%s: cannot verify master key (%s).\n";
static const char *key_key_pp_fmt = "%s: cannot preprocess key (%s).\n";
static const char *key_rkey_fmt = "%s: cannot initialize random key generator (%s).\n";
static const char *key_getm_fmt = "%s: cannot get master entry (%s).\n";

static int		mprinc_init = 0;
static krb5_principal	master_principal;

static int		mkeyb_init = 0;
static krb5_keyblock	master_keyblock;

static int		mencb_init = 0;
static krb5_encrypt_block master_encblock;

static int		mrand_init = 0;
static krb5_pointer	master_random;

static int		ment_init = 0;
static krb5_db_entry	master_entry;

static int		mrealm_init = 0;
static char		*master_realm = (char *) NULL;

static int		mkeytab_init = 0;
static krb5_keytab	key_keytab = (krb5_keytab) NULL;

static int		madmin_key_init = 0;
static krb5_key_data	*madmin_keys = (krb5_key_data *) NULL;
static krb5_keyblock	madmin_key;
static krb5_int32	madmin_num_keys = 0;

static int		key_num_ktents = 0;
static krb5_key_salt_tuple *key_ktents = (krb5_key_salt_tuple *) NULL;
static int		key_ktents_inited = 0;
static krb5_key_salt_tuple default_ktent = {
    KEYTYPE_DES, KRB5_KDB_SALTTYPE_NORMAL
};

static int key_debug_level = 0;

extern char *programname;

/*
 * key_get_admin_entry()	- Find the admin entry or create one.
 */
static krb5_error_code
key_get_admin_entry(kcontext)
    krb5_context	kcontext;
{
    krb5_error_code	kret;
    char		*realm_name;
    char		*admin_princ_name;
    krb5_principal	admin_principal;
    int			number_of_entries;
    krb5_boolean	more_entries;
    krb5_db_entry	madmin_entry;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_get_admin_entry()\n"));
    kret = ENOMEM;
    realm_name = key_master_realm();

    /*
     * The admin principal format is:
     *	<admin-service-name>/<realm>@<realm>
     */
    admin_princ_name = (char *) malloc((size_t)
				       ((2*strlen(realm_name)) + 3 +
					strlen(KRB5_ADM_SERVICE_NAME)));
    if (admin_princ_name) {
	/* Format the admin name */
	sprintf(admin_princ_name, "%s/%s@%s", KRB5_ADM_SERVICE_NAME,
		realm_name, realm_name);
	DPRINT(DEBUG_REALM, key_debug_level,
	       ("- setting up admin principal %s\n", admin_princ_name));
	/* Parse the admin name */
	if (!(kret = krb5_parse_name(kcontext,
				     admin_princ_name,
				     &admin_principal))) {
	    number_of_entries = 1;
	    more_entries = 0;
	    /*
	     * Attempt to get the database entry.
	     */
	    if (!(kret = krb5_db_get_principal(kcontext,
					       admin_principal,
					       &madmin_entry,
					       &number_of_entries,
					       &more_entries)) &&
		(number_of_entries == 1) &&
		(!more_entries)) {
		DPRINT(DEBUG_REALM, key_debug_level,
		       ("- found database entry for %s\n", admin_princ_name));
		/*
		 * If the entry's present and it's unique, then we can
		 * just proceed and decrypt the key.
		 */
		madmin_num_keys = madmin_entry.n_key_data;
		if (!(kret = key_decrypt_keys(kcontext,
					      &madmin_entry,
					      &madmin_num_keys,
					      madmin_entry.key_data,
					      &madmin_keys))) {
		    DPRINT(DEBUG_REALM, key_debug_level,
			   ("- found admin keys\n"));
		    madmin_key_init = 1;
		}
		else
		    fprintf(stderr,
			    key_cpw_decerr_fmt,
			    programname,
			    admin_princ_name);
		krb5_db_free_principal(kcontext,
				       &madmin_entry,
				       number_of_entries);
	    }
	    else {
		/*
		 * We failed to find a unique entry.  See if the entry
		 * wasn't present.  If so, then try to create it.
		 */
		if (!kret && !number_of_entries) {
		    krb5_tl_mod_princ	mprinc;
		    krb5_timestamp	now;

		    DPRINT(DEBUG_REALM, key_debug_level,
			   ("- no database entry for %s\n", admin_princ_name));
		    /*
		     * Not present - Set up our database entry.
		     */
		    memset((char *) &madmin_entry, 0, sizeof(madmin_entry));
		    madmin_entry.attributes = KRB5_KDB_PWCHANGE_SERVICE;
		    madmin_entry.princ = admin_principal;
		    madmin_entry.max_life = KEY_DEF_MAX_LIFE;
		    madmin_entry.max_renewable_life = KEY_DEF_MAX_RLIFE;
		    number_of_entries = 1;

		    krb5_timeofday(kcontext, &now);
		    /*
		     * Argh - now set up our auxiliary data.
		     */
		    if ((madmin_entry.tl_data =
			 (krb5_tl_data *) malloc(sizeof(krb5_tl_data))) &&
			(madmin_entry.tl_data->tl_data_contents =
			 (krb5_octet *) malloc(sizeof(krb5_timestamp)))) {
			madmin_entry.n_tl_data = 1;
			madmin_entry.tl_data->tl_data_next =
			    (krb5_tl_data *) NULL;
			madmin_entry.tl_data->tl_data_type =
			    KRB5_TL_LAST_PWD_CHANGE;
			madmin_entry.tl_data->tl_data_length =
			    sizeof(krb5_timestamp);
			madmin_entry.tl_data->tl_data_contents[0] =
			    (unsigned char) ((now >> 24) & 0xff);
			madmin_entry.tl_data->tl_data_contents[1] =
			    (unsigned char) ((now >> 16) & 0xff);
			madmin_entry.tl_data->tl_data_contents[2] =
			    (unsigned char) ((now >> 8) & 0xff);
			madmin_entry.tl_data->tl_data_contents[3] =
			    (unsigned char) (now & 0xff);
		    }

		    mprinc.mod_date = now;
		    if (!krb5_copy_principal(kcontext,
					     admin_principal,
					     &mprinc.mod_princ)) {
			krb5_dbe_encode_mod_princ_data(kcontext,
						       &mprinc,
						       &madmin_entry);
			krb5_free_principal(kcontext, mprinc.mod_princ);
		    }

		    /*
		     * Generate a random key.
		     */
		    if (!(kret = key_random_key(kcontext,
						&madmin_entry,
						&madmin_num_keys,
						&madmin_keys))) {
			if (!(kret = key_encrypt_keys(kcontext,
						      &madmin_entry,
						      &madmin_num_keys,
						      madmin_keys,
						      &madmin_entry.key_data))
			    )  {
			    madmin_entry.n_key_data =
				(krb5_int16) madmin_num_keys;
			    if (kret = 
				krb5_db_put_principal(kcontext,
						      &madmin_entry,
						      &number_of_entries)) {
				fprintf(stderr,
					key_add_cpw_err_fmt,
					programname,
					admin_princ_name,
					error_message(kret));
			    }
			    else
				com_err(programname, 0,
					key_add_cpw_succ_fmt,
					admin_princ_name);
			}
			else
			    fprintf(stderr,
				    key_cpw_encerr_fmt,
				    programname,
				    admin_princ_name);
			if (!kret)
			    madmin_key_init = 1;
		    }
		    else
			fprintf(stderr,
				key_cpw_rkeyerr_fmt,
				programname,
				admin_princ_name);
		}
		else {
		    if (!kret && more_entries)
			krb5_db_free_principal(kcontext,
					       &madmin_entry,
					       number_of_entries);
		    fprintf(stderr,
			    key_cpw_uniqerr_fmt,
			    programname,
			    admin_princ_name);
		}
	    }
	    krb5_free_principal(kcontext, admin_principal);
	}
	else
	    fprintf(stderr,
		    key_cpw_parserr_fmt,
		    programname,
		    admin_princ_name);
	free(admin_princ_name);
    }

    if (kret && madmin_num_keys && madmin_keys) {
	key_free_key_data(madmin_keys, madmin_num_keys);
	madmin_key_init = 0;
    }

    if (!kret && madmin_num_keys && madmin_keys) {
	krb5_key_data		*kdata;
	krb5_db_entry		xxx;

	/*
	 * Find the latest key.
	 */
	xxx.n_key_data = (krb5_int16) madmin_num_keys;
	xxx.key_data = madmin_keys;
	if (krb5_dbe_find_keytype(kcontext,
				  &xxx,
				  KEYTYPE_DES,
				  -1,
				  -1,
				  &kdata))
	    kdata = &madmin_keys[0];

	memset(&madmin_key, 0, sizeof(krb5_keyblock));
	madmin_key.keytype = KEYTYPE_DES;
	madmin_key.etype = ETYPE_UNKNOWN;
	madmin_key.length = kdata->key_data_length[0];
	madmin_key.contents = kdata->key_data_contents[0];
    }

    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_get_admin_entry() = %d\n", kret));
    return(kret);
}

/*
 * key_init()	- Initialize key context.
 */
krb5_error_code
key_init(kcontext, debug_level, enc_type, key_type, master_key_name, manual,
	 db_file, db_realm, kt_name, sf_name, nktent, ktents)
    krb5_context	kcontext;
    int			debug_level;
    int			enc_type;
    int			key_type;
    char		*master_key_name;
    int			manual;
    char		*db_file;
    char		*db_realm;
    char		*kt_name;
    char		*sf_name;
    krb5_int32		nktent;
    krb5_key_salt_tuple	*ktents;
{
    krb5_enctype 	kdc_etype;
    char		*mkey_name;

    krb5_error_code	kret;
    krb5_enctype	etype;
    int			one_success;
    int 		number_of_entries;
    krb5_boolean	more_entries;

    key_debug_level = debug_level;
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("* key_init(enc-type=%d, key-type=%d,\n\tmkeyname=%s, manual=%d,\n\tdb=%s,\n\trealm=%s,\n\tktab=%s)\n",
	    enc_type, key_type,
	    ((master_key_name) ? master_key_name : "(null)"),
	    manual,
	    ((db_file) ? db_file : "(default)"),
	    ((db_realm) ? db_realm : "(null)"),
	    ((kt_name) ? kt_name : "(null)")));
    /*
     * Figure out arguments.
     */
    master_keyblock.keytype = ((key_type == -1) ? KEYTYPE_DES : key_type);
    mkey_name = ((!master_key_name) ? KRB5_KDB_M_NAME : master_key_name);
    kdc_etype = ((enc_type == -1) ? DEFAULT_KDC_ETYPE : enc_type);

    /*
     * First, try to set up our keytab if supplied.
     */
    if (kt_name) {
	if (kret = krb5_kt_resolve(kcontext, kt_name, &key_keytab)) {
	    fprintf(stderr, key_keytab_fmt, programname,
		    kt_name, error_message(kret));
	    goto leave;
	}
    }
    mkeytab_init = 1;

    if (!valid_etype(kdc_etype)) {
	kret = KRB5_PROG_ETYPE_NOSUPP;
	fprintf(stderr, key_bad_etype_fmt, programname, kdc_etype,
		error_message(kret));
	goto leave;
    }
    if (!db_realm) {
	kret = krb5_get_default_realm(kcontext, &master_realm);
	if (kret) {
	    fprintf(stderr, key_def_realm_fmt, programname,
		    error_message(kret));
	    goto leave;
	}
    }
    else {
	if (kret = krb5_set_default_realm(kcontext, db_realm))
	    goto leave;
	master_realm = (char *) malloc(strlen(db_realm)+1);
	if (!master_realm) {
	    kret = ENOMEM;
	    goto leave;
	}
	strcpy(master_realm, db_realm);
    }
    mrealm_init = 1;
    DPRINT(DEBUG_REALM, key_debug_level,
	   ("- initializing for realm %s\n", master_realm));

    /* Set database name if supplied */
    if (db_file && (kret = krb5_db_set_name(kcontext, db_file))) {
	fprintf(stderr, key_bad_name_fmt, programname, db_file,
		error_message(kret));
	goto leave;
    }

    /* Initialize database */
    if (kret = krb5_db_init(kcontext)) {
	fprintf(stderr, key_cant_init_fmt, programname,
		error_message(kret));
	goto leave;
    }

    /* Assemble and parse the master key name */
    kret = krb5_db_setup_mkey_name(kcontext,
				   mkey_name,
				   master_realm,
				   (char **) NULL,
				   &master_principal);
    if (kret) {
	fprintf(stderr, key_setup_mkey_fmt, programname,
		error_message(kret));
	goto cleanup;
    }
    mprinc_init = 1;
    DPRINT(DEBUG_HOST, key_debug_level,
	   ("- master key is %s@%s\n", mkey_name, master_realm));

    /* Get the master database entry and save it. */
    number_of_entries = 1;
    kret = krb5_db_get_principal(kcontext,
				     master_principal,
				     &master_entry,
				     &number_of_entries,
				     &more_entries);
    if (!kret) {
	if (number_of_entries != 1) {
	    if (number_of_entries)
		krb5_db_free_principal(kcontext,
				       &master_entry,
				       number_of_entries);
	    kret = KRB5_KDB_NOMASTERKEY;
	}
	else if (more_entries) {
	    krb5_db_free_principal(kcontext,
				   &master_entry,
				   number_of_entries);
	    kret = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
	}
    }
    if (kret) {
	fprintf(stderr, key_getm_fmt, programname, error_message(kret));
	goto leave;
    }
    ment_init = 1;

    krb5_use_cstype(kcontext, &master_encblock, kdc_etype);

    /* Go get the master key */
    kret = krb5_db_fetch_mkey(kcontext,
			      master_principal,
			      &master_encblock,
			      manual,
			      FALSE,		/* Only read once if manual */
			      sf_name,		/* stash file */
			      0,		/* No salt */
			      &master_keyblock);
    if (kret) {
	fprintf(stderr, key_get_mkey_fmt, programname,
		error_message(kret));
	goto cleanup;
    }

    /* Verify the master key */
    if (kret = krb5_db_verify_master_key(kcontext,
					 master_principal,
					 &master_keyblock,
					 &master_encblock)) {
	fprintf(stderr, key_vmast_key_fmt, programname,
		error_message(kret));
	goto leave;
    }

    /* Do any key pre-processing */
    if (kret = krb5_process_key(kcontext,
				&master_encblock,
				&master_keyblock)) {
	fprintf(stderr, key_key_pp_fmt, programname, error_message(kret));
	goto leave;
    }
    mencb_init = 1;
    mkeyb_init = 1;

    /* Now initialize the random key */
    kret = krb5_init_random_key(kcontext,
				&master_encblock,
				&master_keyblock,
				&master_random);
    if (kret) {
	fprintf(stderr, key_rkey_fmt, programname, error_message(kret));
	goto leave;
    }
    mrand_init = 1;

    /*
     * We're almost home.  We now want to find our service entry and if there
     * is none, then we want to create it.  This way, kadmind5 becomes just
     * a plug in and go kind of utility.
     */
    kret = key_get_admin_entry(kcontext, debug_level);

    if (!kret) {
	if (key_num_ktents = nktent)
	    key_ktents = ktents;
	else {
	    key_num_ktents = 1;
	    key_ktents = &default_ktent;
	}
	key_ktents_inited = 1;
    }

 cleanup:
    if (kret) {
	if (mrand_init) {
	    krb5_finish_random_key(kcontext, &master_encblock, &master_random);
	    mrand_init = 0;
	}
	if (mencb_init) {
	    krb5_finish_key(kcontext, &master_encblock);
	    mencb_init = 0;
	}
	if (mkeyb_init) {
	    memset(master_keyblock.contents, 0,
		   (size_t) master_keyblock.length);
	    krb5_xfree(master_keyblock.contents);
	    mkeyb_init = 0;
	}
	if (ment_init) {
	    krb5_db_free_principal(kcontext, &master_entry, 1);
	    ment_init = 0;
	}
	if (mrealm_init) {
	    krb5_xfree(master_realm);
	    mrealm_init = 0;
	}
	if (mkeytab_init) {
	    if (key_keytab)
		krb5_kt_close(kcontext, key_keytab);
	    key_keytab = (krb5_keytab) NULL;
	    mkeytab_init = 0;
	}
	if (madmin_key_init) {
	    key_free_key_data(madmin_keys, madmin_num_keys);
	    madmin_key_init = 0;
	}
    }
 leave:
    DPRINT(DEBUG_CALLS, key_debug_level, ("X key_init() = %d\n", kret));
    return(kret);
}

/*
 * key_finish	- Terminate key context.
 */
void
key_finish(kcontext, debug_level)
    krb5_context	kcontext;
    int			debug_level;
{
    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_finish()\n"));
    if (mrand_init) {
	krb5_finish_random_key(kcontext, &master_encblock, &master_random);
	mrand_init = 0;
    }
    if (mkeyb_init) {
	krb5_finish_key(kcontext, &master_encblock);
	memset((char *) &master_encblock, 0,
	       sizeof(master_encblock));
	mkeyb_init = 0;
    }
    if (mprinc_init) {
	krb5_free_principal(kcontext, master_principal);
	mprinc_init = 0;
    }
    if (mencb_init) {
	master_encblock.crypto_entry = 0;
	mencb_init = 0;
    }
    if (ment_init) {
	krb5_db_free_principal(kcontext, &master_entry, 1);
	ment_init = 0;
    }
    if (mrealm_init) {
	krb5_xfree(master_realm);
	mrealm_init = 0;
    }
    if (mkeytab_init) {
	if (key_keytab)
	    krb5_kt_close(kcontext, key_keytab);
	key_keytab = (krb5_keytab) NULL;
	mkeytab_init = 0;
    }
    if (madmin_key_init) {
	key_free_key_data(madmin_keys, madmin_num_keys);
	madmin_key_init = 0;
    }
    krb5_db_fini(kcontext);
    /* memset((char *) tgs_key.contents, 0, tgs_key.length); */
    DPRINT(DEBUG_CALLS, key_debug_level, ("X key_finish()\n"));
}

/*
 * key_string2key_keysalt()	- Local iterator routine for keysalt_iterate.
 */
static krb5_error_code
key_string2key_keysalt(ksent, ptr)
    krb5_key_salt_tuple	*ksent;
    krb5_pointer	ptr;
{
    struct keysalt_iterate_args *argp;
    krb5_boolean	salted;
    krb5_key_data	*kdata;
    krb5_error_code	kret;
    krb5_data		salt;
    krb5_keyblock	key;
    krb5_key_data	*okeyp;

    argp = (struct keysalt_iterate_args *) ptr;
    kret = 0;
    /*
     * Determine if this key/salt pair is salted.
     */
    salted = 0;
    krb5_use_keytype(argp->context, &master_encblock, ksent->ks_keytype);
    if (!krb5_dbe_find_keytype(argp->context,
			       argp->dbentry,
			       ksent->ks_keytype,
			       ksent->ks_salttype,
			       -1,
			       &kdata)) {
	if (kdata->key_data_length[1] && kdata->key_data_contents[1])
	    salted = 1;
    }
    else {
	/*
	 * Cannot find a name-to-data matching, so we must have to create a
	 * new key entry.
	 */
	if (!(kret = krb5_dbe_create_key_data(argp->context, argp->dbentry))) {
	    kdata = &argp->dbentry->key_data[argp->dbentry->n_key_data-1];
	    kdata->key_data_type[0] = (krb5_int16) ksent->ks_keytype;
	    kdata->key_data_type[1] = (krb5_int16) ksent->ks_salttype;
	}
    }

    if (!kret) {
	/*
	 * We have "kdata" pointing to the key entry we're to futz
	 * with.
	 */
	if (!salted) {
	    switch (kdata->key_data_type[1]) {
	    case KRB5_KDB_SALTTYPE_V4:
		salt.length = 0;
		salt.data = (char *) NULL;
		break;
	    case KRB5_KDB_SALTTYPE_NORMAL:
		/* Normal salt */
		if (kret = krb5_principal2salt(argp->context,
					       argp->dbentry->princ,
					       &salt))
		    goto done;
		break;
	    case KRB5_KDB_SALTTYPE_NOREALM:
		if (kret = krb5_principal2salt_norealm(argp->context,
						       argp->dbentry->princ,
						       &salt))
		    goto done;
		break;
	    case KRB5_KDB_SALTTYPE_ONLYREALM:
	    {
		krb5_data *xsalt;
		if (kret = krb5_copy_data(argp->context,
					  krb5_princ_realm(argp->context,
							   argp->dbentry->princ
							   ),
					  &xsalt))
		    goto done;
		salt.length = xsalt->length;
		salt.data = xsalt->data;
		krb5_xfree(xsalt);
	    }
		break;
	    default:
		goto done;
	    }
	}
	else {
	    if (salt.length = kdata->key_data_length[1]) {
		if (salt.data = (char *) malloc(salt.length))
		    memcpy(salt.data,
			   (char *) kdata->key_data_contents[1],
			   (size_t) salt.length);
	    }
	    else
		salt.data = (char *) NULL;
	}

       	/*
	 * salt contains the salt.
	 */
	if (kret = krb5_string_to_key(argp->context,
				      &master_encblock,
				      kdata->key_data_type[0],
				      &key,
				      argp->string,
				      &salt))
	    goto done;
	
	/*
	 * Now, salt contains the salt and key contains the decrypted
	 * key.  kdata contains the key/salt data.  Fill in the output.
	 */
	okeyp = &argp->keys[argp->index];
	argp->index++;
	okeyp->key_data_ver = KRB5_KDB_V1_KEY_DATA_ARRAY;
	okeyp->key_data_kvno = kdata->key_data_kvno + 1;
	okeyp->key_data_type[0] = kdata->key_data_type[0];
	okeyp->key_data_type[1] = kdata->key_data_type[1];
	okeyp->key_data_length[0] = (krb5_int16) key.length;
	okeyp->key_data_length[1] = (krb5_int16) salt.length;
	okeyp->key_data_contents[0] = (krb5_octet *) key.contents;
	okeyp->key_data_contents[1] = (krb5_octet *) salt.data;
    }
 done:
    return(kret);
}

/*
 * key_string_to_keys() - convert string to keys.
 */
krb5_error_code
key_string_to_keys(kcontext, dbentp, string, nksalt, ksaltp, nkeysp, keysp)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_data		*string;
    krb5_int32		nksalt;
    krb5_key_salt_tuple	*ksaltp;
    krb5_int32		*nkeysp;
    krb5_key_data	**keysp;
{
    krb5_error_code	kret;
    krb5_key_salt_tuple	*keysalts;
    krb5_int32		nkeysalts;
    krb5_key_data	*keys;
    struct keysalt_iterate_args ksargs;
    krb5_boolean	did_alloc;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_string_to_keys()\n"));

    keys = (krb5_key_data *) NULL;
    /*
     * Determine how many and of what kind of keys to generate.
     */
    keysalts = ksaltp;
    nkeysalts = nksalt;
    did_alloc = 0;
    if (!keysalts || !nkeysalts) {
	kret = key_dbent_to_keysalts(dbentp, &nkeysalts, &keysalts);
	did_alloc = 1;
    }
    if (keysalts && nkeysalts) {
	if (keys = (krb5_key_data *)
	    malloc((size_t) (nkeysalts * sizeof(krb5_key_data)))) {
	    memset(keys, 0, nkeysalts * sizeof(krb5_key_data));
	    ksargs.context = kcontext;
	    ksargs.string = string;
	    ksargs.dbentry = dbentp;
	    ksargs.keys = keys;
	    ksargs.index = 0;
	    kret = krb5_keysalt_iterate(keysalts,
					nkeysalts,
					0,
					key_string2key_keysalt,
					(krb5_pointer) &ksargs);
	}
	else
	    kret = ENOMEM;
	if (did_alloc) 
	    krb5_xfree(keysalts);
    }
 done:
    if (!kret) {
	*nkeysp = ksargs.index;
	*keysp = keys;
    }
    else {
	if (keys && nkeysalts)
	    key_free_key_data(keys, nkeysalts);
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_string_to_keys() = %d\n", kret));
    return(kret);
}

/*
 * key_random_keysalt()	- Local iterator routine for keysalt_iterate.
 */
static krb5_error_code
key_randomkey_keysalt(ksent, ptr)
    krb5_key_salt_tuple	*ksent;
    krb5_pointer	ptr;
{
    struct keysalt_iterate_args *argp;
    krb5_boolean	salted;
    krb5_key_data	*kdata;
    krb5_error_code	kret;
    krb5_keyblock	*key;
    krb5_key_data	*okeyp;

    argp = (struct keysalt_iterate_args *) ptr;
    kret = 0;

    krb5_use_keytype(argp->context, &master_encblock, ksent->ks_keytype);
    if (krb5_dbe_find_keytype(argp->context,
			      argp->dbentry,
			      ksent->ks_keytype,
			      ksent->ks_salttype,
			      -1,
			      &kdata)) {
	/*
	 * Cannot find a name-to-data matching, so we must have to create a
	 * new key entry.
	 */
	if (!(kret = krb5_dbe_create_key_data(argp->context, argp->dbentry))) {
	    kdata = &argp->dbentry->key_data[argp->dbentry->n_key_data-1];
	    kdata->key_data_type[0] = (krb5_int16) ksent->ks_keytype;
	    kdata->key_data_type[1] = (krb5_int16) 0;
	}
    }

    if (!kret) {
	/*
	 * We have "kdata" pointing to the key entry we're to futz
	 * with.
	 */
	if (!(kret = krb5_random_key(kcontext,
				     &master_encblock,
				     master_random,
				     &key))) {
	    /*
	     * Now, salt contains the salt and key contains the decrypted
	     * key.  kdata contains the key/salt data.  Fill in the output.
	     */
	    okeyp = &argp->keys[argp->index];
	    argp->index++;
	    okeyp->key_data_ver = KRB5_KDB_V1_KEY_DATA_ARRAY;
	    okeyp->key_data_kvno = kdata->key_data_kvno + 1;
	    okeyp->key_data_type[0] = kdata->key_data_type[0];
	    okeyp->key_data_type[1] = 0;
	    okeyp->key_data_length[0] = (krb5_int16) key->length;
	    okeyp->key_data_length[1] = 0;
	    okeyp->key_data_contents[0] = (krb5_octet *) key->contents;
	    okeyp->key_data_contents[1] = (krb5_octet *) NULL;
	    krb5_xfree(key);
	}
    }
    return(kret);
}

/*
 * key_random_key()	- generate a random key.
 */
krb5_error_code
key_random_key(kcontext, dbentp, nkeysp, keysp)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_int32		*nkeysp;
    krb5_key_data	**keysp;
{
    krb5_error_code	kret;
    krb5_key_salt_tuple	*keysalts;
    krb5_int32		nkeysalts;
    krb5_key_data	*keys;
    struct keysalt_iterate_args ksargs;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_random_key()\n"));

    keys = (krb5_key_data *) NULL;
    nkeysalts = 0;
    /*
     * Determine how many and of what kind of keys to generate.
     */
    if (!(kret = key_dbent_to_keysalts(dbentp, &nkeysalts, &keysalts))) {
	if (keys = (krb5_key_data *)
	    malloc((size_t) (nkeysalts * sizeof(krb5_key_data)))) {
	    memset(keys, 0, nkeysalts * sizeof(krb5_key_data));
	    ksargs.context = kcontext;
	    ksargs.string = (krb5_data *) NULL;
	    ksargs.dbentry = dbentp;
	    ksargs.keys = keys;
	    ksargs.index = 0;
	    kret = krb5_keysalt_iterate(keysalts,
					nkeysalts,
					1,
					key_randomkey_keysalt,
					(krb5_pointer) &ksargs);
	}
	else
	    kret = ENOMEM;
	krb5_xfree(keysalts);
    }
 done:
    if (!kret) {
	*nkeysp = ksargs.index;
	*keysp = keys;
    }
    else {
	if (keys && nkeysalts)
	    key_free_key_data(keys, nkeysalts);
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_random_keys() = %d\n", kret));
    return(kret);
}

/*
 * key_encrypt_keys() - encrypt keys.
 */
krb5_error_code
key_encrypt_keys(kcontext, dbentp, nkeysp, inkeys, outkeysp)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_int32		*nkeysp;
    krb5_key_data	*inkeys;
    krb5_key_data	**outkeysp;
{
    krb5_error_code	kret;
    krb5_db_entry	loser;
    krb5_int32		nkeys, ndone;
    krb5_keyblock	tmpkey;
    krb5_keysalt	salt;
    int			i;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_encrypt_keys()\n"));
    memset(&loser, 0, sizeof(krb5_db_entry));
    ndone = 0;
    nkeys = *nkeysp;
    for (i=0; i<nkeys; i++) {
	krb5_use_keytype(kcontext,
			 &master_encblock,
			 (krb5_keytype) inkeys[i].key_data_type[0]);
	if (!(kret = krb5_dbe_create_key_data(kcontext, &loser))) {
	    tmpkey.keytype = inkeys[i].key_data_type[0];
	    tmpkey.length = inkeys[i].key_data_length[0];
	    if (tmpkey.contents = (krb5_octet *) malloc((size_t)tmpkey.length))
		memcpy(tmpkey.contents,
		       inkeys[i].key_data_contents[0],
		       tmpkey.length);
	    else
		break;
	    salt.type = inkeys[i].key_data_type[1];
	    if (salt.data.length = inkeys[i].key_data_length[1]) {
		if (salt.data.data = (char *)
		    malloc((size_t) salt.data.length))
		    memcpy(salt.data.data,
			   inkeys[i].key_data_contents[1],
			   (size_t) salt.data.length);
		else
		    break;
	    }
	    else
		salt.data.data = (char *) NULL;

	    if (kret = krb5_dbekd_encrypt_key_data(kcontext,
						   &master_encblock,
						   &tmpkey,
						   &salt,
						   (int) inkeys[i].
						       key_data_kvno,
						   &loser.key_data[i]))
		break;
	    else
		ndone++;
	}
	else
	    break;
    }
 done:
    if (kret) {
	if (loser.key_data && loser.n_key_data)
	    key_free_key_data(loser.key_data, (krb5_int32) loser.n_key_data);
    }
    else {
	*outkeysp = loser.key_data;
	*nkeysp = ndone;
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_encrypt_keys() = %d\n", kret));
    return(kret);
}

/*
 * key_decrypt_keys() - decrypt keys.
 */
krb5_error_code
key_decrypt_keys(kcontext, dbentp, nkeysp, inkeys, outkeysp)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_int32		*nkeysp;
    krb5_key_data	*inkeys;
    krb5_key_data	**outkeysp;
{
    krb5_error_code	kret;
    krb5_db_entry	loser;
    krb5_int32		nkeys, ndone;
    krb5_keyblock	tmpkey;
    krb5_keysalt	salt;
    int			i;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_decrypt_keys()\n"));
    memset(&loser, 0, sizeof(krb5_db_entry));
    ndone = 0;
    nkeys = *nkeysp;
    for (i=0; i<nkeys; i++) {
	krb5_use_keytype(kcontext,
			 &master_encblock,
			 (krb5_keytype) inkeys[i].key_data_type[0]);
	if (!(kret = krb5_dbe_create_key_data(kcontext, &loser))) {
	    if (kret = krb5_dbekd_decrypt_key_data(kcontext,
						   &master_encblock,
						   &inkeys[i],
						   &tmpkey,
						   &salt))
		break;
	    loser.key_data[i].key_data_ver = KRB5_KDB_V1_KEY_DATA_ARRAY;
	    loser.key_data[i].key_data_type[0] = tmpkey.keytype;
	    loser.key_data[i].key_data_length[0] = (krb5_int16) tmpkey.length;
	    loser.key_data[i].key_data_contents[0] = tmpkey.contents;
	    loser.key_data[i].key_data_kvno = inkeys[i].key_data_kvno;
	    loser.key_data[i].key_data_type[1] = salt.type;
	    loser.key_data[i].key_data_length[1] = salt.data.length;
	    loser.key_data[i].key_data_contents[1] =
		(krb5_octet *) salt.data.data;
	    ndone++;
	}
	else
	    break;
    }
 done:
    if (kret) {
	if (loser.key_data && loser.n_key_data)
	    key_free_key_data(loser.key_data, (krb5_int32) loser.n_key_data);
    }
    else {
	*outkeysp = loser.key_data;
	*nkeysp = ndone;
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_decrypt_keys() = %d\n", kret));
    return(kret);
}

/*
 * key_pwd_is_weak()	- Check for weakness of key from password
 */
krb5_boolean
key_pwd_is_weak(kcontext, dbentp, string)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_data		*string;
{
    krb5_boolean	weakness;
    krb5_error_code	kret;
    krb5_int32		num_keys;
    krb5_key_data	*key_list;
    int			i;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_pwd_is_weak()\n"));
    weakness = 0;

    kret = key_string_to_keys(kcontext,
			      dbentp,
			      string,
			      0,
			      (krb5_key_salt_tuple *) NULL,
			      &num_keys,
			      &key_list);
    if (!kret) {
	for (i=0; i<num_keys; i++) {
	    if ((key_list[i].key_data_type[0] == KEYTYPE_DES) &&
		(key_list[i].key_data_length[0] == KRB5_MIT_DES_KEYSIZE) &&
		mit_des_is_weak_key(key_list[i].key_data_contents[0])) {
		weakness = 1;
		break;
	    }
	}
	key_free_key_data(key_list, num_keys);
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_pwd_is_weak() = %d\n", weakness));
    return(weakness);
}

/*
 * key_master_entry()	- Return a pointer to the master entry (yuck).
 */
krb5_db_entry *
key_master_entry()
{
    return((ment_init) ? &master_entry : (krb5_db_entry *) NULL);
}

/*
 * key_master_realm()	- Return name of master realm (yuck).
 */
char *
key_master_realm()
{
    return((mrealm_init) ? master_realm : (char *) NULL);
}

/*
 * key_keytab_id()	- Which key table to use?
 */
krb5_keytab
key_keytab_id()
{
    return((mkeytab_init) ? key_keytab : (krb5_keytab) NULL);
}

/*
 * key_admin_key()	- Get a copy of the admin key.
 */
krb5_keyblock *
key_admin_key()
{
    return((madmin_key_init) ? &madmin_key : (krb5_keyblock *) NULL);
}

/*
 * key_master_encblock()	- Return pointer to master encryption block.
 */
krb5_encrypt_block *
key_master_encblock()
{
    return((mencb_init) ? &master_encblock : (krb5_encrypt_block *) NULL);
}

/*
 * key_free_key_data()		- Free a krb5_key_data array.
 */
void
key_free_key_data(keys, nkeys)
    krb5_key_data	*keys;
    krb5_int32		nkeys;
{
    /*
     * XXX - this should probably be a dbe routine.
     */
    int i, j;

    if (keys && nkeys) {
	for (i=0; i<nkeys; i++) {
	    for (j=0; j<KRB5_KDB_V1_KEY_DATA_ARRAY; j++) {
		if (keys[i].key_data_length[j] &&
		    keys[i].key_data_contents[j]) {
		    memset(keys[i].key_data_contents[j], 0,
			   keys[i].key_data_length[j]);
		    free(keys[i].key_data_contents[j]);
		}
	    }
	    memset(&keys[i], 0, sizeof(krb5_key_data));
	}
	free(keys);
    }
}

/*
 * key_dbent_to_keysalts()	- Generate a list of key/salt pairs.
 */
krb5_error_code
key_dbent_to_keysalts(dbentp, nentsp, ksentsp)
    krb5_db_entry	*dbentp;
    krb5_int32		*nentsp;
    krb5_key_salt_tuple	**ksentsp;
{
    krb5_error_code	kret;
    int			i, j;
    krb5_int32		num;
    krb5_boolean	found;
    krb5_key_salt_tuple	*ksp;

    kret = 0;
    if (dbentp->n_key_data) {
	/* The hard case */
	if (ksp = (krb5_key_salt_tuple *)
	    malloc(dbentp->n_key_data * sizeof(krb5_key_salt_tuple))) {
	    memset(ksp, 0,
		   dbentp->n_key_data * sizeof(krb5_key_salt_tuple));
	    num = 0;
	    for (i=0; i<dbentp->n_key_data; i++) {
		if (krb5_keysalt_is_present(ksp, num,
					    dbentp->key_data[i].
					    	key_data_type[0],
					    dbentp->key_data[i].
					    	key_data_type[1]))
		    continue;
		ksp[num].ks_keytype = dbentp->key_data[i].key_data_type[0];
		ksp[num].ks_salttype = dbentp->key_data[i].key_data_type[1];
		num++;
	    }
	    *ksentsp = ksp;
	    *nentsp = num;
	}
	else
	    kret = ENOMEM;
    }
    else {
	/* The easy case. */
	if (*ksentsp = (krb5_key_salt_tuple *)
	    malloc(key_num_ktents * sizeof(krb5_key_salt_tuple))) {
	    memcpy(*ksentsp, key_ktents,
		   key_num_ktents * sizeof(krb5_key_salt_tuple));
	    *nentsp = key_num_ktents;
	}
	else
	    kret = ENOMEM;
    }
    return(kret);
}

krb5_error_code
key_update_tl_attrs(kcontext, dbentp, mod_name, is_pwchg)
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
