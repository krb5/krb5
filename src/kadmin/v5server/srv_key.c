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
#include "com_err.h"
#include "kadm5_defs.h"
#include "mit-des.h"

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

static int key_debug_level = 0;

extern char *programname;

/*
 * key_init()	- Initialize key context.
 */
krb5_error_code
key_init(kcontext, debug_level, enc_type, key_type, master_key_name, manual,
	 db_file, db_realm)
    krb5_context	kcontext;
    int			debug_level;
    int			enc_type;
    int			key_type;
    char		*master_key_name;
    int			manual;
    char		*db_file;
    char		*db_realm;
{
    krb5_enctype 	kdc_etype;
    char		*mkey_name;
    char		*the_realm;

    krb5_error_code	kret;
    krb5_enctype	etype;
    int			one_success;
    int 		number_of_entries;
    krb5_boolean	more_entries;

    key_debug_level = debug_level;
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("* key_init(enc-type=%d, key-type=%d,\n\tmkeyname=%s, manual=%d,\n\tdb=%s, realm=%s)\n",
	    enc_type, key_type,
	    ((master_key_name) ? master_key_name : "(null)"),
	    manual,
	    ((db_file) ? db_file : "(default)"),
	    ((db_realm) ? db_realm : "(null)")));
    /*
     * Figure out arguments.
     */
    master_keyblock.keytype = ((key_type == -1) ? KEYTYPE_DES : key_type);
    mkey_name = ((!master_key_name) ? KRB5_KDB_M_NAME : master_key_name);
    kdc_etype = ((enc_type == -1) ? DEFAULT_KDC_ETYPE : enc_type);
    if (!valid_etype(kdc_etype)) {
	kret = KRB5_PROG_ETYPE_NOSUPP;
	fprintf(stderr, key_bad_etype_fmt, programname, kdc_etype,
		error_message(kret));
	goto leave;
    }
    if (!db_realm) {
	kret = krb5_get_default_realm(kcontext, &the_realm);
	if (kret) {
	    fprintf(stderr, key_def_realm_fmt, programname,
		    error_message(kret));
	    goto leave;
	}
    }
    else
	the_realm = db_realm;
    DPRINT(DEBUG_REALM, key_debug_level,
	   ("- initializing for realm %s\n", the_realm));

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
				   the_realm,
				   (char **) NULL,
				   &master_principal);
    if (kret) {
	fprintf(stderr, key_setup_mkey_fmt, programname,
		error_message(kret));
	goto cleanup;
    }
    mprinc_init = 1;
    DPRINT(DEBUG_HOST, key_debug_level,
	   ("- master key is %s@%s\n", mkey_name, the_realm));

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
    mencb_init = 1;

    /* Go get the master key */
    kret = krb5_db_fetch_mkey(kcontext,
			      master_principal,
			      &master_encblock,
			      manual,
			      FALSE,		/* Only read once if manual */
			      0,		/* No salt */
			      &master_keyblock);
    if (kret) {
	fprintf(stderr, key_get_mkey_fmt, programname,
		error_message(kret));
	goto cleanup;
    }
    mkeyb_init = 1;

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

    /* Now initialize the random key */
    kret = krb5_init_random_key(kcontext,
				&master_encblock,
				&master_keyblock,
				&master_random);
    if (!kret)
	mrand_init = 1;

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
    }
    if (the_realm != db_realm)
	krb5_xfree(the_realm);
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
    krb5_db_fini(kcontext);
    /* memset((char *) tgs_key.contents, 0, tgs_key.length); */
    DPRINT(DEBUG_CALLS, key_debug_level, ("X key_finish()\n"));
}

/*
 * key_string_to_keys() - convert string to keys.
 */
krb5_error_code
key_string_to_keys(kcontext, principal, string, psalttype, asalttype,
		   primary, alternate)
    krb5_context	kcontext;
    krb5_principal	principal;
    krb5_data		*string;
    krb5_int32		psalttype;
    krb5_int32		asalttype;
    krb5_keyblock	*primary;
    krb5_keyblock	*alternate;
{
    krb5_error_code	kret;
    krb5_data		psalt_data, asalt_data;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_string_to_keys()\n"));
    kret = KRB_ERR_GENERIC;
    psalt_data.length = asalt_data.length = 0;
    psalt_data.data = asalt_data.data = (char *) NULL;

    /*
     * Determine the primary salt type.
     */
    switch (psalttype) {
    case KRB5_KDB_SALTTYPE_NORMAL:
	/* Normal salt */
	if (kret = krb5_principal2salt(kcontext, principal, &psalt_data))
	    goto done;
	asalt_data.data = (char *) NULL;
	asalt_data.length = 0;
	break;
    case KRB5_KDB_SALTTYPE_V4:
	/* V4 salt */
	psalt_data.data = (char *) NULL;
	psalt_data.length = 0;
	if (kret = krb5_principal2salt(kcontext, principal, &asalt_data))
	    goto done;
	break;
    case KRB5_KDB_SALTTYPE_NOREALM:
	if (kret = krb5_principal2salt_norealm(kcontext,
					       principal,
					       &psalt_data))
	    goto done;
	asalt_data.data = (char *) NULL;
	asalt_data.length = 0;
	break;
    case KRB5_KDB_SALTTYPE_ONLYREALM:
    {
	krb5_data	*tmp;

	if (kret = krb5_copy_data(kcontext,
				  krb5_princ_realm(kcontext, principal),
				  &tmp))
	    goto done;
	psalt_data = *tmp;
	krb5_xfree(tmp);
	asalt_data.data = (char *) NULL;
	asalt_data.length = 0;
	break;
    }
    default:
	goto done;
    }

    /* Now convert the string to keys */
    kret = krb5_string_to_key(kcontext,
			      &master_encblock,
			      master_keyblock.keytype,
			      primary,
			      string,
			      &psalt_data);
    if (!kret)
	kret = krb5_string_to_key(kcontext,
				  &master_encblock,
				  master_keyblock.keytype,
				  alternate,
				  string,
				  &asalt_data);

 done:
    if (kret) {
	if (primary->contents) {
	    memset((char *) primary->contents, 0, (size_t) primary->length);
	    krb5_xfree(primary->contents);
	}
	if (alternate->contents) {
	    memset((char *) alternate->contents, 0,
		   (size_t) alternate->length);
	    krb5_xfree(alternate->contents);
	}
    }
    if (psalt_data.data) {
	memset(psalt_data.data, 0, (size_t) psalt_data.length);
	krb5_xfree(psalt_data.data);
    }
    if (asalt_data.data) {
	memset(asalt_data.data, 0, (size_t) asalt_data.length);
	krb5_xfree(asalt_data.data);
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_string_to_keys() = %d\n", kret));
    return(kret);
}

/*
 * key_encrypt_keys() - encrypt keys.
 */
krb5_error_code
key_encrypt_keys(kcontext, principal, primary, alternate, eprimary, ealternate)
    krb5_context	kcontext;
    krb5_principal	principal;
    krb5_keyblock	*primary;
    krb5_keyblock	*alternate;
    krb5_encrypted_keyblock	*eprimary;
    krb5_encrypted_keyblock	*ealternate;
{
    krb5_error_code	kret;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_encrypt_keys()\n"));

    kret = krb5_kdb_encrypt_key(kcontext,
				&master_encblock,
				primary,
				eprimary);
    if (kret)
	kret = krb5_kdb_encrypt_key(kcontext,
				    &master_encblock,
				    alternate,
				    ealternate);
 done:
    if (kret) {
	if (eprimary->contents) {
	    memset((char *) eprimary->contents, 0, (size_t) eprimary->length);
	    krb5_xfree(eprimary->contents);
	}
	if (ealternate->contents) {
	    memset((char *) ealternate->contents, 0,
		   (size_t) ealternate->length);
	    krb5_xfree(ealternate->contents);
	}
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_encrypt_keys() = %d\n", kret));
    return(kret);
}

/*
 * key_decrypt_keys() - decrypt keys.
 */
krb5_error_code
key_decrypt_keys(kcontext, principal, eprimary, ealternate, primary, alternate)
    krb5_context	kcontext;
    krb5_principal	principal;
    krb5_encrypted_keyblock	*eprimary;
    krb5_encrypted_keyblock	*ealternate;
    krb5_keyblock	*primary;
    krb5_keyblock	*alternate;
{
    krb5_error_code	kret;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_decrypt_keys()\n"));

    kret = krb5_kdb_decrypt_key(kcontext,
				&master_encblock,
				eprimary,
				primary);
    if (kret)
	kret = krb5_kdb_decrypt_key(kcontext,
				    &master_encblock,
				    ealternate,
				    alternate);
 done:
    if (kret) {
	if (primary->contents) {
	    memset((char *) primary->contents, 0, (size_t) primary->length);
	    krb5_xfree(primary->contents);
	}
	if (alternate->contents) {
	    memset((char *) alternate->contents, 0,
		   (size_t) alternate->length);
	    krb5_xfree(alternate->contents);
	}
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_decrypt_keys() = %d\n", kret));
    return(kret);
}

/*
 * key_pwd_is_weak()	- Check for weakness of key from password
 */
krb5_boolean
key_pwd_is_weak(kcontext, principal, string, psalttype, asalttype)
    krb5_context	kcontext;
    krb5_principal	principal;
    krb5_data		*string;
    krb5_int32		psalttype;
    krb5_int32		asalttype;
{
    krb5_boolean	weakness;
    krb5_error_code	kret;
    krb5_keyblock	primary;
    krb5_keyblock	alternate;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_pwd_is_weak()\n"));
    weakness = 0;

    if (master_encblock.key->etype != ETYPE_NULL) {
	memset((char *) &primary, 0, sizeof(primary));
	memset((char *) &alternate, 0, sizeof(alternate));

	kret = key_string_to_keys(kcontext,
				  principal,
				  string,
				  psalttype,
				  asalttype,
				  &primary,
				  &alternate);
	if (!kret) {
	    if (primary.length &&
		(primary.length == sizeof(mit_des_cblock)) &&
		mit_des_is_weak_key(primary.contents))
		weakness = 1;
	    if (alternate.length &&
		(alternate.length == sizeof(mit_des_cblock)) &&
		mit_des_is_weak_key(alternate.contents))
		weakness = 1;
	    if (primary.contents) {
		memset((char *) primary.contents, 0, (size_t) primary.length);
		krb5_xfree(primary.contents);
	    }
	    if (alternate.contents) {
		memset((char *) alternate.contents, 0,
		       (size_t) alternate.length);
		krb5_xfree(alternate.contents);
	    }
	}
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_pwd_is_weak() = %d\n", weakness));
    return(weakness);
}

