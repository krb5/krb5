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

static int key_debug_level = 0;

extern char *programname;

/*
 * key_init()	- Initialize key context.
 */
krb5_error_code
key_init(kcontext, debug_level, enc_type, key_type, master_key_name, manual,
	 db_file, db_realm, kt_name)
    krb5_context	kcontext;
    int			debug_level;
    int			enc_type;
    int			key_type;
    char		*master_key_name;
    int			manual;
    char		*db_file;
    char		*db_realm;
    char		*kt_name;
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
			      0,		/* No salt */
			      &master_keyblock);
    if (kret) {
	fprintf(stderr, key_get_mkey_fmt, programname,
		error_message(kret));
	goto cleanup;
    }
    mencb_init = 1;
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
    krb5_db_fini(kcontext);
    /* memset((char *) tgs_key.contents, 0, tgs_key.length); */
    DPRINT(DEBUG_CALLS, key_debug_level, ("X key_finish()\n"));
}

/*
 * key_string_to_keys() - convert string to keys.
 */
krb5_error_code
key_string_to_keys(kcontext, principal, string, psalttype, asalttype,
		   primary, alternate, psaltdatap, asaltdatap)
    krb5_context	kcontext;
    krb5_principal	principal;
    krb5_data		*string;
    krb5_int32		psalttype;
    krb5_int32		asalttype;
    krb5_keyblock	*primary;
    krb5_keyblock	*alternate;
    krb5_data		*psaltdatap;
    krb5_data		*asaltdatap;
{
    krb5_error_code	kret;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_string_to_keys()\n"));
    kret = KRB_ERR_GENERIC;
    psaltdatap->length = asaltdatap->length = 0;
    psaltdatap->data = asaltdatap->data = (char *) NULL;

    /*
     * Determine the primary salt type.
     */
    switch (psalttype) {
    case KRB5_KDB_SALTTYPE_NORMAL:
	/* Normal salt */
	if (kret = krb5_principal2salt(kcontext, principal, psaltdatap))
	    goto done;
	asaltdatap->data = (char *) NULL;
	asaltdatap->length = 0;
	break;
    case KRB5_KDB_SALTTYPE_V4:
	/* V4 salt */
	psaltdatap->data = (char *) NULL;
	psaltdatap->length = 0;
	if (kret = krb5_principal2salt(kcontext, principal, asaltdatap))
	    goto done;
	break;
    case KRB5_KDB_SALTTYPE_NOREALM:
	if (kret = krb5_principal2salt_norealm(kcontext,
					       principal,
					       psaltdatap))
	    goto done;
	asaltdatap->data = (char *) NULL;
	asaltdatap->length = 0;
	break;
    case KRB5_KDB_SALTTYPE_ONLYREALM:
    {
	krb5_data	*tmp;

	if (kret = krb5_copy_data(kcontext,
				  krb5_princ_realm(kcontext, principal),
				  &tmp))
	    goto done;
	*psaltdatap = *tmp;
	krb5_xfree(tmp);
	asaltdatap->data = (char *) NULL;
	asaltdatap->length = 0;
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
			      psaltdatap);
    if (!kret)
	kret = krb5_string_to_key(kcontext,
				  &master_encblock,
				  master_keyblock.keytype,
				  alternate,
				  string,
				  asaltdatap);

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
	if (psaltdatap->data) {
	    memset(psaltdatap->data, 0, (size_t) psaltdatap->length);
	    krb5_xfree(psaltdatap->data);
	    psaltdatap->data = (char *) NULL;
	}
	if (asaltdatap->data) {
	    memset(asaltdatap->data, 0, (size_t) asaltdatap->length);
	    krb5_xfree(asaltdatap->data);
	    asaltdatap->data = (char *) NULL;
	}
    }
    DPRINT(DEBUG_CALLS, key_debug_level,
	   ("X key_string_to_keys() = %d\n", kret));
    return(kret);
}

/*
 * key_random_key()	- generate a random key.
 */
krb5_error_code
key_random_key(kcontext, rkeyp)
    krb5_context	kcontext;
    krb5_keyblock	*rkeyp;
{
    krb5_error_code	kret;
    krb5_keyblock	*tmp;
    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_random_key()\n"));

    tmp = (krb5_keyblock *) NULL;
    kret = krb5_random_key(kcontext, &master_encblock, master_random, &tmp);
    if (tmp) {
	memcpy(rkeyp, tmp, sizeof(krb5_keyblock));
	krb5_xfree(tmp);
    }
    DPRINT(DEBUG_CALLS, key_debug_level, ("X key_random_key()=%d\n", kret));
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
    krb5_data		psalt, asalt;

    DPRINT(DEBUG_CALLS, key_debug_level, ("* key_pwd_is_weak()\n"));
    weakness = 0;

    if (master_encblock.key->etype != ETYPE_NULL) {
	memset((char *) &primary, 0, sizeof(primary));
	memset((char *) &alternate, 0, sizeof(alternate));
	memset((char *) &psalt, 0, sizeof(psalt));
	memset((char *) &asalt, 0, sizeof(asalt));

	kret = key_string_to_keys(kcontext,
				  principal,
				  string,
				  psalttype,
				  asalttype,
				  &primary,
				  &alternate,
				  &psalt,
				  &asalt);
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
	    if (psalt.data) {
		memset((char *) psalt.data, 0, (size_t) psalt.length);
		krb5_xfree(psalt.data);
	    }
	    if (asalt.data) {
		memset((char *) asalt.data, 0, (size_t) asalt.length);
		krb5_xfree(asalt.data);
	    }
	}
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
