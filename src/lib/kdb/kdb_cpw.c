/*
 * lib/kdb/kdb_cpw.c
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

#include "k5-int.h"
#include "krb5/adm.h"
#include <stdio.h>
#include <errno.h>

static int
get_key_data_kvno(context, count, data)
    krb5_context	  context;
    int			  count;
    krb5_key_data	* data;
{
    int i, kvno;
    /* Find last key version number */
    for (kvno = i = 0; i < count; i++) {
	if (kvno < data[i].key_data_kvno) {
	    kvno = data[i].key_data_kvno;
	}
    }
    return(kvno);
}

static void
cleanup_key_data(context, count, data)
    krb5_context	  context;
    int			  count;
    krb5_key_data	* data;
{
    int i, j;

    for (i = 0; i < count; i++) {
	for (j = 0; j < data[i].key_data_ver; j++) {
	    if (data[i].key_data_length[j]) {
	    	free(data[i].key_data_contents[j]);
	    }
	}
    }
}

/*
 * Currently we can only generate random keys for preinitialized
 * krb5_encrypt_block with a seed. This is bogus but currently
 * necessary to insure that we don't generate two keys with the 
 * same data.
 */
static krb5_error_code
add_key_rnd(context, master_eblock, ks_tuple, ks_tuple_count, db_entry, kvno)
    krb5_context	  context;
    krb5_encrypt_block  * master_eblock;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    krb5_db_entry	* db_entry;
    int			  kvno;
{
    krb5_principal	  krbtgt_princ;
    krb5_keyblock	  krbtgt_keyblock, * key;
    krb5_pointer 	  krbtgt_seed;	
    krb5_encrypt_block	  krbtgt_eblock;
    krb5_db_entry	  krbtgt_entry;
    krb5_boolean	  more;
    int			  max_kvno, one, i, j;
    krb5_error_code	  retval;

    retval = krb5_build_principal_ext(context, &krbtgt_princ,
				      db_entry->princ->realm.length,
				      db_entry->princ->realm.data,
				      KRB5_TGS_NAME_SIZE,
				      KRB5_TGS_NAME,
				      db_entry->princ->realm.length,
				      db_entry->princ->realm.data);
    if (retval)
	return retval;

    /* Get tgt from database */
    retval = krb5_db_get_principal(context, krbtgt_princ, &krbtgt_entry,
				   &one, &more);
    krb5_free_principal(context, krbtgt_princ); /* don't need it anymore */
    if (retval)
	return(retval);
    if ((one > 1) || (more)) {
	krb5_db_free_principal(context, &krbtgt_entry, one);
	return KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
    }
    if (!one) 
	return KRB5_KDB_NOENTRY;

    /* Get max kvno */
    for (max_kvno = j = 0; j < krbtgt_entry.n_key_data; j++) {
	 if (max_kvno < krbtgt_entry.key_data[j].key_data_kvno) {
	     max_kvno = krbtgt_entry.key_data[j].key_data_kvno;
	}
    }

    for (i = 0; i < ks_tuple_count; i++) {
        if (retval = krb5_dbe_create_key_data(context, db_entry)) 
	    goto add_key_rnd_err;

	for (j = 0; j < krbtgt_entry.n_key_data; j++) {
	     if ((krbtgt_entry.key_data[j].key_data_kvno == max_kvno) &&
		 (krbtgt_entry.key_data[j].key_data_type[0] == 
		  ks_tuple[i].ks_keytype)) {
		break;
	    }
	}

	if (j == krbtgt_entry.n_key_data) {
	    retval = KRB5_KDB_BAD_KEYTYPE;
	    goto add_key_rnd_err;
	}

	/* Decrypt key */
    	if (retval = krb5_dbekd_decrypt_key_data(context, master_eblock, 
						 &krbtgt_entry.key_data[j],
						 &krbtgt_keyblock, NULL)) {
	    goto add_key_rnd_err;
	}

	/* Init key */
	krb5_use_keytype(context, &krbtgt_eblock, ks_tuple[i].ks_keytype);
	if (retval = krb5_process_key(context,&krbtgt_eblock,&krbtgt_keyblock)){
	    goto add_key_rnd_err;
	}

	/* Init random generator */
	if (retval = krb5_init_random_key(context, &krbtgt_eblock,
					  &krbtgt_keyblock, &krbtgt_seed)) {
	    krb5_finish_key(context, &krbtgt_eblock);
	    goto add_key_rnd_err;
	}

    	if (retval = krb5_random_key(context,&krbtgt_eblock,krbtgt_seed,&key)) {
	    krb5_finish_random_key(context, &krbtgt_eblock, &krbtgt_seed);
	    krb5_finish_key(context, &krbtgt_eblock);
	    goto add_key_rnd_err;
	}

	krb5_finish_random_key(context, &krbtgt_eblock, &krbtgt_seed);
	krb5_finish_key(context, &krbtgt_eblock);

    	if (retval = krb5_dbekd_encrypt_key_data(context, master_eblock, 
						 key, NULL, kvno + 1, 
						 db_entry->key_data)) {
    	    krb5_free_keyblock(context, key);
	    goto add_key_rnd_err;
	}

	/* Finish random key */
    	krb5_free_keyblock(context, key);
    }

add_key_rnd_err:;
    krb5_db_free_principal(context, &krbtgt_entry, one);
    return(retval);
}

/*
 * Change random key for a krb5_db_entry 
 * Assumes the max kvno
 *
 * As a side effect all old keys are nuked.
 */
krb5_error_code
krb5_dbe_crk(context, master_eblock, ks_tuple, ks_tuple_count, db_entry)
    krb5_context	  context;
    krb5_encrypt_block  * master_eblock;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    krb5_db_entry	* db_entry;
{
    int 		  key_data_count;
    krb5_key_data 	* key_data;
    krb5_error_code	  retval;
    int			  kvno;

    /* First save the old keydata */
    kvno = get_key_data_kvno(context, db_entry->n_key_data, db_entry->key_data);
    key_data_count = db_entry->n_key_data;
    key_data = db_entry->key_data;
    db_entry->key_data = NULL;
    db_entry->n_key_data = 0;

    if (retval = add_key_rnd(context, master_eblock, ks_tuple, 
			     ks_tuple_count, db_entry, kvno)) {
	cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
	db_entry->n_key_data = key_data_count;
	db_entry->key_data = key_data;
    } else {
	cleanup_key_data(context, key_data_count, key_data);
    }
    return(retval);
}

/*
 * Add random key for a krb5_db_entry 
 * Assumes the max kvno
 *
 * As a side effect all old keys older than the max kvno are nuked.
 */
krb5_error_code
krb5_dbe_ark(context, master_eblock, ks_tuple, ks_tuple_count, db_entry)
    krb5_context	  context;
    krb5_encrypt_block  * master_eblock;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    krb5_db_entry	* db_entry;
{
    int 		  key_data_count;
    krb5_key_data 	* key_data;
    krb5_error_code	  retval;
    int			  kvno;
    int			  i;

    /* First save the old keydata */
    kvno = get_key_data_kvno(context, db_entry->n_key_data, db_entry->key_data);
    key_data_count = db_entry->n_key_data;
    key_data = db_entry->key_data;
    db_entry->key_data = NULL;
    db_entry->n_key_data = 0;

    if (retval = add_key_rnd(context, master_eblock, ks_tuple, 
			     ks_tuple_count, db_entry, kvno)) {
	cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
	db_entry->n_key_data = key_data_count;
	db_entry->key_data = key_data;
    } else {
	/* Copy keys with key_data_kvno = kvno */
	for (i = 0; i < key_data_count; i++) {
	    if (key_data[i].key_data_kvno = kvno) {
		if (retval = krb5_dbe_create_key_data(context, db_entry)) {
		    cleanup_key_data(context, db_entry->n_key_data,
				     db_entry->key_data);
		    break;
		}
		/* We should decrypt/re-encrypt the data to use the same mkvno*/
		db_entry->key_data[db_entry->n_key_data - 1] = key_data[i];
		memset(&key_data[i], 0, sizeof(krb5_key_data));
	    }
	}
	cleanup_key_data(context, key_data_count, key_data);
    }
    return(retval);
}

/*
 * Add key_data for a krb5_db_entry 
 * If passwd is NULL the assumes that the caller wants a random password.
 */
static krb5_error_code
add_key_pwd(context, master_eblock, ks_tuple, ks_tuple_count, passwd, 
	    db_entry, kvno)
    krb5_context	  context;
    krb5_encrypt_block  * master_eblock;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    char 		* passwd;
    krb5_db_entry	* db_entry;
    int			  kvno;
{
    krb5_error_code	  retval;
    krb5_encrypt_block    key_eblock;
    krb5_keysalt	  key_salt;
    krb5_keyblock	  key;
    krb5_data	  	  pwd;
    int			  i;

    for (i = 0; i < ks_tuple_count; i++) {
	krb5_use_keytype(context, &key_eblock, ks_tuple[i].ks_keytype);
	if (retval = krb5_dbe_create_key_data(context, db_entry)) 
	    return(retval);

	/* Convert password string to key using appropriate salt */
	switch (key_salt.type = ks_tuple[i].ks_salttype) {
    	case KRB5_KDB_SALTTYPE_ONLYREALM: {
            krb5_data * saltdata;
            if (retval = krb5_copy_data(context, krb5_princ_realm(context,
					db_entry->princ), &saltdata))
	 	return(retval);

	    key_salt.data = *saltdata;
	    krb5_xfree(saltdata);
	}
    	case KRB5_KDB_SALTTYPE_NOREALM:
            if (retval=krb5_principal2salt_norealm(context, db_entry->princ,
                                                         &key_salt.data)) 
		return(retval);
            break;
	case KRB5_KDB_SALTTYPE_NORMAL:
            if (retval = krb5_principal2salt(context, db_entry->princ,
					         &key_salt.data)) 
		return(retval);
            break;
    	case KRB5_KDB_SALTTYPE_V4:
            key_salt.data.length = 0;
            key_salt.data.data = 0;
            break;
	default:
	    return(KRB5_KDB_BAD_SALTTYPE);
	}

    	pwd.data = passwd;
    	pwd.length = strlen(passwd);
	if (retval = krb5_string_to_key(context, &key_eblock, 
					ks_tuple[i].ks_keytype, &key,
					&pwd, &key_salt.data))
	    return(retval);

	if (retval = krb5_dbekd_encrypt_key_data(context, master_eblock, &key,
		     key_salt.type ? (const krb5_keysalt *)&key_salt : NULL,
		     kvno + 1, &db_entry->key_data[i])) {
	    krb5_xfree(key.contents);
	    return(retval);
	}
	krb5_xfree(key.contents);
    }
    return(retval);
}

/*
 * Change password for a krb5_db_entry 
 * Assumes the max kvno
 *
 * As a side effect all old keys are nuked.
 */
krb5_error_code
krb5_dbe_cpw(context, master_eblock, ks_tuple, ks_tuple_count, passwd, db_entry)
    krb5_context	  context;
    krb5_encrypt_block  * master_eblock;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    char 		* passwd;
    krb5_db_entry	* db_entry;
{
    int 		  key_data_count;
    krb5_key_data 	* key_data;
    krb5_error_code	  retval;
    int			  kvno;

    /* First save the old keydata */
    kvno = get_key_data_kvno(context, db_entry->n_key_data, db_entry->key_data);
    key_data_count = db_entry->n_key_data;
    key_data = db_entry->key_data;
    db_entry->key_data = NULL;
    db_entry->n_key_data = 0;

    if (retval = add_key_pwd(context, master_eblock, ks_tuple, ks_tuple_count,
			     passwd, db_entry, kvno)) {
	cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
	db_entry->n_key_data = key_data_count;
	db_entry->key_data = key_data;
    } else {
	cleanup_key_data(context, key_data_count, key_data);
    }
    return(retval);
}

/*
 * Add password for a krb5_db_entry 
 * Assumes the max kvno
 *
 * As a side effect all old keys older than the max kvno are nuked.
 */
krb5_error_code
krb5_dbe_apw(context, master_eblock, ks_tuple, ks_tuple_count, passwd, db_entry)
    krb5_context	  context;
    krb5_encrypt_block  * master_eblock;
    krb5_key_salt_tuple	* ks_tuple;
    int			  ks_tuple_count;
    char 		* passwd;
    krb5_db_entry	* db_entry;
{
    int 		  key_data_count;
    krb5_key_data 	* key_data;
    krb5_error_code	  retval;
    int			  kvno;
    int			  i;

    /* First save the old keydata */
    kvno = get_key_data_kvno(context, db_entry->n_key_data, db_entry->key_data);
    key_data_count = db_entry->n_key_data;
    key_data = db_entry->key_data;
    db_entry->key_data = NULL;
    db_entry->n_key_data = 0;

    if (retval = add_key_pwd(context, master_eblock, ks_tuple, ks_tuple_count,
			     passwd, db_entry, kvno)) {
	cleanup_key_data(context, db_entry->n_key_data, db_entry->key_data);
	db_entry->n_key_data = key_data_count;
	db_entry->key_data = key_data;
    } else {
	/* Copy keys with key_data_kvno = kvno */
	for (i = 0; i < key_data_count; i++) {
	    if (key_data[i].key_data_kvno = kvno) {
		if (retval = krb5_dbe_create_key_data(context, db_entry)) {
		    cleanup_key_data(context, db_entry->n_key_data,
				     db_entry->key_data);
		    break;
		}
		/* We should decrypt/re-encrypt the data to use the same mkvno*/
		db_entry->key_data[db_entry->n_key_data - 1] = key_data[i];
		memset(&key_data[i], 0, sizeof(krb5_key_data));
	    }
	}
	cleanup_key_data(context, key_data_count, key_data);
    }
    return(retval);
}
