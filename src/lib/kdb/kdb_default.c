/*
 * lib/kdb/kdb_helper.c
 *
 * Copyright 1995, 2008 by the Massachusetts Institute of Technology. 
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */

#include "k5-int.h"
#include "kdb.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>


/*
 * Given a particular enctype and optional salttype and kvno, find the
 * most appropriate krb5_key_data entry of the database entry.
 *
 * If stype or kvno is negative, it is ignored.
 * If kvno is 0 get the key which is maxkvno for the princ and matches
 * the other attributes.
 */
krb5_error_code
krb5_dbe_def_search_enctype(kcontext, dbentp, start, ktype, stype, kvno, kdatap)
    krb5_context	kcontext;
    krb5_db_entry	*dbentp;
    krb5_int32		*start;
    krb5_int32		ktype;
    krb5_int32		stype;
    krb5_int32		kvno;
    krb5_key_data	**kdatap;
{
    int			i, idx;
    int			maxkvno;
    krb5_key_data	*datap;
    krb5_error_code	ret;

    ret = 0;
    if (kvno == -1 && stype == -1 && ktype == -1)
	kvno = 0;

    if (kvno == 0) { 
	/* Get the max key version */
	for (i = 0; i < dbentp->n_key_data; i++) {
	    if (kvno < dbentp->key_data[i].key_data_kvno) { 
		kvno = dbentp->key_data[i].key_data_kvno;
	    }
	}
    }

    maxkvno = -1;
    datap = (krb5_key_data *) NULL;
    for (i = *start; i < dbentp->n_key_data; i++) {
        krb5_boolean    similar;
        krb5_int32      db_stype;

	ret = 0;
	if (dbentp->key_data[i].key_data_ver > 1) {
	    db_stype = dbentp->key_data[i].key_data_type[1];
	} else {
	    db_stype = KRB5_KDB_SALTTYPE_NORMAL;
	}

	/*
	 * Filter out non-permitted enctypes.
	 */
	if (!krb5_is_permitted_enctype(kcontext,
				       dbentp->key_data[i].key_data_type[0])) {
	    ret = KRB5_KDB_NO_PERMITTED_KEY;
	    continue;
	}
	

	if (ktype > 0) {
	    if ((ret = krb5_c_enctype_compare(kcontext, (krb5_enctype) ktype,
					      dbentp->key_data[i].key_data_type[0],
					      &similar)))

		return(ret);
	}

	if (((ktype <= 0) || similar) &&
	    ((db_stype == stype) || (stype < 0))) {
	    if (kvno >= 0) {
		if (kvno == dbentp->key_data[i].key_data_kvno) {
		    datap = &dbentp->key_data[i];
		    idx = i;
		    maxkvno = kvno;
		    break;
		}
	    } else {
		if (dbentp->key_data[i].key_data_kvno > maxkvno) {
		    maxkvno = dbentp->key_data[i].key_data_kvno;
		    datap = &dbentp->key_data[i];
		    idx = i;
		}
	    }
	}
    }
    if (maxkvno < 0)
	return ret ? ret : KRB5_KDB_NO_MATCHING_KEY;
    *kdatap = datap;
    *start = idx+1;
    return 0;
}
    
/*
 *  kdb default functions. Ideally, some other file should have this functions. For now, TBD.
 */
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

krb5_error_code
krb5_def_store_mkey(krb5_context   context,
                    char           *keyfile,
                    krb5_principal mname,
                    krb5_kvno      kvno,
                    krb5_keyblock  *key,
                    char           *master_pwd)
{
    krb5_error_code retval = 0;
    char defkeyfile[MAXPATHLEN+1];
    char *tmp_ktname = NULL, *tmp_ktpath;
    krb5_data *realm = krb5_princ_realm(context, mname);
#ifndef LEAN_CLIENT 
    krb5_keytab kt;
    krb5_keytab_entry new_entry;
#endif /* LEAN_CLIENT */
    struct stat stb;
    int statrc;

    if (!keyfile) {
        (void) strcpy(defkeyfile, DEFAULT_KEYFILE_STUB);
        (void) strncat(defkeyfile, realm->data,
            min(sizeof(defkeyfile)-sizeof(DEFAULT_KEYFILE_STUB)-1,
                realm->length));
        defkeyfile[sizeof(defkeyfile) - 1] = '\0';
        keyfile = defkeyfile;
    }

    /*
     * XXX making the assumption that the keyfile is in a dir that requires root
     * privilege to write to thus making timing attacks unlikely.
     */
    if ((statrc = stat(keyfile, &stb)) >= 0) {
        /* if keyfile exists it better be a regular file */
        if (!S_ISREG(stb.st_mode)) {
            retval = EINVAL;
            krb5_set_error_message (context, retval,
                "keyfile (%s) is not a regular file: %s",
                keyfile, error_message(retval));
            goto out;
        }
    }

    /* Use temp keytab file name in case creation of keytab fails */

    /* create temp file template for use by mktemp() */
    if ((retval = asprintf(&tmp_ktname, "WRFILE:%s_XXXXXX", keyfile)) < 0) {
        krb5_set_error_message (context, retval,
            "Could not create temp keytab file name.");
        goto out;
    }

    if (mktemp(tmp_ktname) == NULL) {
        retval = errno;
        krb5_set_error_message (context, retval,
            "Could not create temp stash file: %s",
            error_message(errno));
        goto out;
    }

#ifndef LEAN_CLIENT 
    /* create new stash keytab using temp file name */
    retval = krb5_kt_resolve(context, tmp_ktname, &kt);
    if (retval != 0)
        goto out;

    memset((char *) &new_entry, 0, sizeof(new_entry));
    new_entry.principal = mname;
    new_entry.key = *key;
    new_entry.vno = kvno;
#endif /* LEAN_CLIENT */
    /*
     * Set tmp_ktpath to point to the keyfile path (skip WRFILE:).  Subtracting
     * 1 to account for NULL terminator in sizeof calculation of a string
     * constant.  Used further down.
     */
    tmp_ktpath = tmp_ktname + (sizeof("WRFILE:") - 1);

#ifndef LEAN_CLIENT 
    retval = krb5_kt_add_entry(context, kt, &new_entry);
    if (retval != 0) {
        /* delete tmp keyfile if it exists and an error occurrs */
        if (stat(keyfile, &stb) >= 0)
            (void) unlink(tmp_ktpath);
    } else {
        /* rename original keyfile to original filename */
        if (rename(tmp_ktpath, keyfile) < 0) {
            retval = errno;
            krb5_set_error_message (context, retval,
                "rename of temporary keyfile (%s) to (%s) failed: %s",
                tmp_ktpath, keyfile, error_message(errno));
        }
    }
#endif /* LEAN_CLIENT */

out:
    if (tmp_ktname != NULL)
        free(tmp_ktname);

    return retval;
}

static krb5_error_code
krb5_db_def_fetch_mkey_stash(krb5_context   context,
			     const char *keyfile,
			     krb5_keyblock *key,
			     krb5_kvno     *kvno)
{
    krb5_error_code retval = 0;
    krb5_ui_2 enctype;
    krb5_ui_4 keylength;
    FILE *kf = NULL;

#ifdef ANSI_STDIO
    if (!(kf = fopen(keyfile, "rb")))
#else
    if (!(kf = fopen(keyfile, "r")))
#endif
	return KRB5_KDB_CANTREAD_STORED;
    set_cloexec_file(kf);

    if (fread((krb5_pointer) &enctype, 2, 1, kf) != 1) {
	retval = KRB5_KDB_CANTREAD_STORED;
	goto errout;
    }

#if BIG_ENDIAN_MASTER_KEY
    enctype = ntohs((uint16_t) enctype);
#endif

    if (key->enctype == ENCTYPE_UNKNOWN)
	key->enctype = enctype;
    else if (enctype != key->enctype) {
	retval = KRB5_KDB_BADSTORED_MKEY;
	goto errout;
    }

    if (fread((krb5_pointer) &keylength,
	      sizeof(keylength), 1, kf) != 1) {
	retval = KRB5_KDB_CANTREAD_STORED;
	goto errout;
    }

#if BIG_ENDIAN_MASTER_KEY
    key->length = ntohl((uint32_t) keylength);
#else
    key->length = keylength;
#endif

    if (!key->length || ((int) key->length) < 0) {
	retval = KRB5_KDB_BADSTORED_MKEY;
	goto errout;
    }
	
    if (!(key->contents = (krb5_octet *)malloc(key->length))) {
	retval = ENOMEM;
	goto errout;
    }

    if (fread((krb5_pointer) key->contents, sizeof(key->contents[0]),
					    key->length, kf) != key->length) {
	retval = KRB5_KDB_CANTREAD_STORED;
	memset(key->contents, 0,  key->length);
	free(key->contents);
	key->contents = 0;
    } else
	retval = 0;

    /*
     * Note, the old stash format did not store the kvno and at this point it
     * can be assumed to be 1 as is the case for the mkey princ.  If the kvno is
     * passed in and isn't ignore_vno just leave it alone as this could cause
     * verifcation trouble if the mkey princ is using a kvno other than 1.
     */
    if (kvno && *kvno == IGNORE_VNO)
	*kvno = 1;

 errout:
    (void) fclose(kf);
    return retval;
}

#ifndef LEAN_CLIENT 
static krb5_error_code
krb5_db_def_fetch_mkey_keytab(krb5_context   context,
                              const char     *keyfile,
                              krb5_principal mname,
                              krb5_keyblock  *key,
                              krb5_kvno      *kvno)
{
    krb5_error_code retval = 0;
    krb5_keytab kt;
    krb5_keytab_entry kt_ent;
    krb5_enctype enctype = IGNORE_ENCTYPE;

    if ((retval = krb5_kt_resolve(context, keyfile, &kt)) != 0)
        goto errout;

    /* override default */
    if (key->enctype != ENCTYPE_UNKNOWN)
        enctype = key->enctype;

    if ((retval = krb5_kt_get_entry(context, kt, mname,
                                    kvno ? *kvno : IGNORE_VNO,
                                    enctype,
                                    &kt_ent)) == 0) {

        if (key->enctype == ENCTYPE_UNKNOWN)
            key->enctype = kt_ent.key.enctype;

        if (((int) kt_ent.key.length) < 0) {
            retval = KRB5_KDB_BADSTORED_MKEY;
            krb5_kt_free_entry(context, &kt_ent);
            goto errout;
        }

        key->length = kt_ent.key.length;

        /*
         * If a kvno pointer was passed in and it dereferences the
         * IGNORE_VNO value then it should be assigned the value of the kvno
         * found in the keytab otherwise the KNVO specified should be the
         * same as the one returned from the keytab.
         */
        if (kvno != NULL && *kvno == IGNORE_VNO)
            *kvno = kt_ent.vno;

        /*
         * kt_ent will be free'd so need to allocate and copy key contents for
         * output to caller.
         */
        if (!(key->contents = (krb5_octet *)malloc(key->length))) {
            retval = ENOMEM;
            krb5_kt_free_entry(context, &kt_ent);
            goto errout;
        }
        memcpy(key->contents, kt_ent.key.contents, kt_ent.key.length);
        krb5_kt_free_entry(context, &kt_ent);
    }

errout:
    return retval;
}
#endif /* LEAN_CLIENT */

krb5_error_code
krb5_db_def_fetch_mkey(krb5_context   context,
                       krb5_principal mname,
                       krb5_keyblock *key,
                       krb5_kvno     *kvno,
                       char          *db_args)
{
    krb5_error_code retval_ofs = 0, retval_kt = 0;
    char keyfile[MAXPATHLEN+1];
    krb5_data *realm = krb5_princ_realm(context, mname);

    key->magic = KV5M_KEYBLOCK;

    if (db_args != NULL) {
        (void) strncpy(keyfile, db_args, sizeof(keyfile));
    } else {
        (void) strcpy(keyfile, DEFAULT_KEYFILE_STUB);
        (void) strncat(keyfile, realm->data,
            min(sizeof(keyfile)-sizeof(DEFAULT_KEYFILE_STUB)-1,
                realm->length));
    }
    /* null terminate no matter what */
    keyfile[sizeof(keyfile) - 1] = '\0';

#ifndef LEAN_CLIENT 
    /* assume the master key is in a keytab */
    retval_kt = krb5_db_def_fetch_mkey_keytab(context, keyfile, mname, key, kvno);
    if (retval_kt != 0) {
#endif /* LEAN_CLIENT */
        /*
         * If it's not in a keytab, fall back and try getting the mkey from the
         * older stash file format.
         */
        retval_ofs = krb5_db_def_fetch_mkey_stash(context, keyfile, key, kvno);
#ifndef LEAN_CLIENT 
    }
#endif /* LEAN_CLIENT */

    if (retval_kt != 0 && retval_ofs != 0) {
        /*
         * Error, not able to get mkey from either file format.  Note, in order
         * to try to return a more correct error, the logic below is assuming
         * that if either of the stash reading functions returned
         * KRB5_KDB_BADSTORED_MKEY then this is probably the real error.
         */
        krb5_set_error_message (context, KRB5_KDB_CANTREAD_STORED,
            "Can not fetch master key either from keytab (error: %s) or old "
            "format (error %s).", error_message(retval_kt),
            error_message(retval_ofs));
        return KRB5_KDB_CANTREAD_STORED;
    } else {
        return 0;
    }
}

krb5_error_code
krb5_def_verify_master_key(krb5_context    context,
                           krb5_principal  mprinc,
                           krb5_kvno       kvno,
                           krb5_keyblock   *mkey)
{
    krb5_error_code retval;
    krb5_db_entry master_entry;
    int nprinc;
    krb5_boolean more;
    krb5_keyblock tempkey;

    nprinc = 1;
    if ((retval = krb5_db_get_principal(context, mprinc,
					&master_entry, &nprinc, &more)))
	return(retval);
	
    if (nprinc != 1) {
	if (nprinc)
	    krb5_db_free_principal(context, &master_entry, nprinc);
	return(KRB5_KDB_NOMASTERKEY);
    } else if (more) {
	krb5_db_free_principal(context, &master_entry, nprinc);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    }	

    if ((retval = krb5_dbekd_decrypt_key_data(context, mkey, 
					      &master_entry.key_data[0],
					      &tempkey, NULL))) {
	krb5_db_free_principal(context, &master_entry, nprinc);
	return retval;
    }

    if (mkey->length != tempkey.length ||
	memcmp((char *)mkey->contents,
	       (char *)tempkey.contents,mkey->length)) {
	retval = KRB5_KDB_BADMASTERKEY;
    }

    if (kvno != IGNORE_VNO &&
        kvno != (krb5_kvno) master_entry.key_data->key_data_kvno) {
        retval = KRB5_KDB_BADMASTERKEY;
        krb5_set_error_message (context, retval,
            "User specified mkeyVNO (%u) does not match master key princ's KVNO (%u)",
            kvno, master_entry.key_data->key_data_kvno);
    }

    memset((char *)tempkey.contents, 0, tempkey.length);
    krb5_xfree(tempkey.contents);
    krb5_db_free_principal(context, &master_entry, nprinc);
    
    return retval;
}


krb5_error_code kdb_def_set_mkey ( krb5_context kcontext,
				   char *pwd,
				   krb5_keyblock *key )
{
    /* printf("default set master key\n"); */
    return 0;
}

krb5_error_code kdb_def_get_mkey ( krb5_context kcontext,
				   krb5_keyblock **key )
{
    /* printf("default get master key\n"); */
    return 0;
}

krb5_error_code krb5_def_promote_db (krb5_context kcontext,
				     char *s, char **args)
{
    /* printf("default promote_db\n"); */
    return KRB5_PLUGIN_OP_NOTSUPP;
}
