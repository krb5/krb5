/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/kdb/kdb_default.c */
/*
 * Copyright 1995, 2009 by the Massachusetts Institute of Technology.
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
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
    krb5_context        kcontext;
    krb5_db_entry       *dbentp;
    krb5_int32          *start;
    krb5_int32          ktype;
    krb5_int32          stype;
    krb5_int32          kvno;
    krb5_key_data       **kdatap;
{
    int                 i, idx;
    int                 maxkvno;
    krb5_key_data       *datap;
    krb5_error_code     ret;
    krb5_boolean        saw_non_permitted = FALSE;

    ret = 0;
    if (ktype != -1 && !krb5_is_permitted_enctype(kcontext, ktype))
        return KRB5_KDB_NO_PERMITTED_KEY;

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
    idx = -1;
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

        /* Match this entry against the arguments. */
        if (ktype != -1) {
            ret = krb5_c_enctype_compare(kcontext, (krb5_enctype) ktype,
                                         dbentp->key_data[i].key_data_type[0],
                                         &similar);
            if (ret != 0 || !similar)
                continue;
        }
        if (stype >= 0 && db_stype != stype)
            continue;
        if (kvno >= 0 && dbentp->key_data[i].key_data_kvno != kvno)
            continue;

        /* Filter out non-permitted enctypes. */
        if (!krb5_is_permitted_enctype(kcontext,
                                       dbentp->key_data[i].key_data_type[0])) {
            saw_non_permitted = TRUE;
            continue;
        }

        if (dbentp->key_data[i].key_data_kvno > maxkvno) {
            maxkvno = dbentp->key_data[i].key_data_kvno;
            datap = &dbentp->key_data[i];
            idx = i;
        }
    }
    /* If we scanned the whole set of keys and matched only non-permitted
     * enctypes, indicate that. */
    if (maxkvno < 0 && *start == 0 && saw_non_permitted)
        ret = KRB5_KDB_NO_PERMITTED_KEY;
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
krb5_def_store_mkey_list(krb5_context       context,
                         char               *keyfile,
                         krb5_principal     mname,
                         krb5_keylist_node  *keylist,
                         char               *master_pwd)
{
    krb5_error_code retval = 0;
    char defkeyfile[MAXPATHLEN+1];
    char *tmp_ktname = NULL, *tmp_ktpath;
    krb5_data *realm = krb5_princ_realm(context, mname);
    krb5_keytab kt = NULL;
    krb5_keytab_entry new_entry;
    struct stat stb;
    int statrc;

    if (!keyfile) {
        (void) snprintf(defkeyfile, sizeof(defkeyfile), "%s%s",
                        DEFAULT_KEYFILE_STUB, realm->data);
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
            krb5_set_error_message(context, retval,
                                   _("keyfile (%s) is not a regular file: %s"),
                                   keyfile, error_message(retval));
            goto out;
        }
    }

    /* Use temp keytab file name in case creation of keytab fails */

    /* create temp file template for use by mktemp() */
    if ((retval = asprintf(&tmp_ktname, "WRFILE:%s_XXXXXX", keyfile)) < 0) {
        krb5_set_error_message(context, retval,
                               _("Could not create temp keytab file name."));
        goto out;
    }

    /*
     * Set tmp_ktpath to point to the keyfile path (skip WRFILE:).  Subtracting
     * 1 to account for NULL terminator in sizeof calculation of a string
     * constant.  Used further down.
     */
    tmp_ktpath = tmp_ktname + (sizeof("WRFILE:") - 1);

    if (mktemp(tmp_ktpath) == NULL) {
        retval = errno;
        krb5_set_error_message(context, retval,
                               _("Could not create temp stash file: %s"),
                               error_message(errno));
        goto out;
    }

    /* create new stash keytab using temp file name */
    retval = krb5_kt_resolve(context, tmp_ktname, &kt);
    if (retval != 0)
        goto out;

    while (keylist && !retval) {
        memset(&new_entry, 0, sizeof(new_entry));
        new_entry.principal = mname;
        new_entry.key = keylist->keyblock;
        new_entry.vno = keylist->kvno;

        retval = krb5_kt_add_entry(context, kt, &new_entry);
        keylist = keylist->next;
    }
    krb5_kt_close(context, kt);

    if (retval != 0) {
        /* delete tmp keyfile if it exists and an error occurrs */
        if (stat(keyfile, &stb) >= 0)
            (void) unlink(tmp_ktpath);
    } else {
        /* rename original keyfile to original filename */
        if (rename(tmp_ktpath, keyfile) < 0) {
            retval = errno;
            krb5_set_error_message(context, retval,
                                   _("rename of temporary keyfile (%s) to "
                                     "(%s) failed: %s"), tmp_ktpath, keyfile,
                                   error_message(errno));
        }
    }

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
        zap(key->contents, key->length);
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

static krb5_error_code
krb5_db_def_fetch_mkey_keytab(krb5_context   context,
                              const char     *keyfile,
                              krb5_principal mname,
                              krb5_keyblock  *key,
                              krb5_kvno      *kvno)
{
    krb5_error_code retval = 0;
    krb5_keytab kt = NULL;
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
    if (kt)
        krb5_kt_close(context, kt);

    return retval;
}

krb5_error_code
krb5_db_def_fetch_mkey(krb5_context   context,
                       krb5_principal mname,
                       krb5_keyblock *key,
                       krb5_kvno     *kvno,
                       char          *db_args)
{
    krb5_error_code retval;
    char keyfile[MAXPATHLEN+1];
    krb5_data *realm = krb5_princ_realm(context, mname);

    key->magic = KV5M_KEYBLOCK;

    if (db_args != NULL) {
        (void) strncpy(keyfile, db_args, sizeof(keyfile));
    } else {
        (void) snprintf(keyfile, sizeof(keyfile), "%s%s",
                        DEFAULT_KEYFILE_STUB, realm->data);
    }
    /* null terminate no matter what */
    keyfile[sizeof(keyfile) - 1] = '\0';

    /* Try the keytab and old stash file formats. */
    retval = krb5_db_def_fetch_mkey_keytab(context, keyfile, mname, key, kvno);
    if (retval == KRB5_KEYTAB_BADVNO)
        retval = krb5_db_def_fetch_mkey_stash(context, keyfile, key, kvno);

    /*
     * Use a generic error code for failure to retrieve the master
     * key, but set a message indicating the actual error.
     */
    if (retval != 0) {
        krb5_set_error_message(context, KRB5_KDB_CANTREAD_STORED,
                               _("Can not fetch master key (error: %s)."),
                               error_message(retval));
        return KRB5_KDB_CANTREAD_STORED;
    } else
        return 0;
}

krb5_error_code
krb5_def_fetch_mkey_list(krb5_context        context,
                         krb5_principal        mprinc,
                         const krb5_keyblock  *mkey,
                         krb5_keylist_node  **mkeys_list)
{
    krb5_error_code retval;
    krb5_db_entry *master_entry;
    krb5_boolean found_key = FALSE;
    krb5_keyblock cur_mkey;
    krb5_keylist_node *mkey_list_head = NULL, **mkey_list_node;
    krb5_key_data *key_data;
    krb5_mkey_aux_node  *mkey_aux_data_list = NULL, *aux_data_entry;
    int i;

    if (mkeys_list == NULL)
        return (EINVAL);

    memset(&cur_mkey, 0, sizeof(cur_mkey));

    retval = krb5_db_get_principal(context, mprinc, 0, &master_entry);
    if (retval == KRB5_KDB_NOENTRY)
        return (KRB5_KDB_NOMASTERKEY);
    if (retval)
        return (retval);

    /*
     * Check if the input mkey is the latest key and if it isn't then find the
     * latest mkey.
     */

    if (mkey->enctype == master_entry->key_data[0].key_data_type[0]) {
        if (krb5_dbe_decrypt_key_data(context, mkey,
                                      &master_entry->key_data[0],
                                      &cur_mkey, NULL) == 0) {
            found_key = TRUE;
        }
    }

    if (!found_key) {
        if ((retval = krb5_dbe_lookup_mkey_aux(context, master_entry,
                                               &mkey_aux_data_list)))
            goto clean_n_exit;

        for (aux_data_entry = mkey_aux_data_list; aux_data_entry != NULL;
             aux_data_entry = aux_data_entry->next) {

            if (krb5_dbe_decrypt_key_data(context, mkey,
                                          &aux_data_entry->latest_mkey,
                                          &cur_mkey, NULL) == 0) {
                found_key = TRUE;
                break;
            }
        }
        if (found_key != TRUE) {
            krb5_set_error_message(context, KRB5_KDB_BADMASTERKEY,
                                   _("Unable to decrypt latest master key "
                                     "with the provided master key\n"));
            retval = KRB5_KDB_BADMASTERKEY;
            goto clean_n_exit;
        }
    }

    /*
     * Extract all the mkeys from master_entry using the most current mkey and
     * create a mkey list for the mkeys field in kdc_realm_t.
     */

    mkey_list_head = (krb5_keylist_node *) malloc(sizeof(krb5_keylist_node));
    if (mkey_list_head == NULL) {
        retval = ENOMEM;
        goto clean_n_exit;
    }

    memset(mkey_list_head, 0, sizeof(krb5_keylist_node));

    /* Set mkey_list_head to the current mkey as an optimization. */
    /* mkvno may not be latest so ... */
    mkey_list_head->kvno = master_entry->key_data[0].key_data_kvno;
    /* this is the latest clear mkey (avoids a redundant decrypt) */
    mkey_list_head->keyblock = cur_mkey;

    /* loop through any other master keys creating a list of krb5_keylist_nodes */
    mkey_list_node = &mkey_list_head->next;
    for (i = 1; i < master_entry->n_key_data; i++) {
        if (*mkey_list_node == NULL) {
            /* *mkey_list_node points to next field of previous node */
            *mkey_list_node = (krb5_keylist_node *) malloc(sizeof(krb5_keylist_node));
            if (*mkey_list_node == NULL) {
                retval = ENOMEM;
                goto clean_n_exit;
            }
            memset(*mkey_list_node, 0, sizeof(krb5_keylist_node));
        }
        key_data = &master_entry->key_data[i];
        retval = krb5_dbe_decrypt_key_data(context, &cur_mkey, key_data,
                                           &((*mkey_list_node)->keyblock),
                                           NULL);
        if (retval)
            goto clean_n_exit;

        (*mkey_list_node)->kvno = key_data->key_data_kvno;
        mkey_list_node = &((*mkey_list_node)->next);
    }

    *mkeys_list = mkey_list_head;

clean_n_exit:
    krb5_db_free_principal(context, master_entry);
    krb5_dbe_free_mkey_aux_list(context, mkey_aux_data_list);
    if (retval != 0)
        krb5_dbe_free_key_list(context, mkey_list_head);
    return retval;
}
