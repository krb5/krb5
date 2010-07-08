/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include <stdio.h>
#include <stdlib.h>
#include "k5-int.h"
#include <kadm5/admin.h>
#include "server_internal.h"

krb5_principal      master_princ;
krb5_keyblock       master_keyblock; /* local mkey */
krb5_keylist_node  *master_keylist = NULL;
krb5_actkvno_node   *active_mkey_list = NULL;
krb5_db_entry       master_db;

krb5_principal      hist_princ;

/* much of this code is stolen from the kdc.  there should be some
   library code to deal with this. */

krb5_error_code kdb_init_master(kadm5_server_handle_t handle,
                                char *r, int from_keyboard)
{
    int            ret = 0;
    char           *realm;
    krb5_boolean   from_kbd = FALSE;
    krb5_kvno       mkvno = IGNORE_VNO;

    if (from_keyboard)
        from_kbd = TRUE;

    if (r == NULL)  {
        if ((ret = krb5_get_default_realm(handle->context, &realm)))
            return ret;
    } else {
        realm = r;
    }

    if ((ret = krb5_db_setup_mkey_name(handle->context,
                                       handle->params.mkey_name,
                                       realm, NULL, &master_princ)))
        goto done;

    master_keyblock.enctype = handle->params.enctype;

    /*
     * Fetch the local mkey, may not be the latest but that's okay because we
     * really want the list of all mkeys and those can be retrieved with any
     * valid mkey.
     */
    ret = krb5_db_fetch_mkey(handle->context, master_princ,
                             master_keyblock.enctype, from_kbd,
                             FALSE /* only prompt once */,
                             handle->params.stash_file,
                             &mkvno  /* get the kvno of the returned mkey */,
                             NULL /* I'm not sure about this,
                                     but it's what the kdc does --marc */,
                             &master_keyblock);
    if (ret)
        goto done;

    if ((ret = krb5_db_fetch_mkey_list(handle->context, master_princ,
                                       &master_keyblock, mkvno, &master_keylist))) {
        krb5_db_fini(handle->context);
        return (ret);
    }

    if ((ret = krb5_dbe_fetch_act_key_list(handle->context, master_princ,
                                           &active_mkey_list))) {
        krb5_db_fini(handle->context);
        return (ret);
    }

done:
    if (r == NULL)
        free(realm);

    return(ret);
}

/*
 * Function: kdb_init_hist
 *
 * Purpose: Initializes the hist_princ variable.
 *
 * Arguments:
 *
 *      handle          (r) kadm5 api server handle
 *      r               (r) realm of history principal to use, or NULL
 *
 * Effects: This function sets the value of the hist_princ global variable.
 */
krb5_error_code kdb_init_hist(kadm5_server_handle_t handle, char *r)
{
    int     ret = 0;
    char    *realm, *hist_name;

    if (r == NULL)  {
        if ((ret = krb5_get_default_realm(handle->context, &realm)))
            return ret;
    } else {
        realm = r;
    }

    if (asprintf(&hist_name, "%s@%s", KADM5_HIST_PRINCIPAL, realm) < 0) {
        hist_name = NULL;
        goto done;
    }

    if ((ret = krb5_parse_name(handle->context, hist_name, &hist_princ)))
        goto done;

done:
    free(hist_name);
    if (r == NULL)
        free(realm);
    return ret;
}

static krb5_error_code
create_hist(kadm5_server_handle_t handle)
{
    kadm5_ret_t ret;
    krb5_key_salt_tuple ks[1];
    kadm5_principal_ent_rec ent;
    long mask = KADM5_PRINCIPAL | KADM5_MAX_LIFE | KADM5_ATTRIBUTES;

    /* Create the history principal. */
    memset(&ent, 0, sizeof(ent));
    ent.principal = hist_princ;
    ent.max_life = KRB5_KDB_DISALLOW_ALL_TIX;
    ent.attributes = 0;
    ks[0].ks_enctype = handle->params.enctype;
    ks[0].ks_salttype = KRB5_KDB_SALTTYPE_NORMAL;
    ret = kadm5_create_principal_3(handle, &ent, mask, 1, ks, NULL);
    if (ret)
        return ret;

    /* For better compatibility with pre-1.8 libkadm5 code, we want the
     * initial history kvno to be 2, so re-randomize it. */
    return kadm5_randkey_principal_3(handle, ent.principal, 0, 1, ks,
                                     NULL, NULL);
}

/*
 * Function: kdb_get_hist_key
 *
 * Purpose: Fetches the current history key, creating it if necessary
 *
 * Arguments:
 *
 *      handle          (r) kadm5 api server handle
 *      hist_keyblock   (w) keyblock to fill in with history key
 *      hist_kvno       (w) kvno to fill in with history kvno
 *
 * Effects: This function looks up the history principal and retrieves the
 * current history key and version.  If the history principal does not exist,
 * it will be created.
 */
krb5_error_code
kdb_get_hist_key(kadm5_server_handle_t handle, krb5_keyblock *hist_keyblock,
                 krb5_kvno *hist_kvno)
{
    krb5_error_code ret;
    krb5_db_entry *kdb;
    krb5_keyblock *mkey;

    /* Fetch the history principal, creating it if necessary. */
    ret = kdb_get_entry(handle, hist_princ, &kdb, NULL);
    if (ret == KADM5_UNK_PRINC) {
        ret = create_hist(handle);
        if (ret)
            return ret;
        ret = kdb_get_entry(handle, hist_princ, &kdb, NULL);
    }
    if (ret)
        return ret;

    if (kdb->n_key_data <= 0) {
        ret = KRB5_KDB_NO_MATCHING_KEY;
        krb5_set_error_message(handle->context, ret,
                               "History entry contains no key data");
        goto done;
    }

    ret = krb5_dbe_find_mkey(handle->context, master_keylist, kdb, &mkey);
    if (ret)
        goto done;

    ret = krb5_dbe_decrypt_key_data(handle->context, mkey, &kdb->key_data[0],
                                    hist_keyblock, NULL);
    if (ret)
        goto done;

    *hist_kvno = kdb->key_data[0].key_data_kvno;

done:
    kdb_free_entry(handle, kdb, NULL);
    return ret;
}

/*
 * Function: kdb_get_entry
 *
 * Purpose: Gets an entry from the kerberos database and breaks
 * it out into a krb5_db_entry and an osa_princ_ent_t.
 *
 * Arguments:
 *
 *              handle          (r) the server_handle
 *              principal       (r) the principal to get
 *              kdb             (w) krb5_db_entry to create
 *              adb             (w) osa_princ_ent_rec to fill in
 *
 * when the caller is done with kdb and adb, kdb_free_entry must be
 * called to release them.  The adb record is filled in with the
 * contents of the KRB5_TL_KADM_DATA record; if that record doesn't
 * exist, an empty but valid adb record is returned.
 */
krb5_error_code
kdb_get_entry(kadm5_server_handle_t handle,
              krb5_principal principal, krb5_db_entry **kdb_ptr,
              osa_princ_ent_rec *adb)
{
    krb5_error_code ret;
    krb5_tl_data tl_data;
    XDR xdrs;
    krb5_db_entry *kdb;

    *kdb_ptr = NULL;

    ret = krb5_db_get_principal(handle->context, principal,
                                KRB5_KDB_FLAG_ALIAS_OK, &kdb);
    if (ret == KRB5_KDB_NOENTRY)
        return(KADM5_UNK_PRINC);
    if (ret)
        return(ret);

    if (adb) {
        memset(adb, 0, sizeof(*adb));

        tl_data.tl_data_type = KRB5_TL_KADM_DATA;
        /*
         * XXX Currently, lookup_tl_data always returns zero; it sets
         * tl_data->tl_data_length to zero if the type isn't found.
         * This should be fixed...
         */
        if ((ret = krb5_dbe_lookup_tl_data(handle->context, kdb, &tl_data))
            || (tl_data.tl_data_length == 0)) {
            /* there's no admin data.  this can happen, if the admin
               server is put into production after some principals
               are created.  In this case, return valid admin
               data (which is all zeros with the hist_kvno filled
               in), and when the entry is written, the admin
               data will get stored correctly. */

            adb->admin_history_kvno = INITIAL_HIST_KVNO;
            *kdb_ptr = kdb;
            return(ret);
        }

        xdrmem_create(&xdrs, tl_data.tl_data_contents,
                      tl_data.tl_data_length, XDR_DECODE);
        if (! xdr_osa_princ_ent_rec(&xdrs, adb)) {
            xdr_destroy(&xdrs);
            krb5_db_free_principal(handle->context, kdb);
            return(KADM5_XDR_FAILURE);
        }
        xdr_destroy(&xdrs);
    }

    *kdb_ptr = kdb;
    return(0);
}

/*
 * Function: kdb_free_entry
 *
 * Purpose: frees the resources allocated by kdb_get_entry
 *
 * Arguments:
 *
 *              handle          (r) the server_handle
 *              kdb             (w) krb5_db_entry to fill in
 *              adb             (w) osa_princ_ent_rec to fill in
 *
 * when the caller is done with kdb and adb, kdb_free_entry must be
 * called to release them.
 */

krb5_error_code
kdb_free_entry(kadm5_server_handle_t handle,
               krb5_db_entry *kdb, osa_princ_ent_rec *adb)
{
    XDR xdrs;


    if (kdb)
        krb5_db_free_principal(handle->context, kdb);

    if (adb) {
        xdrmem_create(&xdrs, NULL, 0, XDR_FREE);
        xdr_osa_princ_ent_rec(&xdrs, adb);
        xdr_destroy(&xdrs);
    }

    return(0);
}

/*
 * Function: kdb_put_entry
 *
 * Purpose: Stores the osa_princ_ent_t and krb5_db_entry into to
 * database.
 *
 * Arguments:
 *
 *              handle  (r) the server_handle
 *              kdb     (r/w) the krb5_db_entry to store
 *              adb     (r) the osa_princ_db_ent to store
 *
 * Effects:
 *
 * The last modifier field of the kdb is set to the caller at now.
 * adb is encoded with xdr_osa_princ_ent_ret and stored in kbd as
 * KRB5_TL_KADM_DATA.  kdb is then written to the database.
 */
krb5_error_code
kdb_put_entry(kadm5_server_handle_t handle,
              krb5_db_entry *kdb, osa_princ_ent_rec *adb)
{
    krb5_error_code ret;
    krb5_int32 now;
    XDR xdrs;
    krb5_tl_data tl_data;

    ret = krb5_timeofday(handle->context, &now);
    if (ret)
        return(ret);

    ret = krb5_dbe_update_mod_princ_data(handle->context, kdb, now,
                                         handle->current_caller);
    if (ret)
        return(ret);

    xdralloc_create(&xdrs, XDR_ENCODE);
    if(! xdr_osa_princ_ent_rec(&xdrs, adb)) {
        xdr_destroy(&xdrs);
        return(KADM5_XDR_FAILURE);
    }
    tl_data.tl_data_type = KRB5_TL_KADM_DATA;
    tl_data.tl_data_length = xdr_getpos(&xdrs);
    tl_data.tl_data_contents = xdralloc_getdata(&xdrs);

    ret = krb5_dbe_update_tl_data(handle->context, kdb, &tl_data);

    xdr_destroy(&xdrs);

    if (ret)
        return(ret);

    /* we are always updating TL data */
    kdb->mask |= KADM5_TL_DATA;

    ret = krb5_db_put_principal(handle->context, kdb);
    if (ret)
        return(ret);

    return(0);
}

krb5_error_code
kdb_delete_entry(kadm5_server_handle_t handle, krb5_principal name)
{
    krb5_error_code ret;

    ret = krb5_db_delete_principal(handle->context, name);
    if (ret == KRB5_KDB_NOENTRY)
        ret = 0;
    return ret;
}

typedef struct _iter_data {
    void (*func)(void *, krb5_principal);
    void *data;
} iter_data;

static krb5_error_code
kdb_iter_func(krb5_pointer data, krb5_db_entry *kdb)
{
    iter_data *id = (iter_data *) data;

    (*(id->func))(id->data, kdb->princ);

    return(0);
}

krb5_error_code
kdb_iter_entry(kadm5_server_handle_t handle, char *match_entry,
               void (*iter_fct)(void *, krb5_principal), void *data)
{
    iter_data id;
    krb5_error_code ret;

    id.func = iter_fct;
    id.data = data;

    ret = krb5_db_iterate(handle->context, match_entry, kdb_iter_func, &id);
    if (ret)
        return(ret);

    return(0);
}
