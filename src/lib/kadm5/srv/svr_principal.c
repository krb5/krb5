/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include        <sys/types.h>
#include        <sys/time.h>
#include        <errno.h>
#include        <kadm5/admin.h>
#include        <kdb.h>
#include        <stdio.h>
#include        <string.h>
#include        "server_internal.h"
#include        <stdarg.h>
#include        <stdlib.h>
#ifdef USE_PASSWORD_SERVER
#include        <sys/wait.h>
#include        <signal.h>

#endif

#ifdef USE_VALGRIND
#include <valgrind/memcheck.h>
#else
#define VALGRIND_CHECK_DEFINED(LVALUE) ((void)0)
#endif

extern  krb5_principal      master_princ;
extern  krb5_principal      hist_princ;
extern  krb5_keyblock       master_keyblock;
extern  krb5_keylist_node  *master_keylist;
extern  krb5_actkvno_node  *active_mkey_list;
extern  krb5_db_entry       master_db;

static int decrypt_key_data(krb5_context context, krb5_keyblock *mkey,
                            int n_key_data, krb5_key_data *key_data,
                            krb5_keyblock **keyblocks, int *n_keys);

static krb5_error_code
kadm5_copy_principal(krb5_context context, krb5_const_principal inprinc, krb5_principal *outprinc)
{
    register krb5_principal tempprinc;
    register int i, nelems;

    tempprinc = (krb5_principal)krb5_db_alloc(context, NULL, sizeof(krb5_principal_data));

    if (tempprinc == 0)
        return ENOMEM;

    VALGRIND_CHECK_DEFINED(*inprinc);
    *tempprinc = *inprinc;

    nelems = (int) krb5_princ_size(context, inprinc);
    tempprinc->data = krb5_db_alloc(context, NULL, nelems * sizeof(krb5_data));
    if (tempprinc->data == 0) {
        krb5_db_free(context, (char *)tempprinc);
        return ENOMEM;
    }

    for (i = 0; i < nelems; i++) {
        unsigned int len = krb5_princ_component(context, inprinc, i)->length;
        krb5_princ_component(context, tempprinc, i)->length = len;
        if (((krb5_princ_component(context, tempprinc, i)->data =
              krb5_db_alloc(context, NULL, len)) == 0) && len) {
            while (--i >= 0)
                krb5_db_free(context, krb5_princ_component(context, tempprinc, i)->data);
            krb5_db_free (context, tempprinc->data);
            krb5_db_free (context, tempprinc);
            return ENOMEM;
        }
        if (len)
            memcpy(krb5_princ_component(context, tempprinc, i)->data,
                   krb5_princ_component(context, inprinc, i)->data, len);
        krb5_princ_component(context, tempprinc, i)->magic = KV5M_DATA;
    }

    tempprinc->realm.data =
        krb5_db_alloc(context, NULL, tempprinc->realm.length = inprinc->realm.length);
    if (!tempprinc->realm.data && tempprinc->realm.length) {
        for (i = 0; i < nelems; i++)
            krb5_db_free(context, krb5_princ_component(context, tempprinc, i)->data);
        krb5_db_free(context, tempprinc->data);
        krb5_db_free(context, tempprinc);
        return ENOMEM;
    }
    if (tempprinc->realm.length)
        memcpy(tempprinc->realm.data, inprinc->realm.data,
               inprinc->realm.length);

    *outprinc = tempprinc;
    return 0;
}

static void
kadm5_free_principal(krb5_context context, krb5_principal val)
{
    register krb5_int32 i;

    if (!val)
        return;

    if (val->data) {
        i = krb5_princ_size(context, val);
        while(--i >= 0)
            krb5_db_free(context, krb5_princ_component(context, val, i)->data);
        krb5_db_free(context, val->data);
    }
    if (val->realm.data)
        krb5_db_free(context, val->realm.data);
    krb5_db_free(context, val);
}

/*
 * XXX Functions that ought to be in libkrb5.a, but aren't.
 */
kadm5_ret_t krb5_copy_key_data_contents(context, from, to)
    krb5_context context;
    krb5_key_data *from, *to;
{
    int i, idx;

    *to = *from;

    idx = (from->key_data_ver == 1 ? 1 : 2);

    for (i = 0; i < idx; i++) {
        if ( from->key_data_length[i] ) {
            to->key_data_contents[i] = malloc(from->key_data_length[i]);
            if (to->key_data_contents[i] == NULL) {
                for (i = 0; i < idx; i++) {
                    if (to->key_data_contents[i]) {
                        memset(to->key_data_contents[i], 0,
                               to->key_data_length[i]);
                        free(to->key_data_contents[i]);
                    }
                }
                return ENOMEM;
            }
            memcpy(to->key_data_contents[i], from->key_data_contents[i],
                   from->key_data_length[i]);
        }
    }
    return 0;
}

static krb5_tl_data *dup_tl_data(krb5_tl_data *tl)
{
    krb5_tl_data *n;

    n = (krb5_tl_data *) malloc(sizeof(krb5_tl_data));
    if (n == NULL)
        return NULL;
    n->tl_data_contents = malloc(tl->tl_data_length);
    if (n->tl_data_contents == NULL) {
        free(n);
        return NULL;
    }
    memcpy(n->tl_data_contents, tl->tl_data_contents, tl->tl_data_length);
    n->tl_data_type = tl->tl_data_type;
    n->tl_data_length = tl->tl_data_length;
    n->tl_data_next = NULL;
    return n;
}

/* This is in lib/kdb/kdb_cpw.c, but is static */
static void cleanup_key_data(context, count, data)
    krb5_context   context;
    int                    count;
    krb5_key_data        * data;
{
    int i, j;

    for (i = 0; i < count; i++)
        for (j = 0; j < data[i].key_data_ver; j++)
            if (data[i].key_data_length[j])
                krb5_db_free(context, data[i].key_data_contents[j]);
    krb5_db_free(context, data);
}

/*
 * Set *passptr to NULL if the request looks like the first part of a krb5 1.6
 * addprinc -randkey operation.  The krb5 1.6 dummy password for these requests
 * was invalid UTF-8, which runs afoul of the arcfour string-to-key.
 */
static void
check_1_6_dummy(kadm5_principal_ent_t entry, long mask,
                int n_ks_tuple, krb5_key_salt_tuple *ks_tuple, char **passptr)
{
    int i;
    char *password = *passptr;

    /* Old-style randkey operations disallowed tickets to start. */
    if (!(mask & KADM5_ATTRIBUTES) ||
        !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX))
        return;

    /* The 1.6 dummy password was the octets 1..255. */
    for (i = 0; (unsigned char) password[i] == i + 1; i++);
    if (password[i] != '\0' || i != 255)
        return;

    /* This will make the caller use a random password instead. */
    *passptr = NULL;
}

kadm5_ret_t
kadm5_create_principal(void *server_handle,
                       kadm5_principal_ent_t entry, long mask,
                       char *password)
{
    return
        kadm5_create_principal_3(server_handle, entry, mask,
                                 0, NULL, password);
}
kadm5_ret_t
kadm5_create_principal_3(void *server_handle,
                         kadm5_principal_ent_t entry, long mask,
                         int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
                         char *password)
{
    krb5_db_entry               kdb;
    osa_princ_ent_rec           adb;
    kadm5_policy_ent_rec        polent;
    krb5_int32                  now;
    krb5_tl_data                *tl_data_orig, *tl_data_tail;
    unsigned int                ret;
    kadm5_server_handle_t handle = server_handle;
    krb5_keyblock               *act_mkey;
    krb5_kvno                   act_kvno;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    check_1_6_dummy(entry, mask, n_ks_tuple, ks_tuple, &password);

    /*
     * Argument sanity checking, and opening up the DB
     */
    if(!(mask & KADM5_PRINCIPAL) || (mask & KADM5_MOD_NAME) ||
       (mask & KADM5_MOD_TIME) || (mask & KADM5_LAST_PWD_CHANGE) ||
       (mask & KADM5_MKVNO) || (mask & KADM5_POLICY_CLR) ||
       (mask & KADM5_AUX_ATTRIBUTES) || (mask & KADM5_KEY_DATA) ||
       (mask & KADM5_LAST_SUCCESS) || (mask & KADM5_LAST_FAILED) ||
       (mask & KADM5_FAIL_AUTH_COUNT))
        return KADM5_BAD_MASK;
    if((mask & ~ALL_PRINC_MASK))
        return KADM5_BAD_MASK;
    if (entry == NULL)
        return EINVAL;

    /*
     * Check to see if the principal exists
     */
    ret = kdb_get_entry(handle, entry->principal, &kdb, &adb);

    switch(ret) {
    case KADM5_UNK_PRINC:
        break;
    case 0:
        kdb_free_entry(handle, &kdb, &adb);
        return KADM5_DUP;
    default:
        return ret;
    }

    memset(&kdb, 0, sizeof(krb5_db_entry));
    memset(&adb, 0, sizeof(osa_princ_ent_rec));

    /*
     * If a policy was specified, load it.
     * If we can not find the one specified return an error
     */
    if ((mask & KADM5_POLICY)) {
        if ((ret = kadm5_get_policy(handle->lhandle, entry->policy,
                                    &polent)) != KADM5_OK) {
            if(ret == EINVAL)
                return KADM5_BAD_POLICY;
            else
                return ret;
        }
    }
    if (password) {
        ret = passwd_check(handle, password, (mask & KADM5_POLICY),
                           &polent, entry->principal);
        if (ret) {
            if (mask & KADM5_POLICY)
                (void) kadm5_free_policy_ent(handle->lhandle, &polent);
            return ret;
        }
    }
    /*
     * Start populating the various DB fields, using the
     * "defaults" for fields that were not specified by the
     * mask.
     */
    if ((ret = krb5_timeofday(handle->context, &now))) {
        if (mask & KADM5_POLICY)
            (void) kadm5_free_policy_ent(handle->lhandle, &polent);
        return ret;
    }

    kdb.magic = KRB5_KDB_MAGIC_NUMBER;
    kdb.len = KRB5_KDB_V1_BASE_LENGTH; /* gag me with a chainsaw */

    if ((mask & KADM5_ATTRIBUTES))
        kdb.attributes = entry->attributes;
    else
        kdb.attributes = handle->params.flags;

    if ((mask & KADM5_MAX_LIFE))
        kdb.max_life = entry->max_life;
    else
        kdb.max_life = handle->params.max_life;

    if (mask & KADM5_MAX_RLIFE)
        kdb.max_renewable_life = entry->max_renewable_life;
    else
        kdb.max_renewable_life = handle->params.max_rlife;

    if ((mask & KADM5_PRINC_EXPIRE_TIME))
        kdb.expiration = entry->princ_expire_time;
    else
        kdb.expiration = handle->params.expiration;

    kdb.pw_expiration = 0;
    if ((mask & KADM5_POLICY)) {
        if(polent.pw_max_life)
            kdb.pw_expiration = now + polent.pw_max_life;
        else
            kdb.pw_expiration = 0;
    }
    if ((mask & KADM5_PW_EXPIRATION))
        kdb.pw_expiration = entry->pw_expiration;

    kdb.last_success = 0;
    kdb.last_failed = 0;
    kdb.fail_auth_count = 0;

    /* this is kind of gross, but in order to free the tl data, I need
       to free the entire kdb entry, and that will try to free the
       principal. */

    if ((ret = kadm5_copy_principal(handle->context,
                                    entry->principal, &(kdb.princ)))) {
        if (mask & KADM5_POLICY)
            (void) kadm5_free_policy_ent(handle->lhandle, &polent);
        return(ret);
    }

    if ((ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now))) {
        krb5_db_free_principal(handle->context, &kdb, 1);
        if (mask & KADM5_POLICY)
            (void) kadm5_free_policy_ent(handle->lhandle, &polent);
        return(ret);
    }

    if (mask & KADM5_TL_DATA) {
        /* splice entry->tl_data onto the front of kdb.tl_data */
        tl_data_orig = kdb.tl_data;
        for (tl_data_tail = entry->tl_data; tl_data_tail;
             tl_data_tail = tl_data_tail->tl_data_next)
        {
            ret = krb5_dbe_update_tl_data(handle->context, &kdb, tl_data_tail);
            if( ret )
            {
                krb5_db_free_principal(handle->context, &kdb, 1);
                if (mask & KADM5_POLICY)
                    (void) kadm5_free_policy_ent(handle->lhandle, &polent);
                return ret;
            }
        }
    }

    /* initialize the keys */

    ret = krb5_dbe_find_act_mkey(handle->context, master_keylist,
                                 active_mkey_list, &act_kvno, &act_mkey);
    if (ret) {
        krb5_db_free_principal(handle->context, &kdb, 1);
        if (mask & KADM5_POLICY)
            (void) kadm5_free_policy_ent(handle->lhandle, &polent);
        return (ret);
    }

    if (password) {
        ret = krb5_dbe_cpw(handle->context, act_mkey,
                           n_ks_tuple?ks_tuple:handle->params.keysalts,
                           n_ks_tuple?n_ks_tuple:handle->params.num_keysalts,
                           password, (mask & KADM5_KVNO)?entry->kvno:1,
                           FALSE, &kdb);
    } else {
        /* Null password means create with random key (new in 1.8). */
        ret = krb5_dbe_crk(handle->context, &master_keyblock,
                           n_ks_tuple?ks_tuple:handle->params.keysalts,
                           n_ks_tuple?n_ks_tuple:handle->params.num_keysalts,
                           FALSE, &kdb);
    }
    if (ret) {
        krb5_db_free_principal(handle->context, &kdb, 1);
        if (mask & KADM5_POLICY)
            (void) kadm5_free_policy_ent(handle->lhandle, &polent);
        return(ret);
    }

    /* Record the master key VNO used to encrypt this entry's keys */
    ret = krb5_dbe_update_mkvno(handle->context, &kdb, act_kvno);
    if (ret)
    {
        krb5_db_free_principal(handle->context, &kdb, 1);
        if (mask & KADM5_POLICY)
            (void) kadm5_free_policy_ent(handle->lhandle, &polent);
        return ret;
    }

    /* populate the admin-server-specific fields.  In the OV server,
       this used to be in a separate database.  Since there's already
       marshalling code for the admin fields, to keep things simple,
       I'm going to keep it, and make all the admin stuff occupy a
       single tl_data record, */

    adb.admin_history_kvno = INITIAL_HIST_KVNO;
    if ((mask & KADM5_POLICY)) {
        adb.aux_attributes = KADM5_POLICY;

        /* this does *not* need to be strdup'ed, because adb is xdr */
        /* encoded in osa_adb_create_princ, and not ever freed */

        adb.policy = entry->policy;
    }

    /* increment the policy ref count, if any */

    if ((mask & KADM5_POLICY)) {
        polent.policy_refcnt++;
        if ((ret = kadm5_modify_policy_internal(handle->lhandle, &polent,
                                                KADM5_REF_COUNT))
            != KADM5_OK) {
            krb5_db_free_principal(handle->context, &kdb, 1);
            if (mask & KADM5_POLICY)
                (void) kadm5_free_policy_ent(handle->lhandle, &polent);
            return(ret);
        }
    }

    /* In all cases key and the principal data is set, let the database provider know */
    kdb.mask = mask | KADM5_KEY_DATA | KADM5_PRINCIPAL ;

    /* store the new db entry */
    ret = kdb_put_entry(handle, &kdb, &adb);

    krb5_db_free_principal(handle->context, &kdb, 1);

    if (ret) {
        if ((mask & KADM5_POLICY)) {
            /* decrement the policy ref count */

            polent.policy_refcnt--;
            /*
             * if this fails, there's nothing we can do anyway.  the
             * policy refcount wil be too high.
             */
            (void) kadm5_modify_policy_internal(handle->lhandle, &polent,
                                                KADM5_REF_COUNT);
        }

        if (mask & KADM5_POLICY)
            (void) kadm5_free_policy_ent(handle->lhandle, &polent);
        return(ret);
    }

    if (mask & KADM5_POLICY)
        (void) kadm5_free_policy_ent(handle->lhandle, &polent);

    return KADM5_OK;
}


kadm5_ret_t
kadm5_delete_principal(void *server_handle, krb5_principal principal)
{
    unsigned int                ret;
    kadm5_policy_ent_rec        polent;
    krb5_db_entry               kdb;
    osa_princ_ent_rec           adb;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (principal == NULL)
        return EINVAL;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
        return(ret);

    if ((adb.aux_attributes & KADM5_POLICY)) {
        if ((ret = kadm5_get_policy(handle->lhandle,
                                    adb.policy, &polent))
            == KADM5_OK) {
            polent.policy_refcnt--;
            if ((ret = kadm5_modify_policy_internal(handle->lhandle, &polent,
                                                    KADM5_REF_COUNT))
                != KADM5_OK) {
                (void) kadm5_free_policy_ent(handle->lhandle, &polent);
                kdb_free_entry(handle, &kdb, &adb);
                return(ret);
            }
        }
        if ((ret = kadm5_free_policy_ent(handle->lhandle, &polent))) {
            kdb_free_entry(handle, &kdb, &adb);
            return ret;
        }
    }

    ret = kdb_delete_entry(handle, principal);

    kdb_free_entry(handle, &kdb, &adb);

    return ret;
}

kadm5_ret_t
kadm5_modify_principal(void *server_handle,
                       kadm5_principal_ent_t entry, long mask)
{
    int                     ret, ret2, i;
    kadm5_policy_ent_rec    npol, opol;
    int                     have_npol = 0, have_opol = 0;
    krb5_db_entry           kdb;
    krb5_tl_data            *tl_data_orig;
    osa_princ_ent_rec       adb;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if((mask & KADM5_PRINCIPAL) || (mask & KADM5_LAST_PWD_CHANGE) ||
       (mask & KADM5_MOD_TIME) || (mask & KADM5_MOD_NAME) ||
       (mask & KADM5_MKVNO) || (mask & KADM5_AUX_ATTRIBUTES) ||
       (mask & KADM5_KEY_DATA) || (mask & KADM5_LAST_SUCCESS) ||
       (mask & KADM5_LAST_FAILED))
        return KADM5_BAD_MASK;
    if((mask & ~ALL_PRINC_MASK))
        return KADM5_BAD_MASK;
    if((mask & KADM5_POLICY) && (mask & KADM5_POLICY_CLR))
        return KADM5_BAD_MASK;
    if(entry == (kadm5_principal_ent_t) NULL)
        return EINVAL;
    if (mask & KADM5_TL_DATA) {
        tl_data_orig = entry->tl_data;
        while (tl_data_orig) {
            if (tl_data_orig->tl_data_type < 256)
                return KADM5_BAD_TL_TYPE;
            tl_data_orig = tl_data_orig->tl_data_next;
        }
    }

    ret = kdb_get_entry(handle, entry->principal, &kdb, &adb);
    if (ret)
        return(ret);

    /*
     * This is pretty much the same as create ...
     */

    if ((mask & KADM5_POLICY)) {
        /* get the new policy */
        ret = kadm5_get_policy(handle->lhandle, entry->policy, &npol);
        if (ret) {
            switch (ret) {
            case EINVAL:
                ret = KADM5_BAD_POLICY;
                break;
            case KADM5_UNK_POLICY:
            case KADM5_BAD_POLICY:
                ret =  KADM5_UNK_POLICY;
                break;
            }
            goto done;
        }
        have_npol = 1;

        /* if we already have a policy, get it to decrement the refcnt */
        if(adb.aux_attributes & KADM5_POLICY) {
            /* ... but not if the old and new are the same */
            if(strcmp(adb.policy, entry->policy)) {
                ret = kadm5_get_policy(handle->lhandle,
                                       adb.policy, &opol);
                switch(ret) {
                case EINVAL:
                case KADM5_BAD_POLICY:
                case KADM5_UNK_POLICY:
                    break;
                case KADM5_OK:
                    have_opol = 1;
                    opol.policy_refcnt--;
                    break;
                default:
                    goto done;
                    break;
                }
                npol.policy_refcnt++;
            }
        } else npol.policy_refcnt++;

        /* set us up to use the new policy */
        adb.aux_attributes |= KADM5_POLICY;
        if (adb.policy)
            free(adb.policy);
        adb.policy = strdup(entry->policy);

        /* set pw_max_life based on new policy */
        if (npol.pw_max_life) {
            ret = krb5_dbe_lookup_last_pwd_change(handle->context, &kdb,
                                                  &(kdb.pw_expiration));
            if (ret)
                goto done;
            kdb.pw_expiration += npol.pw_max_life;
        } else {
            kdb.pw_expiration = 0;
        }
    }

    if ((mask & KADM5_POLICY_CLR) &&
        (adb.aux_attributes & KADM5_POLICY)) {
        ret = kadm5_get_policy(handle->lhandle, adb.policy, &opol);
        switch(ret) {
        case EINVAL:
        case KADM5_BAD_POLICY:
        case KADM5_UNK_POLICY:
            ret = KADM5_BAD_DB;
            goto done;
            break;
        case KADM5_OK:
            have_opol = 1;
            if (adb.policy)
                free(adb.policy);
            adb.policy = NULL;
            adb.aux_attributes &= ~KADM5_POLICY;
            kdb.pw_expiration = 0;
            opol.policy_refcnt--;
            break;
        default:
            goto done;
            break;
        }
    }

    if (((mask & KADM5_POLICY) || (mask & KADM5_POLICY_CLR)) &&
        (((have_opol) &&
          (ret =
           kadm5_modify_policy_internal(handle->lhandle, &opol,
                                        KADM5_REF_COUNT))) ||
         ((have_npol) &&
          (ret =
           kadm5_modify_policy_internal(handle->lhandle, &npol,
                                        KADM5_REF_COUNT)))))
        goto done;

    if ((mask & KADM5_ATTRIBUTES))
        kdb.attributes = entry->attributes;
    if ((mask & KADM5_MAX_LIFE))
        kdb.max_life = entry->max_life;
    if ((mask & KADM5_PRINC_EXPIRE_TIME))
        kdb.expiration = entry->princ_expire_time;
    if (mask & KADM5_PW_EXPIRATION)
        kdb.pw_expiration = entry->pw_expiration;
    if (mask & KADM5_MAX_RLIFE)
        kdb.max_renewable_life = entry->max_renewable_life;

    if((mask & KADM5_KVNO)) {
        for (i = 0; i < kdb.n_key_data; i++)
            kdb.key_data[i].key_data_kvno = entry->kvno;
    }

    if (mask & KADM5_TL_DATA) {
        krb5_tl_data *tl;

        /* may have to change the version number of the API. Updates the list with the given tl_data rather than over-writting */

        for (tl = entry->tl_data; tl;
             tl = tl->tl_data_next)
        {
            ret = krb5_dbe_update_tl_data(handle->context, &kdb, tl);
            if( ret )
            {
                goto done;
            }
        }
    }

    /*
     * Setting entry->fail_auth_count to 0 can be used to manually unlock
     * an account. It is not possible to set fail_auth_count to any other
     * value using kadmin.
     */
    if (mask & KADM5_FAIL_AUTH_COUNT) {
        if (entry->fail_auth_count != 0) {
            ret = KADM5_BAD_SERVER_PARAMS;
            goto done;
        }

        kdb.fail_auth_count = 0;
    }

    /* let the mask propagate to the database provider */
    kdb.mask = mask;

    ret = kdb_put_entry(handle, &kdb, &adb);
    if (ret) goto done;

    ret = KADM5_OK;
done:
    if (have_opol) {
        ret2 = kadm5_free_policy_ent(handle->lhandle, &opol);
        ret = ret ? ret : ret2;
    }
    if (have_npol) {
        ret2 = kadm5_free_policy_ent(handle->lhandle, &npol);
        ret = ret ? ret : ret2;
    }
    kdb_free_entry(handle, &kdb, &adb);
    return ret;
}

kadm5_ret_t
kadm5_rename_principal(void *server_handle,
                       krb5_principal source, krb5_principal target)
{
    krb5_db_entry       kdb;
    osa_princ_ent_rec   adb;
    int                 ret, i;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (source == NULL || target == NULL)
        return EINVAL;

    if ((ret = kdb_get_entry(handle, target, &kdb, &adb)) == 0) {
        kdb_free_entry(handle, &kdb, &adb);
        return(KADM5_DUP);
    }

    if ((ret = kdb_get_entry(handle, source, &kdb, &adb)))
        return ret;

    /* this is kinda gross, but unavoidable */

    for (i=0; i<kdb.n_key_data; i++) {
        if ((kdb.key_data[i].key_data_ver == 1) ||
            (kdb.key_data[i].key_data_type[1] == KRB5_KDB_SALTTYPE_NORMAL)) {
            ret = KADM5_NO_RENAME_SALT;
            goto done;
        }
    }

    kadm5_free_principal(handle->context, kdb.princ);
    ret = kadm5_copy_principal(handle->context, target, &kdb.princ);
    if (ret) {
        kdb.princ = NULL; /* so freeing the dbe doesn't lose */
        goto done;
    }

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
        goto done;

    ret = kdb_delete_entry(handle, source);

done:
    kdb_free_entry(handle, &kdb, &adb);
    return ret;
}

kadm5_ret_t
kadm5_get_principal(void *server_handle, krb5_principal principal,
                    kadm5_principal_ent_t entry,
                    long in_mask)
{
    krb5_db_entry               kdb;
    osa_princ_ent_rec           adb;
    krb5_error_code             ret = 0;
    long                        mask;
    int i;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    /*
     * In version 1, all the defined fields are always returned.
     * entry is a pointer to a kadm5_principal_ent_t_v1 that should be
     * filled with allocated memory.
     */
    mask = in_mask;

    memset(entry, 0, sizeof(*entry));

    if (principal == NULL)
        return EINVAL;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
        return ret;

    if ((mask & KADM5_POLICY) &&
        adb.policy && (adb.aux_attributes & KADM5_POLICY)) {
        if ((entry->policy = strdup(adb.policy)) == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (mask & KADM5_AUX_ATTRIBUTES)
        entry->aux_attributes = adb.aux_attributes;

    if ((mask & KADM5_PRINCIPAL) &&
        (ret = krb5_copy_principal(handle->context, kdb.princ,
                                   &entry->principal))) {
        goto done;
    }

    if (mask & KADM5_PRINC_EXPIRE_TIME)
        entry->princ_expire_time = kdb.expiration;

    if ((mask & KADM5_LAST_PWD_CHANGE) &&
        (ret = krb5_dbe_lookup_last_pwd_change(handle->context, &kdb,
                                               &(entry->last_pwd_change)))) {
        goto done;
    }

    if (mask & KADM5_PW_EXPIRATION)
        entry->pw_expiration = kdb.pw_expiration;
    if (mask & KADM5_MAX_LIFE)
        entry->max_life = kdb.max_life;

    /* this is a little non-sensical because the function returns two */
    /* values that must be checked separately against the mask */
    if ((mask & KADM5_MOD_NAME) || (mask & KADM5_MOD_TIME)) {
        ret = krb5_dbe_lookup_mod_princ_data(handle->context, &kdb,
                                             &(entry->mod_date),
                                             &(entry->mod_name));
        if (ret) {
            goto done;
        }

        if (! (mask & KADM5_MOD_TIME))
            entry->mod_date = 0;
        if (! (mask & KADM5_MOD_NAME)) {
            krb5_free_principal(handle->context, entry->mod_name);
            entry->mod_name = NULL;
        }
    }

    if (mask & KADM5_ATTRIBUTES)
        entry->attributes = kdb.attributes;

    if (mask & KADM5_KVNO)
        for (entry->kvno = 0, i=0; i<kdb.n_key_data; i++)
            if (kdb.key_data[i].key_data_kvno > entry->kvno)
                entry->kvno = kdb.key_data[i].key_data_kvno;

    if (mask & KADM5_MKVNO) {
        ret = krb5_dbe_get_mkvno(handle->context, &kdb, master_keylist,
                                 &entry->mkvno);
        if (ret)
            goto done;
    }

    if (mask & KADM5_MAX_RLIFE)
        entry->max_renewable_life = kdb.max_renewable_life;
    if (mask & KADM5_LAST_SUCCESS)
        entry->last_success = kdb.last_success;
    if (mask & KADM5_LAST_FAILED)
        entry->last_failed = kdb.last_failed;
    if (mask & KADM5_FAIL_AUTH_COUNT)
        entry->fail_auth_count = kdb.fail_auth_count;
    if (mask & KADM5_TL_DATA) {
        krb5_tl_data *tl, *tl2;

        entry->tl_data = NULL;

        tl = kdb.tl_data;
        while (tl) {
            if (tl->tl_data_type > 255) {
                if ((tl2 = dup_tl_data(tl)) == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                tl2->tl_data_next = entry->tl_data;
                entry->tl_data = tl2;
                entry->n_tl_data++;
            }

            tl = tl->tl_data_next;
        }
    }
    if (mask & KADM5_KEY_DATA) {
        entry->n_key_data = kdb.n_key_data;
        if(entry->n_key_data) {
            entry->key_data = malloc(entry->n_key_data*sizeof(krb5_key_data));
            if (entry->key_data == NULL) {
                ret = ENOMEM;
                goto done;
            }
        } else
            entry->key_data = NULL;

        for (i = 0; i < entry->n_key_data; i++)
            ret = krb5_copy_key_data_contents(handle->context,
                                              &kdb.key_data[i],
                                              &entry->key_data[i]);
        if (ret)
            goto done;
    }

    ret = KADM5_OK;

done:
    if (ret && entry->principal) {
        krb5_free_principal(handle->context, entry->principal);
        entry->principal = NULL;
    }
    kdb_free_entry(handle, &kdb, &adb);

    return ret;
}

/*
 * Function: check_pw_reuse
 *
 * Purpose: Check if a key appears in a list of keys, in order to
 * enforce password history.
 *
 * Arguments:
 *
 *      context                 (r) the krb5 context
 *      hist_keyblock           (r) the key that hist_key_data is
 *                              encrypted in
 *      n_new_key_data          (r) length of new_key_data
 *      new_key_data            (r) keys to check against
 *                              pw_hist_data, encrypted in hist_keyblock
 *      n_pw_hist_data          (r) length of pw_hist_data
 *      pw_hist_data            (r) passwords to check new_key_data against
 *
 * Effects:
 * For each new_key in new_key_data:
 *      decrypt new_key with the master_keyblock
 *      for each password in pw_hist_data:
 *              for each hist_key in password:
 *                      decrypt hist_key with hist_keyblock
 *                      compare the new_key and hist_key
 *
 * Returns krb5 errors, KADM5_PASS_RESUSE if a key in
 * new_key_data is the same as a key in pw_hist_data, or 0.
 */
static kadm5_ret_t
check_pw_reuse(krb5_context context,
               krb5_keyblock *mkey,
               krb5_keyblock *hist_keyblock,
               int n_new_key_data, krb5_key_data *new_key_data,
               unsigned int n_pw_hist_data, osa_pw_hist_ent *pw_hist_data)
{
    int x, y, z;
    krb5_keyblock newkey, histkey;
    krb5_error_code ret;

    for (x = 0; x < n_new_key_data; x++) {
        ret = krb5_dbekd_decrypt_key_data(context,
                                          mkey,
                                          &(new_key_data[x]),
                                          &newkey, NULL);
        if (ret)
            return(ret);
        for (y = 0; y < n_pw_hist_data; y++) {
            for (z = 0; z < pw_hist_data[y].n_key_data; z++) {
                ret = krb5_dbekd_decrypt_key_data(context,
                                                  hist_keyblock,
                                                  &pw_hist_data[y].key_data[z],
                                                  &histkey, NULL);
                if (ret)
                    return(ret);

                if ((newkey.length == histkey.length) &&
                    (newkey.enctype == histkey.enctype) &&
                    (memcmp(newkey.contents, histkey.contents,
                            histkey.length) == 0)) {
                    krb5_free_keyblock_contents(context, &histkey);
                    krb5_free_keyblock_contents(context, &newkey);

                    return(KADM5_PASS_REUSE);
                }
                krb5_free_keyblock_contents(context, &histkey);
            }
        }
        krb5_free_keyblock_contents(context, &newkey);
    }

    return(0);
}

/*
 * Function: create_history_entry
 *
 * Purpose: Creates a password history entry from an array of
 * key_data.
 *
 * Arguments:
 *
 *      context         (r) krb5_context to use
 *      mkey            (r) master keyblock to decrypt key data with
 *      hist_key        (r) history keyblock to encrypt key data with
 *      n_key_data      (r) number of elements in key_data
 *      key_data        (r) keys to add to the history entry
 *      hist            (w) history entry to fill in
 *
 * Effects:
 *
 * hist->key_data is allocated to store n_key_data key_datas.  Each
 * element of key_data is decrypted with master_keyblock, re-encrypted
 * in hist_key, and added to hist->key_data.  hist->n_key_data is
 * set to n_key_data.
 */
static
int create_history_entry(krb5_context context, krb5_keyblock *mkey,
                         krb5_keyblock *hist_key, int n_key_data,
                         krb5_key_data *key_data, osa_pw_hist_ent *hist)
{
    int i, ret;
    krb5_keyblock key;
    krb5_keysalt salt;

    hist->key_data = (krb5_key_data*)malloc(n_key_data*sizeof(krb5_key_data));
    if (hist->key_data == NULL)
        return ENOMEM;
    memset(hist->key_data, 0, n_key_data*sizeof(krb5_key_data));

    for (i = 0; i < n_key_data; i++) {
        ret = krb5_dbekd_decrypt_key_data(context,
                                          mkey,
                                          &key_data[i],
                                          &key, &salt);
        if (ret)
            return ret;

        ret = krb5_dbekd_encrypt_key_data(context, hist_key,
                                          &key, &salt,
                                          key_data[i].key_data_kvno,
                                          &hist->key_data[i]);
        if (ret)
            return ret;

        krb5_free_keyblock_contents(context, &key);
        /* krb5_free_keysalt(context, &salt); */
    }

    hist->n_key_data = n_key_data;
    return 0;
}

static
void free_history_entry(krb5_context context, osa_pw_hist_ent *hist)
{
    int i;

    for (i = 0; i < hist->n_key_data; i++)
        krb5_free_key_data_contents(context, &hist->key_data[i]);
    free(hist->key_data);
}

/*
 * Function: add_to_history
 *
 * Purpose: Adds a password to a principal's password history.
 *
 * Arguments:
 *
 *      context         (r) krb5_context to use
 *      hist_kvno       (r) kvno of current history key
 *      adb             (r/w) admin principal entry to add keys to
 *      pol             (r) adb's policy
 *      pw              (r) keys for the password to add to adb's key history
 *
 * Effects:
 *
 * add_to_history adds a single password to adb's password history.
 * pw contains n_key_data keys in its key_data, in storage should be
 * allocated but not freed by the caller (XXX blech!).
 *
 * This function maintains adb->old_keys as a circular queue.  It
 * starts empty, and grows each time this function is called until it
 * is pol->pw_history_num items long.  adb->old_key_len holds the
 * number of allocated entries in the array, and must therefore be [0,
 * pol->pw_history_num).  adb->old_key_next is the index into the
 * array where the next element should be written, and must be [0,
 * adb->old_key_len).
 */
static kadm5_ret_t add_to_history(krb5_context context,
                                  krb5_kvno hist_kvno,
                                  osa_princ_ent_t adb,
                                  kadm5_policy_ent_t pol,
                                  osa_pw_hist_ent *pw)
{
    osa_pw_hist_ent *histp;
    uint32_t nhist;
    unsigned int i, knext, nkeys;

    nhist = pol->pw_history_num;
    /* A history of 1 means just check the current password */
    if (nhist <= 1)
        return 0;

    if (adb->admin_history_kvno != hist_kvno) {
        /* The history key has changed since the last password change, so we
         * have to reset the password history. */
        free(adb->old_keys);
        adb->old_keys = NULL;
        adb->old_key_len = 0;
        adb->old_key_next = 0;
        adb->admin_history_kvno = hist_kvno;
    }

    nkeys = adb->old_key_len;
    knext = adb->old_key_next;
    /* resize the adb->old_keys array if necessary */
    if (nkeys + 1 < nhist) {
        if (adb->old_keys == NULL) {
            adb->old_keys = (osa_pw_hist_ent *)
                malloc((nkeys + 1) * sizeof (osa_pw_hist_ent));
        } else {
            adb->old_keys = (osa_pw_hist_ent *)
                realloc(adb->old_keys,
                        (nkeys + 1) * sizeof (osa_pw_hist_ent));
        }
        if (adb->old_keys == NULL)
            return(ENOMEM);

        memset(&adb->old_keys[nkeys], 0, sizeof(osa_pw_hist_ent));
        nkeys = ++adb->old_key_len;
        /*
         * To avoid losing old keys, shift forward each entry after
         * knext.
         */
        for (i = nkeys - 1; i > knext; i--) {
            adb->old_keys[i] = adb->old_keys[i - 1];
        }
        memset(&adb->old_keys[knext], 0, sizeof(osa_pw_hist_ent));
    } else if (nkeys + 1 > nhist) {
        /*
         * The policy must have changed!  Shrink the array.
         * Can't simply realloc() down, since it might be wrapped.
         * To understand the arithmetic below, note that we are
         * copying into new positions 0 .. N-1 from old positions
         * old_key_next-N .. old_key_next-1, modulo old_key_len,
         * where N = pw_history_num - 1 is the length of the
         * shortened list.        Matt Crawford, FNAL
         */
        /*
         * M = adb->old_key_len, N = pol->pw_history_num - 1
         *
         * tmp[0] .. tmp[N-1] = old[(knext-N)%M] .. old[(knext-1)%M]
         */
        int j;
        osa_pw_hist_t tmp;

        tmp = (osa_pw_hist_ent *)
            malloc((nhist - 1) * sizeof (osa_pw_hist_ent));
        if (tmp == NULL)
            return ENOMEM;
        for (i = 0; i < nhist - 1; i++) {
            /*
             * Add nkeys once before taking remainder to avoid
             * negative values.
             */
            j = (i + nkeys + knext - (nhist - 1)) % nkeys;
            tmp[i] = adb->old_keys[j];
        }
        /* Now free the ones we don't keep (the oldest ones) */
        for (i = 0; i < nkeys - (nhist - 1); i++) {
            j = (i + nkeys + knext) % nkeys;
            histp = &adb->old_keys[j];
            for (j = 0; j < histp->n_key_data; j++) {
                krb5_free_key_data_contents(context, &histp->key_data[j]);
            }
            free(histp->key_data);
        }
        free(adb->old_keys);
        adb->old_keys = tmp;
        nkeys = adb->old_key_len = nhist - 1;
        knext = adb->old_key_next = 0;
    }

    /*
     * If nhist decreased since the last password change, and nkeys+1
     * is less than the previous nhist, it is possible for knext to
     * index into unallocated space.  This condition would not be
     * caught by the resizing code above.
     */
    if (knext + 1 > nkeys)
        knext = adb->old_key_next = 0;
    /* free the old pw history entry if it contains data */
    histp = &adb->old_keys[knext];
    for (i = 0; i < histp->n_key_data; i++)
        krb5_free_key_data_contents(context, &histp->key_data[i]);
    free(histp->key_data);

    /* store the new entry */
    adb->old_keys[knext] = *pw;

    /* update the next pointer */
    if (++adb->old_key_next == nhist - 1)
        adb->old_key_next = 0;

    return(0);
}

/* FIXME: don't use global variable for this */
krb5_boolean use_password_server = 0;

#ifdef USE_PASSWORD_SERVER
static krb5_boolean
kadm5_use_password_server (void)
{
    return use_password_server;
}
#endif

void
kadm5_set_use_password_server (void)
{
    use_password_server = 1;
}

#ifdef USE_PASSWORD_SERVER

/*
 * kadm5_launch_task () runs a program (task_path) to synchronize the
 * Apple password server with the Kerberos database.  Password server
 * programs can receive arguments on the command line (task_argv)
 * and a block of data via stdin (data_buffer).
 *
 * Because a failure to communicate with the tool results in the
 * password server falling out of sync with the database,
 * kadm5_launch_task() always fails if it can't talk to the tool.
 */

static kadm5_ret_t
kadm5_launch_task (krb5_context context,
                   const char *task_path, char * const task_argv[],
                   const char *buffer)
{
    kadm5_ret_t ret;
    int data_pipe[2];

    ret = pipe (data_pipe);
    if (ret)
        ret = errno;

    if (!ret) {
        pid_t pid = fork ();
        if (pid == -1) {
            ret = errno;
            close (data_pipe[0]);
            close (data_pipe[1]);
        } else if (pid == 0) {
            /* The child: */

            if (dup2 (data_pipe[0], STDIN_FILENO) == -1)
                _exit (1);

            close (data_pipe[0]);
            close (data_pipe[1]);

            execv (task_path, task_argv);

            _exit (1); /* Fail if execv fails */
        } else {
            /* The parent: */
            int status;

            ret = 0;

            close (data_pipe[0]);

            /* Write out the buffer to the child, add \n */
            if (buffer) {
                if (krb5_net_write (context, data_pipe[1], buffer, strlen (buffer)) < 0
                    || krb5_net_write (context, data_pipe[1], "\n", 1) < 0)
                {
                    /* kill the child to make sure waitpid() won't hang later */
                    ret = errno;
                    kill (pid, SIGKILL);
                }
            }
            close (data_pipe[1]);

            waitpid (pid, &status, 0);

            if (!ret) {
                if (WIFEXITED (status)) {
                    /* child read password and exited.  Check the return value. */
                    if ((WEXITSTATUS (status) != 0) && (WEXITSTATUS (status) != 252)) {
                        ret = KRB5KDC_ERR_POLICY; /* password change rejected */
                    }
                } else {
                    /* child read password but crashed or was killed */
                    ret = KRB5KRB_ERR_GENERIC; /* FIXME: better error */
                }
            }
        }
    }

    return ret;
}

#endif

kadm5_ret_t
kadm5_chpass_principal(void *server_handle,
                       krb5_principal principal, char *password)
{
    return
        kadm5_chpass_principal_3(server_handle, principal, FALSE,
                                 0, NULL, password);
}

kadm5_ret_t
kadm5_chpass_principal_3(void *server_handle,
                         krb5_principal principal, krb5_boolean keepold,
                         int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
                         char *password)
{
    krb5_int32                  now;
    kadm5_policy_ent_rec        pol;
    osa_princ_ent_rec           adb;
    krb5_db_entry               kdb, kdb_save;
    int                         ret, ret2, last_pwd, hist_added;
    int                         have_pol = 0;
    kadm5_server_handle_t       handle = server_handle;
    osa_pw_hist_ent             hist;
    krb5_keyblock               *act_mkey, hist_keyblock;
    krb5_kvno                   act_kvno, hist_kvno;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    hist_added = 0;
    memset(&hist, 0, sizeof(hist));
    memset(&hist_keyblock, 0, sizeof(hist_keyblock));

    if (principal == NULL || password == NULL)
        return EINVAL;
    if ((krb5_principal_compare(handle->context,
                                principal, hist_princ)) == TRUE)
        return KADM5_PROTECT_PRINCIPAL;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
        return(ret);

    /* we are going to need the current keys after the new keys are set */
    if ((ret = kdb_get_entry(handle, principal, &kdb_save, NULL))) {
        kdb_free_entry(handle, &kdb, &adb);
        return(ret);
    }

    if ((adb.aux_attributes & KADM5_POLICY)) {
        if ((ret = kadm5_get_policy(handle->lhandle, adb.policy, &pol)))
            goto done;
        have_pol = 1;
    }

    if ((ret = passwd_check(handle, password, adb.aux_attributes &
                            KADM5_POLICY, &pol, principal)))
        goto done;

    ret = krb5_dbe_find_act_mkey(handle->context, master_keylist,
                                 active_mkey_list, &act_kvno, &act_mkey);
    if (ret)
        goto done;

    ret = krb5_dbe_cpw(handle->context, act_mkey,
                       n_ks_tuple?ks_tuple:handle->params.keysalts,
                       n_ks_tuple?n_ks_tuple:handle->params.num_keysalts,
                       password, 0 /* increment kvno */,
                       keepold, &kdb);
    if (ret)
        goto done;

    ret = krb5_dbe_update_mkvno(handle->context, &kdb, act_kvno);
    if (ret)
        goto done;

    kdb.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;

    ret = krb5_timeofday(handle->context, &now);
    if (ret)
        goto done;

    if ((adb.aux_attributes & KADM5_POLICY)) {
        /* the policy was loaded before */

        ret = krb5_dbe_lookup_last_pwd_change(handle->context,
                                              &kdb, &last_pwd);
        if (ret)
            goto done;

#if 0
        /*
         * The spec says this check is overridden if the caller has
         * modify privilege.  The admin server therefore makes this
         * check itself (in chpass_principal_wrapper, misc.c). A
         * local caller implicitly has all authorization bits.
         */
        if ((now - last_pwd) < pol.pw_min_life &&
            !(kdb.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
            ret = KADM5_PASS_TOOSOON;
            goto done;
        }
#endif

        ret = kdb_get_hist_key(handle, &hist_keyblock, &hist_kvno);
        if (ret)
            goto done;

        ret = create_history_entry(handle->context,
                                   act_mkey, &hist_keyblock,
                                   kdb_save.n_key_data,
                                   kdb_save.key_data, &hist);
        if (ret)
            goto done;

        ret = check_pw_reuse(handle->context, act_mkey, &hist_keyblock,
                             kdb.n_key_data, kdb.key_data,
                             1, &hist);
        if (ret)
            goto done;

        if (pol.pw_history_num > 1) {
            /* If hist_kvno has changed since the last password change, we
             * can't check the history. */
            if (adb.admin_history_kvno == hist_kvno) {
                ret = check_pw_reuse(handle->context, act_mkey, &hist_keyblock,
                                     kdb.n_key_data, kdb.key_data,
                                     adb.old_key_len, adb.old_keys);
                if (ret)
                    goto done;
            }

            ret = add_to_history(handle->context, hist_kvno, &adb, &pol,
                                 &hist);
            if (ret)
                goto done;
            hist_added = 1;
        }

        if (pol.pw_max_life)
            kdb.pw_expiration = now + pol.pw_max_life;
        else
            kdb.pw_expiration = 0;
    } else {
        kdb.pw_expiration = 0;
    }

#ifdef USE_PASSWORD_SERVER
    if (kadm5_use_password_server () &&
        (krb5_princ_size (handle->context, principal) == 1)) {
        krb5_data *princ = krb5_princ_component (handle->context, principal, 0);
        const char *path = "/usr/sbin/mkpassdb";
        char *argv[] = { "mkpassdb", "-setpassword", NULL, NULL };
        char *pstring = NULL;

        if (!ret) {
            pstring = malloc ((princ->length + 1) * sizeof (char));
            if (pstring == NULL) { ret = ENOMEM; }
        }

        if (!ret) {
            memcpy (pstring, princ->data, princ->length);
            pstring [princ->length] = '\0';
            argv[2] = pstring;

            ret = kadm5_launch_task (handle->context, path, argv, password);
        }

        if (pstring != NULL)
            free (pstring);

        if (ret)
            goto done;
    }
#endif

    ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now);
    if (ret)
        goto done;

    /* unlock principal on this KDC */
    kdb.fail_auth_count = 0;

    /* key data and attributes changed, let the database provider know */
    kdb.mask = KADM5_KEY_DATA | KADM5_ATTRIBUTES |
        KADM5_FAIL_AUTH_COUNT;
    /* | KADM5_CPW_FUNCTION */

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
        goto done;

    ret = KADM5_OK;
done:
    if (!hist_added && hist.key_data)
        free_history_entry(handle->context, &hist);
    kdb_free_entry(handle, &kdb, &adb);
    kdb_free_entry(handle, &kdb_save, NULL);
    krb5_db_free_principal(handle->context, &kdb, 1);
    krb5_free_keyblock_contents(handle->context, &hist_keyblock);

    if (have_pol && (ret2 = kadm5_free_policy_ent(handle->lhandle, &pol))
        && !ret)
        ret = ret2;

    return ret;
}

kadm5_ret_t
kadm5_randkey_principal(void *server_handle,
                        krb5_principal principal,
                        krb5_keyblock **keyblocks,
                        int *n_keys)
{
    return
        kadm5_randkey_principal_3(server_handle, principal,
                                  FALSE, 0, NULL,
                                  keyblocks, n_keys);
}
kadm5_ret_t
kadm5_randkey_principal_3(void *server_handle,
                          krb5_principal principal,
                          krb5_boolean keepold,
                          int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
                          krb5_keyblock **keyblocks,
                          int *n_keys)
{
    krb5_db_entry               kdb;
    osa_princ_ent_rec           adb;
    krb5_int32                  now;
    kadm5_policy_ent_rec        pol;
    int                         ret, last_pwd, have_pol = 0;
    kadm5_server_handle_t       handle = server_handle;
    krb5_keyblock               *act_mkey;

    if (keyblocks)
        *keyblocks = NULL;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (principal == NULL)
        return EINVAL;
    if (krb5_principal_compare(handle->context, principal, hist_princ)) {
        /* If changing the history entry, the new entry must have exactly one
         * key. */
        if (keepold)
            return KADM5_PROTECT_PRINCIPAL;
        ks_tuple = n_ks_tuple ? ks_tuple : handle->params.keysalts,
        n_ks_tuple = 1;
    }

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
        return(ret);

    ret = krb5_dbe_find_act_mkey(handle->context, master_keylist,
                                 active_mkey_list, NULL, &act_mkey);
    if (ret)
        goto done;

    ret = krb5_dbe_crk(handle->context, act_mkey,
                       n_ks_tuple?ks_tuple:handle->params.keysalts,
                       n_ks_tuple?n_ks_tuple:handle->params.num_keysalts,
                       keepold,
                       &kdb);
    if (ret)
        goto done;

    kdb.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;

    ret = krb5_timeofday(handle->context, &now);
    if (ret)
        goto done;

    if ((adb.aux_attributes & KADM5_POLICY)) {
        if ((ret = kadm5_get_policy(handle->lhandle, adb.policy,
                                    &pol)) != KADM5_OK)
            goto done;
        have_pol = 1;

        ret = krb5_dbe_lookup_last_pwd_change(handle->context,
                                              &kdb, &last_pwd);
        if (ret)
            goto done;

#if 0
        /*
         * The spec says this check is overridden if the caller has
         * modify privilege.  The admin server therefore makes this
         * check itself (in chpass_principal_wrapper, misc.c).  A
         * local caller implicitly has all authorization bits.
         */
        if((now - last_pwd) < pol.pw_min_life &&
           !(kdb.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
            ret = KADM5_PASS_TOOSOON;
            goto done;
        }
#endif

        if (pol.pw_max_life)
            kdb.pw_expiration = now + pol.pw_max_life;
        else
            kdb.pw_expiration = 0;
    } else {
        kdb.pw_expiration = 0;
    }

    ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now);
    if (ret)
        goto done;

    /* unlock principal on this KDC */
    kdb.fail_auth_count = 0;

    if (keyblocks) {
        ret = decrypt_key_data(handle->context, act_mkey,
                               kdb.n_key_data, kdb.key_data,
                               keyblocks, n_keys);
        if (ret)
            goto done;
    }

    /* key data changed, let the database provider know */
    kdb.mask = KADM5_KEY_DATA | KADM5_FAIL_AUTH_COUNT;
    /* | KADM5_RANDKEY_USED */;

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
        goto done;

    ret = KADM5_OK;
done:
    kdb_free_entry(handle, &kdb, &adb);
    if (have_pol)
        kadm5_free_policy_ent(handle->lhandle, &pol);

    return ret;
}

/*
 * kadm5_setv4key_principal:
 *
 * Set only ONE key of the principal, removing all others.  This key
 * must have the DES_CBC_CRC enctype and is entered as having the
 * krb4 salttype.  This is to enable things like kadmind4 to work.
 */
kadm5_ret_t
kadm5_setv4key_principal(void *server_handle,
                         krb5_principal principal,
                         krb5_keyblock *keyblock)
{
    krb5_db_entry               kdb;
    osa_princ_ent_rec           adb;
    krb5_int32                  now;
    kadm5_policy_ent_rec        pol;
    krb5_keysalt                keysalt;
    int                         i, k, kvno, ret, have_pol = 0;
#if 0
    int                         last_pwd;
#endif
    kadm5_server_handle_t       handle = server_handle;
    krb5_key_data               tmp_key_data;
    krb5_keyblock               *act_mkey;

    memset( &tmp_key_data, 0, sizeof(tmp_key_data));

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (principal == NULL || keyblock == NULL)
        return EINVAL;
    if (hist_princ && /* this will be NULL when initializing the databse */
        ((krb5_principal_compare(handle->context,
                                 principal, hist_princ)) == TRUE))
        return KADM5_PROTECT_PRINCIPAL;

    if (keyblock->enctype != ENCTYPE_DES_CBC_CRC)
        return KADM5_SETV4KEY_INVAL_ENCTYPE;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
        return(ret);

    for (kvno = 0, i=0; i<kdb.n_key_data; i++)
        if (kdb.key_data[i].key_data_kvno > kvno)
            kvno = kdb.key_data[i].key_data_kvno;

    if (kdb.key_data != NULL)
        cleanup_key_data(handle->context, kdb.n_key_data, kdb.key_data);

    kdb.key_data = (krb5_key_data*)krb5_db_alloc(handle->context, NULL, sizeof(krb5_key_data));
    if (kdb.key_data == NULL)
        return ENOMEM;
    memset(kdb.key_data, 0, sizeof(krb5_key_data));
    kdb.n_key_data = 1;
    keysalt.type = KRB5_KDB_SALTTYPE_V4;
    /* XXX data.magic? */
    keysalt.data.length = 0;
    keysalt.data.data = NULL;

    ret = krb5_dbe_find_act_mkey(handle->context, master_keylist,
                                 active_mkey_list, NULL, &act_mkey);
    if (ret)
        goto done;

    /* use tmp_key_data as temporary location and reallocate later */
    ret = krb5_dbekd_encrypt_key_data(handle->context, act_mkey,
                                      keyblock, &keysalt, kvno + 1,
                                      &tmp_key_data);
    if (ret) {
        goto done;
    }

    for (k = 0; k < tmp_key_data.key_data_ver; k++) {
        kdb.key_data->key_data_type[k] = tmp_key_data.key_data_type[k];
        kdb.key_data->key_data_length[k] = tmp_key_data.key_data_length[k];
        if (tmp_key_data.key_data_contents[k]) {
            kdb.key_data->key_data_contents[k] = krb5_db_alloc(handle->context, NULL, tmp_key_data.key_data_length[k]);
            if (kdb.key_data->key_data_contents[k] == NULL) {
                cleanup_key_data(handle->context, kdb.n_key_data, kdb.key_data);
                kdb.key_data = NULL;
                kdb.n_key_data = 0;
                ret = ENOMEM;
                goto done;
            }
            memcpy (kdb.key_data->key_data_contents[k], tmp_key_data.key_data_contents[k], tmp_key_data.key_data_length[k]);

            memset (tmp_key_data.key_data_contents[k], 0, tmp_key_data.key_data_length[k]);
            free (tmp_key_data.key_data_contents[k]);
            tmp_key_data.key_data_contents[k] = NULL;
        }
    }



    kdb.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;

    ret = krb5_timeofday(handle->context, &now);
    if (ret)
        goto done;

    if ((adb.aux_attributes & KADM5_POLICY)) {
        if ((ret = kadm5_get_policy(handle->lhandle, adb.policy,
                                    &pol)) != KADM5_OK)
            goto done;
        have_pol = 1;

#if 0
        /*
         * The spec says this check is overridden if the caller has
         * modify privilege.  The admin server therefore makes this
         * check itself (in chpass_principal_wrapper, misc.c).  A
         * local caller implicitly has all authorization bits.
         */
        if (ret = krb5_dbe_lookup_last_pwd_change(handle->context,
                                                  &kdb, &last_pwd))
            goto done;
        if((now - last_pwd) < pol.pw_min_life &&
           !(kdb.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
            ret = KADM5_PASS_TOOSOON;
            goto done;
        }
#endif

        if (pol.pw_max_life)
            kdb.pw_expiration = now + pol.pw_max_life;
        else
            kdb.pw_expiration = 0;
    } else {
        kdb.pw_expiration = 0;
    }

    ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now);
    if (ret)
        goto done;

    /* unlock principal on this KDC */
    kdb.fail_auth_count = 0;

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
        goto done;

    ret = KADM5_OK;
done:
    for (i = 0; i < tmp_key_data.key_data_ver; i++) {
        if (tmp_key_data.key_data_contents[i]) {
            memset (tmp_key_data.key_data_contents[i], 0, tmp_key_data.key_data_length[i]);
            free (tmp_key_data.key_data_contents[i]);
        }
    }

    kdb_free_entry(handle, &kdb, &adb);
    if (have_pol)
        kadm5_free_policy_ent(handle->lhandle, &pol);

    return ret;
}

kadm5_ret_t
kadm5_setkey_principal(void *server_handle,
                       krb5_principal principal,
                       krb5_keyblock *keyblocks,
                       int n_keys)
{
    return
        kadm5_setkey_principal_3(server_handle, principal,
                                 FALSE, 0, NULL,
                                 keyblocks, n_keys);
}

kadm5_ret_t
kadm5_setkey_principal_3(void *server_handle,
                         krb5_principal principal,
                         krb5_boolean keepold,
                         int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
                         krb5_keyblock *keyblocks,
                         int n_keys)
{
    krb5_db_entry               kdb;
    osa_princ_ent_rec           adb;
    krb5_int32                  now;
    kadm5_policy_ent_rec        pol;
    krb5_key_data               *old_key_data;
    int                         n_old_keys;
    int                         i, j, k, kvno, ret, have_pol = 0;
#if 0
    int                         last_pwd;
#endif
    kadm5_server_handle_t       handle = server_handle;
    krb5_boolean                similar;
    krb5_keysalt                keysalt;
    krb5_key_data         tmp_key_data;
    krb5_key_data        *tptr;
    krb5_keyblock               *act_mkey;

    CHECK_HANDLE(server_handle);

    krb5_clear_error_message(handle->context);

    if (principal == NULL || keyblocks == NULL)
        return EINVAL;
    if (hist_princ && /* this will be NULL when initializing the databse */
        ((krb5_principal_compare(handle->context,
                                 principal, hist_princ)) == TRUE))
        return KADM5_PROTECT_PRINCIPAL;

    for (i = 0; i < n_keys; i++) {
        for (j = i+1; j < n_keys; j++) {
            if ((ret = krb5_c_enctype_compare(handle->context,
                                              keyblocks[i].enctype,
                                              keyblocks[j].enctype,
                                              &similar)))
                return(ret);
            if (similar) {
                if (n_ks_tuple) {
                    if (ks_tuple[i].ks_salttype == ks_tuple[j].ks_salttype)
                        return KADM5_SETKEY_DUP_ENCTYPES;
                } else
                    return KADM5_SETKEY_DUP_ENCTYPES;
            }
        }
    }

    if (n_ks_tuple && n_ks_tuple != n_keys)
        return KADM5_SETKEY3_ETYPE_MISMATCH;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
        return(ret);

    for (kvno = 0, i=0; i<kdb.n_key_data; i++)
        if (kdb.key_data[i].key_data_kvno > kvno)
            kvno = kdb.key_data[i].key_data_kvno;

    if (keepold) {
        old_key_data = kdb.key_data;
        n_old_keys = kdb.n_key_data;
    } else {
        if (kdb.key_data != NULL)
            cleanup_key_data(handle->context, kdb.n_key_data, kdb.key_data);
        n_old_keys = 0;
        old_key_data = NULL;
    }

    kdb.key_data = (krb5_key_data*)krb5_db_alloc(handle->context, NULL, (n_keys+n_old_keys)
                                                 *sizeof(krb5_key_data));
    if (kdb.key_data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    memset(kdb.key_data, 0, (n_keys+n_old_keys)*sizeof(krb5_key_data));
    kdb.n_key_data = 0;

    for (i = 0; i < n_keys; i++) {
        if (n_ks_tuple) {
            keysalt.type = ks_tuple[i].ks_salttype;
            keysalt.data.length = 0;
            keysalt.data.data = NULL;
            if (ks_tuple[i].ks_enctype != keyblocks[i].enctype) {
                ret = KADM5_SETKEY3_ETYPE_MISMATCH;
                goto done;
            }
        }
        memset (&tmp_key_data, 0, sizeof(tmp_key_data));

        ret = krb5_dbe_find_act_mkey(handle->context, master_keylist,
                                     active_mkey_list, NULL, &act_mkey);
        if (ret)
            goto done;

        ret = krb5_dbekd_encrypt_key_data(handle->context,
                                          act_mkey,
                                          &keyblocks[i],
                                          n_ks_tuple ? &keysalt : NULL,
                                          kvno + 1,
                                          &tmp_key_data);
        if (ret)
            goto done;

        tptr = &kdb.key_data[i];
        tptr->key_data_ver = tmp_key_data.key_data_ver;
        tptr->key_data_kvno = tmp_key_data.key_data_kvno;
        for (k = 0; k < tmp_key_data.key_data_ver; k++) {
            tptr->key_data_type[k] = tmp_key_data.key_data_type[k];
            tptr->key_data_length[k] = tmp_key_data.key_data_length[k];
            if (tmp_key_data.key_data_contents[k]) {
                tptr->key_data_contents[k] = krb5_db_alloc(handle->context, NULL, tmp_key_data.key_data_length[k]);
                if (tptr->key_data_contents[k] == NULL) {
                    int i1;
                    for (i1 = k; i1 < tmp_key_data.key_data_ver; i1++) {
                        if (tmp_key_data.key_data_contents[i1]) {
                            memset (tmp_key_data.key_data_contents[i1], 0, tmp_key_data.key_data_length[i1]);
                            free (tmp_key_data.key_data_contents[i1]);
                        }
                    }

                    ret =  ENOMEM;
                    goto done;
                }
                memcpy (tptr->key_data_contents[k], tmp_key_data.key_data_contents[k], tmp_key_data.key_data_length[k]);

                memset (tmp_key_data.key_data_contents[k], 0, tmp_key_data.key_data_length[k]);
                free (tmp_key_data.key_data_contents[k]);
                tmp_key_data.key_data_contents[k] = NULL;
            }
        }
        kdb.n_key_data++;
    }

    /* copy old key data if necessary */
    for (i = 0; i < n_old_keys; i++) {
        kdb.key_data[i+n_keys] = old_key_data[i];
        memset(&old_key_data[i], 0, sizeof (krb5_key_data));
        kdb.n_key_data++;
    }

    if (old_key_data)
        krb5_db_free(handle->context, old_key_data);

    /* assert(kdb.n_key_data == n_keys + n_old_keys) */
    kdb.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;

    if ((ret = krb5_timeofday(handle->context, &now)))
        goto done;

    if ((adb.aux_attributes & KADM5_POLICY)) {
        if ((ret = kadm5_get_policy(handle->lhandle, adb.policy,
                                    &pol)) != KADM5_OK)
            goto done;
        have_pol = 1;

#if 0
        /*
         * The spec says this check is overridden if the caller has
         * modify privilege.  The admin server therefore makes this
         * check itself (in chpass_principal_wrapper, misc.c).  A
         * local caller implicitly has all authorization bits.
         */
        if (ret = krb5_dbe_lookup_last_pwd_change(handle->context,
                                                  &kdb, &last_pwd))
            goto done;
        if((now - last_pwd) < pol.pw_min_life &&
           !(kdb.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
            ret = KADM5_PASS_TOOSOON;
            goto done;
        }
#endif

        if (pol.pw_max_life)
            kdb.pw_expiration = now + pol.pw_max_life;
        else
            kdb.pw_expiration = 0;
    } else {
        kdb.pw_expiration = 0;
    }

    if ((ret = krb5_dbe_update_last_pwd_change(handle->context, &kdb, now)))
        goto done;

    /* unlock principal on this KDC */
    kdb.fail_auth_count = 0;

    if ((ret = kdb_put_entry(handle, &kdb, &adb)))
        goto done;

    ret = KADM5_OK;
done:
    kdb_free_entry(handle, &kdb, &adb);
    if (have_pol)
        kadm5_free_policy_ent(handle->lhandle, &pol);

    return ret;
}

/*
 * Return the list of keys like kadm5_randkey_principal,
 * but don't modify the principal.
 */
kadm5_ret_t
kadm5_get_principal_keys(void *server_handle /* IN */,
                         krb5_principal principal /* IN */,
                         krb5_keyblock **keyblocks /* OUT */,
                         int *n_keys /* OUT */)
{
    krb5_db_entry               kdb;
    osa_princ_ent_rec           adb;
    kadm5_ret_t                 ret;
    kadm5_server_handle_t       handle = server_handle;
    krb5_keyblock               *mkey_ptr;

    if (keyblocks)
        *keyblocks = NULL;

    CHECK_HANDLE(server_handle);

    if (principal == NULL)
        return EINVAL;

    if ((ret = kdb_get_entry(handle, principal, &kdb, &adb)))
        return(ret);

    if (keyblocks) {
        if ((ret = krb5_dbe_find_mkey(handle->context, master_keylist, &kdb,
                                      &mkey_ptr))) {
            krb5_keylist_node *tmp_mkey_list;
            /* try refreshing master key list */
            /* XXX it would nice if we had the mkvno here for optimization */
            if (krb5_db_fetch_mkey_list(handle->context, master_princ,
                                        &master_keyblock, 0,
                                        &tmp_mkey_list) == 0) {
                krb5_dbe_free_key_list(handle->context, master_keylist);
                master_keylist = tmp_mkey_list;
                if ((ret = krb5_dbe_find_mkey(handle->context, master_keylist,
                                              &kdb, &mkey_ptr))) {
                    goto done;
                }
            } else {
                goto done;
            }
        }

        ret = decrypt_key_data(handle->context, mkey_ptr,
                               kdb.n_key_data, kdb.key_data,
                               keyblocks, n_keys);
        if (ret)
            goto done;
    }

    ret = KADM5_OK;
done:
    kdb_free_entry(handle, &kdb, &adb);

    return ret;
}


/*
 * Allocate an array of n_key_data krb5_keyblocks, fill in each
 * element with the results of decrypting the nth key in key_data with
 * mkey, and if n_keys is not NULL fill it in with the
 * number of keys decrypted.
 */
static int decrypt_key_data(krb5_context context, krb5_keyblock *mkey,
                            int n_key_data, krb5_key_data *key_data,
                            krb5_keyblock **keyblocks, int *n_keys)
{
    krb5_keyblock *keys;
    int ret, i;

    keys = (krb5_keyblock *) malloc(n_key_data*sizeof(krb5_keyblock));
    if (keys == NULL)
        return ENOMEM;
    memset(keys, 0, n_key_data*sizeof(krb5_keyblock));

    for (i = 0; i < n_key_data; i++) {
        ret = krb5_dbekd_decrypt_key_data(context, mkey,
                                          &key_data[i],
                                          &keys[i], NULL);
        if (ret) {
            for (; i >= 0; i--) {
                if (keys[i].contents) {
                    memset (keys[i].contents, 0, keys[i].length);
                    free( keys[i].contents );
                }
            }

            memset(keys, 0, n_key_data*sizeof(krb5_keyblock));
            free(keys);
            return ret;
        }
    }

    *keyblocks = keys;
    if (n_keys)
        *n_keys = n_key_data;

    return 0;
}

/*
 * Function: kadm5_decrypt_key
 *
 * Purpose: Retrieves and decrypts a principal key.
 *
 * Arguments:
 *
 *      server_handle   (r) kadm5 handle
 *      entry           (r) principal retrieved with kadm5_get_principal
 *      ktype           (r) enctype to search for, or -1 to ignore
 *      stype           (r) salt type to search for, or -1 to ignore
 *      kvno            (r) kvno to search for, -1 for max, 0 for max
 *                      only if it also matches ktype and stype
 *      keyblock        (w) keyblock to fill in
 *      keysalt         (w) keysalt to fill in, or NULL
 *      kvnop           (w) kvno to fill in, or NULL
 *
 * Effects: Searches the key_data array of entry, which must have been
 * retrived with kadm5_get_principal with the KADM5_KEY_DATA mask, to
 * find a key with a specified enctype, salt type, and kvno in a
 * principal entry.  If not found, return ENOENT.  Otherwise, decrypt
 * it with the master key, and return the key in keyblock, the salt
 * in salttype, and the key version number in kvno.
 *
 * If ktype or stype is -1, it is ignored for the search.  If kvno is
 * -1, ktype and stype are ignored and the key with the max kvno is
 * returned.  If kvno is 0, only the key with the max kvno is returned
 * and only if it matches the ktype and stype; otherwise, ENOENT is
 * returned.
 */
kadm5_ret_t kadm5_decrypt_key(void *server_handle,
                              kadm5_principal_ent_t entry, krb5_int32
                              ktype, krb5_int32 stype, krb5_int32
                              kvno, krb5_keyblock *keyblock,
                              krb5_keysalt *keysalt, int *kvnop)
{
    kadm5_server_handle_t handle = server_handle;
    krb5_db_entry dbent;
    krb5_key_data *key_data;
    krb5_keyblock *mkey_ptr;
    int ret;

    CHECK_HANDLE(server_handle);

    if (entry->n_key_data == 0 || entry->key_data == NULL)
        return EINVAL;

    /* find_enctype only uses these two fields */
    dbent.n_key_data = entry->n_key_data;
    dbent.key_data = entry->key_data;
    if ((ret = krb5_dbe_find_enctype(handle->context, &dbent, ktype,
                                     stype, kvno, &key_data)))
        return ret;

    /* find_mkey only uses this field */
    dbent.tl_data = entry->tl_data;
    if ((ret = krb5_dbe_find_mkey(handle->context, master_keylist, &dbent,
                                  &mkey_ptr))) {
        krb5_keylist_node *tmp_mkey_list;
        /* try refreshing master key list */
        /* XXX it would nice if we had the mkvno here for optimization */
        if (krb5_db_fetch_mkey_list(handle->context, master_princ,
                                    &master_keyblock, 0, &tmp_mkey_list) == 0) {
            krb5_dbe_free_key_list(handle->context, master_keylist);
            master_keylist = tmp_mkey_list;
            if ((ret = krb5_dbe_find_mkey(handle->context, master_keylist,
                                          &dbent, &mkey_ptr))) {
                return ret;
            }
        } else {
            return ret;
        }
    }

    if ((ret = krb5_dbekd_decrypt_key_data(handle->context,
                                           mkey_ptr, key_data,
                                           keyblock, keysalt)))
        return ret;

    /*
     * Coerce the enctype of the output keyblock in case we got an
     * inexact match on the enctype; this behavior will go away when
     * the key storage architecture gets redesigned for 1.3.
     */
    if (ktype != -1)
        keyblock->enctype = ktype;

    if (kvnop)
        *kvnop = key_data->key_data_kvno;

    return KADM5_OK;
}
