/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/kdb/hdb/kdb_hdb.c */
/*
 * Copyright 2009 by the Massachusetts Institute of Technology.
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

#include "k5-int.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <db.h>
#include <stdio.h>
#include <errno.h>
#include <utime.h>
#include "kdb5.h"
#include "kdb_hdb.h"

static krb5_error_code
kh_init(void)
{
    return 0;
}

static krb5_error_code
kh_fini(void)
{
    return 0;
}

krb5_error_code
kh_map_error(heim_error_code code)
{
    switch (code) {
    case HDB_ERR_UK_SERROR:
        code = KRB5_KDB_UK_SERROR;
        break;
    case HDB_ERR_UK_RERROR:
        code = KRB5_KDB_UK_RERROR;
        break;
    case HDB_ERR_NOENTRY:
        code = KRB5_KDB_NOENTRY;
        break;
    case HDB_ERR_DB_INUSE:
        code = KRB5_KDB_DB_INUSE;
        break;
    case HDB_ERR_DB_CHANGED:
        code = KRB5_KDB_DB_CHANGED;
        break;
    case HDB_ERR_RECURSIVELOCK:
        code = KRB5_KDB_RECURSIVELOCK;
        break;
    case HDB_ERR_NOTLOCKED:
        code = KRB5_KDB_NOTLOCKED;
        break;
    case HDB_ERR_BADLOCKMODE:
        code = KRB5_KDB_BADLOCKMODE;
        break;
    case HDB_ERR_CANT_LOCK_DB:
        code = KRB5_KDB_CANTLOCK_DB;
        break;
    case HDB_ERR_EXISTS:
        code = EEXIST;
        break;
    case HDB_ERR_BADVERSION:
        code = KRB5_KDB_BAD_VERSION;
        break;
    case HDB_ERR_NO_MKEY:
        code = KRB5_KDB_NOMASTERKEY;
        break;
    case HDB_ERR_MANDATORY_OPTION:
        code = KRB5_PLUGIN_OP_NOTSUPP;
        break;
    default:
        break;
    }

    return code;
}

static void
kh_db_context_free(krb5_context context, kh_db_context *kh)
{
    if (kh != NULL) {
        if (kh->hdb != NULL)
            (*kh->hdb->hdb_destroy)(kh->hcontext, kh->hdb);
        if (kh->hcontext != NULL)
            (*kh->heim_free_context)(kh->hcontext);
        if (kh->libkrb5 != NULL)
            krb5int_close_plugin(kh->libkrb5);
        if (kh->libhdb != NULL)
            krb5int_close_plugin(kh->libhdb);
        if (kh->windc != NULL)
            (*kh->windc->fini)(kh->windc_ctx);
        krb5int_close_plugin_dirs(&kh->windc_plugins);
        krb5int_mutex_free(kh->lock);
        free(kh);
    }
}

static krb5_error_code
kh_db_context_init(krb5_context context,
                   const char *libdir,
                   const char *filename,
                   int mode,
                   kh_db_context **pkh)
{
    kh_db_context *kh;
    krb5_error_code code;
    char *libhdb = NULL;
    char *libkrb5 = NULL;
    struct errinfo errinfo;
    int *hdb_interface_version;

    if (libdir == NULL)
        return KRB5_KDB_DBTYPE_INIT; /* XXX */

    memset(&errinfo, 0, sizeof(errinfo));

    kh = k5alloc(sizeof(*kh), &code);
    if (code != 0)
        goto cleanup;

    code = krb5int_mutex_alloc(&kh->lock);
    if (code != 0)
        goto cleanup;

    if (asprintf(&libkrb5, "%s/libkrb5%s", libdir, SHLIBEXT) < 0) {
        code = ENOMEM;
        goto cleanup;
    }

#define GET_PLUGIN_FUNC(_lib, _sym, _member)     do {                   \
        code = krb5int_get_plugin_func(kh->_lib, _sym,                  \
                                       (void (**)())&kh->_member, &errinfo); \
        if (code != 0)                                                  \
            goto cleanup;                                               \
    } while (0)

    /* libkrb5 */
    code = krb5int_open_plugin(libkrb5, &kh->libkrb5, &errinfo);
    if (code != 0)
        goto cleanup;

    GET_PLUGIN_FUNC(libkrb5, "krb5_init_context",     heim_init_context);
    GET_PLUGIN_FUNC(libkrb5, "krb5_free_context",     heim_free_context);
    GET_PLUGIN_FUNC(libkrb5, "krb5_free_principal",   heim_free_principal);
    GET_PLUGIN_FUNC(libkrb5, "krb5_free_addresses",   heim_free_addresses);
    GET_PLUGIN_FUNC(libkrb5, "krb5_pac_free",         heim_pac_free);
    GET_PLUGIN_FUNC(libkrb5, "krb5_pac_parse",        heim_pac_parse);
    GET_PLUGIN_FUNC(libkrb5, "krb5_pac_verify",       heim_pac_verify);
    GET_PLUGIN_FUNC(libkrb5, "_krb5_pac_sign",        heim_pac_sign);

    if (asprintf(&libhdb, "%s/libhdb%s", libdir, SHLIBEXT) < 0)
        goto cleanup;

    /* libhdb */
    code = krb5int_open_plugin(libhdb, &kh->libhdb, &errinfo);
    if (code != 0)
        goto cleanup;

    /*
     * New versions of Heimdal export this symbol to mark the
     * HDB ABI version.
     */
    if (krb5int_get_plugin_data(kh->libhdb, "hdb_interface_version",
                                (void **)&hdb_interface_version,
                                &errinfo) == 0 &&
        *hdb_interface_version != HDB_INTERFACE_VERSION) {
        code = KRB5_PLUGIN_OP_NOTSUPP;
        goto cleanup;
    }

    GET_PLUGIN_FUNC(libhdb,  "hdb_create",            hdb_create);
    GET_PLUGIN_FUNC(libhdb,  "hdb_seal_key",          hdb_seal_key);
    GET_PLUGIN_FUNC(libhdb,  "hdb_unseal_key",        hdb_unseal_key);
    GET_PLUGIN_FUNC(libhdb,  "hdb_set_master_key",    hdb_set_master_key);
    GET_PLUGIN_FUNC(libhdb,  "hdb_free_entry",        hdb_free_entry);

    code = kh_map_error((*kh->heim_init_context)(&kh->hcontext));
    if (code != 0)
        goto cleanup;

    code = kh_map_error((*kh->hdb_create)(kh->hcontext, &kh->hdb, filename));
    if (code != 0)
        goto cleanup;

    if (mode & KRB5_KDB_OPEN_RO)
        kh->mode = O_RDONLY;
    else
        kh->mode = O_RDWR;

    if (mode & KRB5_KDB_SRV_TYPE_KDC)
        kh_hdb_windc_init(context, libdir, kh);

cleanup:
    if (code != 0) {
        kh_db_context_free(context, kh);
        kh = NULL;
    }

    krb5int_free_error(&errinfo, NULL);

    *pkh = kh;

    return code;
}

static krb5_error_code
kh_init_module(krb5_context context,
               char *conf_section,
               char **db_args,
               int mode)
{
    kdb5_dal_handle *dal_handle = context->dal_handle;
    krb5_error_code code;
    kh_db_context *kh;
    char *libdir = NULL;
    char *filename = NULL;

    if (dal_handle->db_context != NULL) {
        kh_db_context_free(context, dal_handle->db_context);
        dal_handle->db_context = NULL;
    }

    code = profile_get_string(context->profile,
                              KDB_MODULE_SECTION,
                              conf_section,
                              "heimdal_libdir",
                              NULL,
                              &libdir);
    if (code != 0)
        goto cleanup;

    code = profile_get_string(context->profile,
                              KDB_MODULE_SECTION,
                              conf_section,
                              "heimdal_dbname",
                              NULL,
                              &filename);
    if (code != 0)
        goto cleanup;

    code = kh_db_context_init(context, libdir, filename, mode, &kh);
    if (code != 0)
        goto cleanup;

    dal_handle->db_context = kh;

cleanup:
    if (libdir != NULL)
        free(libdir);
    if (filename != NULL)
        free(filename);

    return 0;
}

static krb5_error_code
kh_fini_module(krb5_context context)
{
    kdb5_dal_handle *dal_handle = context->dal_handle;

    kh_db_context_free(context, dal_handle->db_context);
    dal_handle->db_context = NULL;

    return 0;
}

/*
 * Heimdal API and SPI wrappers.
 */

static krb5_error_code
kh_hdb_open(krb5_context context,
            kh_db_context *kh,
            int oflag,
            mode_t mode)
{
    heim_error_code hcode;

    hcode = (*kh->hdb->hdb_open)(kh->hcontext, kh->hdb, oflag, mode);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_close(krb5_context context,kh_db_context *kh)
{
    heim_error_code hcode;

    hcode = (*kh->hdb->hdb_close)(kh->hcontext, kh->hdb);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_fetch(krb5_context context,
             kh_db_context *kh,
             const Principal *princ,
             unsigned int flags,
             hdb_entry_ex *entry)
{
    heim_error_code hcode;

    hcode = (*kh->hdb->hdb_fetch)(kh->hcontext, kh->hdb, princ, flags, entry);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_store(krb5_context context,
             kh_db_context *kh,
             unsigned int flags,
             hdb_entry_ex *entry)
{
    heim_error_code hcode;

    hcode = (*kh->hdb->hdb_store)(kh->hcontext, kh->hdb, flags, entry);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_remove(krb5_context context,
              kh_db_context *kh,
              const Principal *princ)
{
    heim_error_code hcode;

    hcode = (*kh->hdb->hdb_remove)(kh->hcontext, kh->hdb, princ);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_firstkey(krb5_context context,
                kh_db_context *kh,
                unsigned int flags,
                hdb_entry_ex *entry)
{
    heim_error_code hcode;

    hcode = (*kh->hdb->hdb_firstkey)(kh->hcontext, kh->hdb, flags, entry);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_nextkey(krb5_context context,
               kh_db_context *kh,
               unsigned int flags,
               hdb_entry_ex *entry)
{
    heim_error_code hcode;

    hcode = (*kh->hdb->hdb_nextkey)(kh->hcontext, kh->hdb, flags, entry);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_lock(krb5_context context,
            kh_db_context *kh,
            int operation)
{
    heim_error_code hcode;

    hcode = (*kh->hdb->hdb_lock)(kh->hcontext, kh->hdb, operation);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_unlock(krb5_context context,
              kh_db_context *kh)
{
    heim_error_code hcode;

    hcode = (*kh->hdb->hdb_unlock)(kh->hcontext, kh->hdb);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_rename(krb5_context context,
              kh_db_context *kh,
              const char *name)
{
    heim_error_code hcode;

    if (kh->hdb->hdb_rename == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;

    hcode = (*kh->hdb->hdb_rename)(kh->hcontext, kh->hdb, name);

    return kh_map_error(hcode);
}

static HDB_extension *
kh_hdb_find_extension(const hdb_entry *entry, unsigned int type)
{
    unsigned int i;
    HDB_extension *ret = NULL;

    if (entry->extensions != NULL) {
        for (i = 0; i < entry->extensions->len; i++) {
            if (entry->extensions->val[i].data.element == type) {
                ret = &entry->extensions->val[i];
                break;
            }
        }
    }

    return ret;
}

static krb5_error_code
kh_hdb_seal_key(krb5_context context,
                kh_db_context *kh,
                Key *key)
{
    heim_error_code hcode;

    hcode = (*kh->hdb_seal_key)(kh->hcontext, kh->hdb, key);

    return kh_map_error(hcode);
}

static krb5_error_code
kh_hdb_unseal_key(krb5_context context,
                  kh_db_context *kh,
                  Key *key)
{
    heim_error_code hcode;

    hcode = (*kh->hdb_unseal_key)(kh->hcontext, kh->hdb, key);

    return kh_map_error(hcode);
}

void
kh_hdb_free_entry(krb5_context context,
                  kh_db_context *kh,
                  hdb_entry_ex *entry)
{
    (*kh->hdb_free_entry)(kh->hcontext, entry);
}

void
kh_kdb_free_entry(krb5_context context,
                  kh_db_context *kh,
                  krb5_db_entry *entry)
{
    krb5_tl_data *tl_data_next = NULL;
    krb5_tl_data *tl_data = NULL;
    int i, j;

    if (entry == NULL)
        return;
    if (entry->e_data != NULL) {
        assert(entry->e_length == sizeof(hdb_entry_ex));
        kh_hdb_free_entry(context, kh, KH_DB_ENTRY(entry));
        free(entry->e_data);
    }

    krb5_free_principal(context, entry->princ);

    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data_next) {
        tl_data_next = tl_data->tl_data_next;
        if (tl_data->tl_data_contents != NULL)
            free(tl_data->tl_data_contents);
        free(tl_data);
    }

    if (entry->key_data != NULL) {
        for (i = 0; i < entry->n_key_data; i++) {
            for (j = 0; j < entry->key_data[i].key_data_ver; j++) {
                if (entry->key_data[i].key_data_length[j] != 0) {
                    if (entry->key_data[i].key_data_contents[j] != NULL) {
                        memset(entry->key_data[i].key_data_contents[j],
                               0,
                               entry->key_data[i].key_data_length[j]);
                        free(entry->key_data[i].key_data_contents[j]);
                    }
                }
                entry->key_data[i].key_data_contents[j] = NULL;
                entry->key_data[i].key_data_length[j] = 0;
                entry->key_data[i].key_data_type[j] = 0;
            }
        }
        free(entry->key_data);
    }

    free(entry);
}

static krb5_error_code
kh_db_create(krb5_context context,
             char *conf_section,
             char **db_args)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    krb5_error_code code;

    if (kh == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;

    code = k5_mutex_lock(kh->lock);
    if (code != 0)
        return code;

    code = kh_hdb_open(context, kh, kh->mode, 0);

    k5_mutex_unlock(kh->lock);

    return code;
}

static krb5_error_code
kh_db_lock(krb5_context context, int kmode)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    krb5_error_code code;
    enum hdb_lockop hmode;

    if (kh == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;

    code = k5_mutex_lock(kh->lock);
    if (code != 0)
        return code;

    if (kmode & KRB5_DB_LOCKMODE_EXCLUSIVE)
        hmode = HDB_WLOCK;
    else
        hmode = HDB_RLOCK;

    code = kh_hdb_lock(context, kh, hmode);

    k5_mutex_unlock(kh->lock);

    return code;
}

static krb5_error_code
kh_db_unlock(krb5_context context)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    krb5_error_code code;

    if (kh == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;

    code = k5_mutex_lock(kh->lock);
    if (code != 0)
        return code;

    code = kh_hdb_unlock(context, kh);

    k5_mutex_unlock(kh->lock);

    return code;
}

krb5_error_code
kh_get_principal(krb5_context context,
                 kh_db_context *kh,
                 krb5_const_principal princ,
                 unsigned int hflags,
                 krb5_db_entry **kentry)
{
    krb5_error_code code;
    Principal *hprinc = NULL;
    hdb_entry_ex *hentry = NULL;

    *kentry = NULL;

    code = kh_marshal_Principal(context, princ, &hprinc);
    if (code != 0)
        return code;

    code = kh_hdb_open(context, kh, kh->mode, 0);
    if (code != 0) {
        kh_free_Principal(context, hprinc);
        return code;
    }

    hentry = k5alloc(sizeof(*hentry), &code);
    if (code != 0) {
        kh_free_Principal(context, hprinc);
        return code;
    }

    code = kh_hdb_fetch(context, kh, hprinc, hflags, hentry);
    if (code != 0) {
        kh_hdb_close(context, kh);
        kh_free_Principal(context, hprinc);
        return code;
    }

    code = kh_unmarshal_hdb_entry(context, &hentry->entry, kentry);
    if (code == 0) {
        (*kentry)->e_length = sizeof(*hentry);
        (*kentry)->e_data = (krb5_octet *)hentry;
    } else {
        kh_hdb_free_entry(context, kh, hentry);
        free(hentry);
    }

    kh_hdb_close(context, kh);
    kh_free_Principal(context, hprinc);

    return code;
}

static krb5_boolean
kh_is_master_key_principal(krb5_context context,
                           krb5_const_principal princ)
{
    return krb5_princ_size(context, princ) == 2 &&
        data_eq_string(princ->data[0], "K") &&
        data_eq_string(princ->data[1], "M");
}

static krb5_error_code
kh_is_tgs_principal(krb5_context context,
                    krb5_const_principal princ)
{
    return krb5_princ_size(context, princ) == 2 &&
        data_eq_string(princ->data[0], KRB5_TGS_NAME);
}

static krb5_error_code
kh_get_master_key_principal(krb5_context context,
                            kh_db_context *kh,
                            krb5_const_principal princ,
                            krb5_db_entry **kentry_ptr)
{
    krb5_error_code code;
    krb5_key_data *key_data;
    krb5_timestamp now;
    krb5_db_entry *kentry;

    *kentry_ptr = NULL;

    kentry = k5alloc(sizeof(*kentry), &code);
    if (kentry == NULL)
        return code;

    kentry->magic = KRB5_KDB_MAGIC_NUMBER;
    kentry->len = KRB5_KDB_V1_BASE_LENGTH;
    kentry->attributes = KRB5_KDB_DISALLOW_ALL_TIX;

    if (princ == NULL)
        code = krb5_parse_name(context, KRB5_KDB_M_NAME, &kentry->princ);
    else
        code = krb5_copy_principal(context, princ, &kentry->princ);
    if (code != 0)
        return code;

    now = time(NULL);

    code = krb5_dbe_update_mod_princ_data(context, kentry, now, kentry->princ);
    if (code != 0) {
        kh_kdb_free_entry(context, kh, kentry);
        return code;
    }

    /* Return a dummy principal */
    kentry->n_key_data = 1;
    kentry->key_data = k5alloc(sizeof(krb5_key_data), &code);
    if (code != 0) {
        kh_kdb_free_entry(context, kh, kentry);
        return code;
    }

    key_data = &kentry->key_data[0];

    key_data->key_data_ver          = KRB5_KDB_V1_KEY_DATA_ARRAY;
    key_data->key_data_kvno         = 1;
    key_data->key_data_type[0]      = ENCTYPE_UNKNOWN;

    *kentry_ptr = kentry;

    return 0;
}

static krb5_error_code
kh_db_get_principal(krb5_context context,
                    krb5_const_principal princ,
                    unsigned int kflags,
                    krb5_db_entry **kentry)
{
    krb5_error_code code;
    kh_db_context *kh = KH_DB_CONTEXT(context);
    unsigned int hflags;

    *kentry = NULL;

    if (kh == NULL)
        return KRB5_KDB_DBNOTINITED;

    if (kh_is_master_key_principal(context, princ))
        return kh_get_master_key_principal(context, kh, princ, kentry);

    code = k5_mutex_lock(kh->lock);
    if (code != 0)
        return code;

    hflags = 0;
    if (kflags & KRB5_KDB_FLAG_CANONICALIZE)
        hflags |= HDB_F_CANON;
    if (kflags & (KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY |
                  KRB5_KDB_FLAG_INCLUDE_PAC))
        hflags |= HDB_F_GET_CLIENT;
    else if (kh_is_tgs_principal(context, princ))
        hflags |= HDB_F_GET_KRBTGT;
    else
        hflags |= HDB_F_GET_ANY;

    code = kh_get_principal(context, kh, princ, hflags, kentry);
    k5_mutex_unlock(kh->lock);

    return code;
}

static void
kh_db_free_principal(krb5_context context,
                     krb5_db_entry *entry)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    krb5_error_code code;

    code = k5_mutex_lock(kh->lock);
    if (code != 0)
        return;

    kh_kdb_free_entry(context, kh, entry);

    k5_mutex_unlock(kh->lock);
}

static krb5_error_code
kh_put_principal(krb5_context context,
                 kh_db_context *kh,
                 krb5_db_entry *kentry)
{
    krb5_error_code code;
    hdb_entry_ex *hentry = NULL;
    unsigned int hflags;

    hflags = 0;

    if ((kentry->attributes & KRB5_KDB_NEW_PRINC) == 0)
        hflags |= HDB_F_REPLACE;

    hentry = k5alloc(sizeof(*hentry), &code);
    if (code != 0)
        goto cleanup;

    code = kh_marshal_hdb_entry(context, kentry, &hentry->entry);
    if (code != 0)
        goto cleanup;

    code = kh_hdb_open(context, kh, kh->mode, 0);
    if (code != 0)
        goto cleanup;

    code = kh_hdb_store(context, kh, hflags, hentry);
    if (code != 0) {
        kh_hdb_close(context, kh);
        goto cleanup;
    }

    if (kentry->e_data != NULL) {
        assert(kentry->e_length == sizeof(hdb_entry_ex));
        kh_hdb_free_entry(context, kh, KH_DB_ENTRY(kentry));
        free(kentry->e_data);
    }

    kentry->e_length = sizeof(*hentry);
    kentry->e_data = (krb5_octet *)hentry;
    hentry = NULL;

    kh_hdb_close(context, kh);

cleanup:
    if (hentry != NULL) {
        kh_hdb_free_entry(context, kh, hentry);
        free(hentry);
    }

    return code;
}

static krb5_error_code
kh_db_put_principal(krb5_context context,
                    krb5_db_entry *entry,
                    char **db_args)
{
    krb5_error_code code;
    kh_db_context *kh = KH_DB_CONTEXT(context);

    if (kh == NULL)
        return KRB5_KDB_DBNOTINITED;

    code = k5_mutex_lock(kh->lock);
    if (code != 0)
        return code;

    code = kh_put_principal(context, kh, entry);

    k5_mutex_unlock(kh->lock);

    return code;
}

static krb5_error_code
kh_delete_principal(krb5_context context,
                    kh_db_context *kh,
                    krb5_const_principal princ)
{
    krb5_error_code code;
    Principal *hprinc;

    code = kh_marshal_Principal(context, princ, &hprinc);
    if (code != 0)
        return code;

    code = kh_hdb_open(context, kh, kh->mode, 0);
    if (code != 0) {
        kh_free_Principal(context, hprinc);
        return code;
    }

    code = kh_hdb_remove(context, kh, hprinc);

    kh_hdb_close(context, kh);
    kh_free_Principal(context, hprinc);

    return code;
}

static krb5_error_code
kh_db_delete_principal(krb5_context context,
                       krb5_const_principal princ)
{
    krb5_error_code code;
    kh_db_context *kh = KH_DB_CONTEXT(context);

    if (kh == NULL)
        return KRB5_KDB_DBNOTINITED;

    code = k5_mutex_lock(kh->lock);
    if (code != 0)
        return code;

    code = kh_delete_principal(context, kh, princ);

    k5_mutex_unlock(kh->lock);

    return code;
}

static krb5_error_code
kh_db_iterate(krb5_context context,
              char *match_entry,
              int (*func)(krb5_pointer, krb5_db_entry *),
              krb5_pointer func_arg)
{
    krb5_error_code code;
    kh_db_context *kh = KH_DB_CONTEXT(context);
    hdb_entry_ex hentry;
    unsigned int hflags = HDB_F_GET_ANY;

    if (kh == NULL)
        return KRB5_KDB_DBNOTINITED;

    code = k5_mutex_lock(kh->lock);
    if (code != 0)
        return code;

    memset(&hentry, 0, sizeof(hentry));

    code = kh_hdb_open(context, kh, kh->mode, 0);
    if (code != 0)
        goto cleanup;

    code = kh_hdb_firstkey(context, kh, hflags, &hentry);
    while (code == 0) {
        krb5_db_entry *kentry;

        if (kh_unmarshal_hdb_entry(context, &hentry.entry, &kentry) == 0) {
            code = (*func)(func_arg, kentry);
            kh_kdb_free_entry(context, kh, kentry);
        }

        kh_hdb_free_entry(context, kh, &hentry);

        if (code != 0)
            break;

        code = kh_hdb_nextkey(context, kh, hflags, &hentry);
    }

    if (code == KRB5_KDB_NOENTRY) {
        krb5_db_entry *kentry;

        /* Return the fake master key principal */
        if (kh_get_master_key_principal(context, kh, NULL, &kentry) == 0) {
            code = (*func)(func_arg, kentry);
            kh_kdb_free_entry(context, kh, kentry);
        }

        code = 0;
    }

    kh_hdb_close(context, kh);

cleanup:
    k5_mutex_unlock(kh->lock);

    return 0;
}

static krb5_error_code
kh_fetch_master_key(krb5_context context,
                    krb5_principal name,
                    krb5_keyblock *key,
                    krb5_kvno *kvno,
                    char *db_args)
{
    return 0;
}

static krb5_error_code
kh_fetch_master_key_list(krb5_context context,
                         krb5_principal mname,
                         const krb5_keyblock *key,
                         krb5_kvno kvno,
                         krb5_keylist_node **mkeys_list)
{
    /* just create a dummy one so that the KDC doesn't balk */
    krb5_keylist_node *mkey;
    krb5_error_code code;

    mkey = k5alloc(sizeof(*mkey), &code);
    if (code != 0)
        return code;

    mkey->keyblock.magic = KV5M_KEYBLOCK;
    mkey->keyblock.enctype = ENCTYPE_UNKNOWN;
    mkey->kvno = 1;

    *mkeys_list = mkey;

    return 0;
}

static void *
kh_db_alloc(krb5_context context, void *ptr, size_t size)
{
    return realloc(ptr, size);
}

static void
kh_db_free(krb5_context context, void *ptr)
{
    free(ptr);
}

static krb5_error_code
kh_promote_db(krb5_context context,
              char *conf_section,
              char **db_args)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    krb5_error_code code;
    char *name;

    if (kh == NULL)
        return KRB5_KDB_DBNOTINITED;

    if (kh->hdb->hdb_name == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;

    if (asprintf(&name, "%s~", kh->hdb->hdb_name) < 0)
        return ENOMEM;

    code = k5_mutex_lock(kh->lock);
    if (code != 0) {
        free(name);
        return code;
    }

    code = kh_hdb_rename(context, kh, name);

    k5_mutex_unlock(kh->lock);
    free(name);

    return code;
}

krb5_error_code
kh_decrypt_key(krb5_context context,
               kh_db_context *kh,
               const krb5_key_data *key_data,
               krb5_keyblock *kkey,
               krb5_keysalt *keysalt)
{
    krb5_error_code code;
    Key hkey;

    memset(&hkey, 0, sizeof(hkey));

    hkey.key.keytype = key_data->key_data_type[0];
    hkey.key.keyvalue.data = k5alloc(key_data->key_data_length[0], &code);
    if (code != 0)
        return code;

    memcpy(hkey.key.keyvalue.data, key_data->key_data_contents[0],
           key_data->key_data_length[0]);
    hkey.key.keyvalue.length = key_data->key_data_length[0];

    code = kh_hdb_unseal_key(context, kh, &hkey);
    if (code != 0) {
        memset(hkey.key.keyvalue.data, 0, hkey.key.keyvalue.length);
        free(hkey.key.keyvalue.data);
        return code;
    }

    kkey->magic     = KV5M_KEYBLOCK;
    kkey->enctype   = hkey.key.keytype;
    kkey->contents  = hkey.key.keyvalue.data;
    kkey->length    = hkey.key.keyvalue.length;

    if (keysalt != NULL) {
        keysalt->type = key_data->key_data_type[1];
        keysalt->data.data = k5alloc(key_data->key_data_length[1], &code);
        if (code != 0) {
            memset(hkey.key.keyvalue.data, 0, hkey.key.keyvalue.length);
            free(hkey.key.keyvalue.data);
            return code;
        }

        memcpy(keysalt->data.data, key_data->key_data_contents[1],
               key_data->key_data_length[1]);
        keysalt->data.length = key_data->key_data_length[1];
    }

    return 0;
}

static krb5_error_code
kh_dbekd_decrypt_key_data(krb5_context context,
                          const krb5_keyblock *mkey,
                          const krb5_key_data *key_data,
                          krb5_keyblock *kkey,
                          krb5_keysalt *keysalt)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    krb5_error_code code;

    if (kh == NULL)
        return KRB5_KDB_DBNOTINITED;

    if (mkey->enctype != ENCTYPE_UNKNOWN)
        code = krb5_dbe_def_decrypt_key_data(context, mkey, key_data,
                                             kkey, keysalt);
    else
        code = kh_decrypt_key(context, kh, key_data, kkey, keysalt);

    return code;
}

static krb5_error_code
kh_encrypt_key(krb5_context context,
               kh_db_context *kh,
               const krb5_keyblock *kkey,
               const krb5_keysalt *keysalt,
               int keyver,
               krb5_key_data *key_data)
{
    krb5_error_code code;
    Key hkey;

    memset(&hkey, 0, sizeof(hkey));
    memset(key_data, 0, sizeof(*key_data));

    hkey.key.keytype = kkey->enctype;
    hkey.key.keyvalue.data = k5alloc(kkey->length, &code);
    if (code != 0)
        return code;

    memcpy(hkey.key.keyvalue.data, kkey->contents, kkey->length);
    hkey.key.keyvalue.length = kkey->length;

    code = kh_hdb_seal_key(context, kh, &hkey);
    if (code != 0) {
        memset(hkey.key.keyvalue.data, 0, hkey.key.keyvalue.length);
        free(hkey.key.keyvalue.data);
        return code;
    }

    key_data->key_data_ver          = KRB5_KDB_V1_KEY_DATA_ARRAY;
    key_data->key_data_kvno         = keyver;
    key_data->key_data_type[0]      = hkey.key.keytype;
    key_data->key_data_contents[0]  = hkey.key.keyvalue.data;
    key_data->key_data_length[0]    = hkey.key.keyvalue.length;

    if (keysalt != NULL) {
        key_data->key_data_type[1] = keysalt->type;
        key_data->key_data_contents[1] = k5alloc(keysalt->data.length, &code);
        if (code != 0) {
            memset(hkey.key.keyvalue.data, 0, hkey.key.keyvalue.length);
            free(hkey.key.keyvalue.data);
            return code;
        }

        memcpy(key_data->key_data_contents[1],
               keysalt->data.data, keysalt->data.length);
        key_data->key_data_length[1] = keysalt->data.length;
    }

    return 0;
}

static krb5_error_code
kh_dbekd_encrypt_key_data(krb5_context context,
                          const krb5_keyblock *mkey,
                          const krb5_keyblock *kkey,
                          const krb5_keysalt *keysalt,
                          int keyver,
                          krb5_key_data *key_data)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    krb5_error_code code;

    if (kh == NULL)
        return KRB5_KDB_DBNOTINITED;

    /* For migration */
    if (mkey->enctype != ENCTYPE_UNKNOWN)
        code = krb5_dbe_def_encrypt_key_data(context, mkey, kkey,
                                             keysalt, keyver, key_data);
    else
        code = kh_encrypt_key(context, kh, kkey, keysalt, keyver, key_data);

    return code;
}

/*
 * Invoke methods
 */

static krb5_error_code
kh_db_check_allowed_to_delegate(krb5_context context,
                                krb5_const_principal client,
                                const krb5_db_entry *server,
                                krb5_const_principal proxy)
{
    krb5_error_code code;
    hdb_entry_ex *hentry;
    HDB_extension *ext;
    HDB_Ext_Constrained_delegation_acl *acl;
    unsigned int i;

    hentry = KH_DB_ENTRY(server);
    ext = kh_hdb_find_extension(&hentry->entry,
                                choice_HDB_extension_data_allowed_to_delegate_to);

    code = KRB5KDC_ERR_POLICY;

    if (ext != NULL) {
        acl = &ext->data.u.allowed_to_delegate_to;

        for (i = 0; i < acl->len; i++) {
            krb5_principal princ;

            if (kh_unmarshal_Principal(context, &acl->val[i], &princ) == 0) {
                if (krb5_principal_compare(context, proxy, princ)) {
                    code = 0;
                    krb5_free_principal(context, princ);
                    break;
                }
                krb5_free_principal(context, princ);
            }
        }
    }

    return code;
}

kdb_vftabl kdb_function_table = {
    KRB5_KDB_DAL_MAJOR_VERSION,
    0,
    kh_init,
    kh_fini,
    kh_init_module,
    kh_fini_module,
    kh_db_create,
    NULL, /* destroy */
    NULL, /* get_age */
    kh_db_lock,
    kh_db_unlock,
    kh_db_get_principal,
    kh_db_free_principal,
    kh_db_put_principal,
    kh_db_delete_principal,
    kh_db_iterate,
    NULL, /* create_policy */
    NULL, /* get_policy */
    NULL, /* put_policy */
    NULL, /* iter_policy */
    NULL, /* delete_policy */
    NULL, /* free_policy */
    kh_db_alloc,
    kh_db_free,
    NULL, /* set_master_key_list */
    NULL, /* get_master_key_list */
    kh_fetch_master_key,
    kh_fetch_master_key_list,
    NULL, /* store_master_key_list */
    NULL, /* dbe_search_enctype */
    NULL, /* change_pwd */
    kh_promote_db,
    kh_dbekd_decrypt_key_data,
    kh_dbekd_encrypt_key_data,
    kh_db_sign_auth_data,
    NULL, /* check_transited_realms */
    kh_db_check_policy_as,
    NULL, /* check_policy_tgs */
    NULL, /* audit_as_req */
    NULL, /* refresh_config */
    kh_db_check_allowed_to_delegate
};
