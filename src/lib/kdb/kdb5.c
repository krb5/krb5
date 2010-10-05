/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2006, 2009, 2010 by the Massachusetts Institute of Technology.
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

/*
 * This code was based on code donated to MIT by Novell for
 * distribution under the MIT license.
 */

/*
 * Include files
 */

#include <stdio.h>
#include <string.h>
#include <k5-int.h>
#include <osconf.h>
#include "kdb5.h"
#include "kdb_log.h"
#include "kdb5int.h"

/* Currently DB2 policy related errors are exported from DAL.  But
   other databases should set_err function to return string.  */
#include "adb_err.h"

/*
 * Type definitions
 */
#define KRB5_TL_DB_ARGS                 0x7fff

/*
 * internal static variable
 */

static k5_mutex_t db_lock = K5_MUTEX_PARTIAL_INITIALIZER;

static db_library lib_list;

/*
 * Helper Functions
 */

MAKE_INIT_FUNCTION(kdb_init_lock_list);
MAKE_FINI_FUNCTION(kdb_fini_lock_list);

int
kdb_init_lock_list()
{
    return k5_mutex_finish_init(&db_lock);
}

static int
kdb_lock_list()
{
    int err;
    err = CALL_INIT_FUNCTION (kdb_init_lock_list);
    if (err)
        return err;
    return k5_mutex_lock(&db_lock);
}

void
kdb_fini_lock_list()
{
    if (INITIALIZER_RAN(kdb_init_lock_list))
        k5_mutex_destroy(&db_lock);
}

static int
kdb_unlock_list()
{
    return k5_mutex_unlock(&db_lock);
}

/*
 * XXX eventually this should be consolidated with krb5_free_key_data_contents
 * so there is only a single version.
 */
void
krb5_dbe_free_key_data_contents(krb5_context context, krb5_key_data *key)
{
    int i, idx;

    if (key) {
        idx = (key->key_data_ver == 1 ? 1 : 2);
        for (i = 0; i < idx; i++) {
            if (key->key_data_contents[i]) {
                zap(key->key_data_contents[i], key->key_data_length[i]);
                free(key->key_data_contents[i]);
            }
        }
    }
    return;
}

void
krb5_dbe_free_key_list(krb5_context context, krb5_keylist_node *val)
{
    krb5_keylist_node *temp = val, *prev;

    while (temp != NULL) {
        prev = temp;
        temp = temp->next;
        krb5_free_keyblock_contents(context, &(prev->keyblock));
        krb5_xfree(prev);
    }
}

void
krb5_dbe_free_actkvno_list(krb5_context context, krb5_actkvno_node *val)
{
    krb5_actkvno_node *temp = val, *prev;

    while (temp != NULL) {
        prev = temp;
        temp = temp->next;
        krb5_xfree(prev);
    }
}

void
krb5_dbe_free_mkey_aux_list(krb5_context context, krb5_mkey_aux_node *val)
{
    krb5_mkey_aux_node *temp = val, *prev;

    while (temp != NULL) {
        prev = temp;
        temp = temp->next;
        krb5_dbe_free_key_data_contents(context, &prev->latest_mkey);
        krb5_xfree(prev);
    }
}

void
krb5_dbe_free_tl_data(krb5_context context, krb5_tl_data *tl_data)
{
    if (tl_data) {
        if (tl_data->tl_data_contents)
            free(tl_data->tl_data_contents);
        free(tl_data);
    }
}

/* Set *section to the appropriate section to use for a database module's
 * profile queries.  The caller must free the result. */
static krb5_error_code
get_conf_section(krb5_context context, char **section)
{
    krb5_error_code status;
    char *result = NULL;
    char *value = NULL;

    *section = NULL;

    if (context->default_realm == NULL) {
        krb5_set_error_message(context, KRB5_KDB_SERVER_INTERNAL_ERR,
                               "No default realm set; cannot initialize KDB");
        return KRB5_KDB_SERVER_INTERNAL_ERR;
    }
    status = profile_get_string(context->profile,
                                /* realms */
                                KDB_REALM_SECTION,
                                context->default_realm,
                                /* under the realm name, database_module */
                                KDB_MODULE_POINTER,
                                /* default value is the realm name itself */
                                context->default_realm,
                                &value);
    if (status)
        return status;
    result = strdup(value);
    profile_release_string(value);
    if (result == NULL)
        return ENOMEM;
    *section = result;
    return 0;
}

static char *
kdb_get_library_name(krb5_context kcontext)
{
    krb5_error_code status = 0;
    char   *result = NULL;
    char   *value = NULL;
    char   *lib = NULL;

    status = profile_get_string(kcontext->profile,
                                /* realms */
                                KDB_REALM_SECTION,
                                kcontext->default_realm,
                                /* under the realm name, database_module */
                                KDB_MODULE_POINTER,
                                /* default value is the realm name itself */
                                kcontext->default_realm,
                                &value);
    if (status)
        goto clean_n_exit;

#define DB2_NAME "db2"
    /* we got the module section. Get the library name from the module */
    status = profile_get_string(kcontext->profile, KDB_MODULE_SECTION, value,
                                KDB_LIB_POINTER,
                                /* default to db2 */
                                DB2_NAME,
                                &lib);

    if (status) {
        goto clean_n_exit;
    }

    result = strdup(lib);
clean_n_exit:
    profile_release_string(value);
    profile_release_string(lib);
    return result;
}

static void
kdb_setup_opt_functions(db_library lib)
{
    if (lib->vftabl.fetch_master_key == NULL)
        lib->vftabl.fetch_master_key = krb5_db_def_fetch_mkey;
    if (lib->vftabl.fetch_master_key_list == NULL)
        lib->vftabl.fetch_master_key_list = krb5_def_fetch_mkey_list;
    if (lib->vftabl.store_master_key_list == NULL)
        lib->vftabl.store_master_key_list = krb5_def_store_mkey_list;
    if (lib->vftabl.dbe_search_enctype == NULL)
        lib->vftabl.dbe_search_enctype = krb5_dbe_def_search_enctype;
    if (lib->vftabl.change_pwd == NULL)
        lib->vftabl.change_pwd = krb5_dbe_def_cpw;
    if (lib->vftabl.decrypt_key_data == NULL)
        lib->vftabl.decrypt_key_data = krb5_dbe_def_decrypt_key_data;
    if (lib->vftabl.encrypt_key_data == NULL)
        lib->vftabl.encrypt_key_data = krb5_dbe_def_encrypt_key_data;
}

#ifdef STATIC_PLUGINS

extern kdb_vftabl krb5_db2_kdb_function_table;
#ifdef ENABLE_LDAP
extern kdb_vftabl krb5_db2_ldap_function_table;
#endif

static krb5_error_code
kdb_load_library(krb5_context kcontext, char *lib_name, db_library *libptr)
{
    krb5_error_code status;
    db_library lib;
    kdb_vftabl *vftabl_addr = NULL;

    if (strcmp(lib_name, "db2") == 0)
        vftabl_addr = &krb5_db2_kdb_function_table;
#ifdef ENABLE_LDAP
    if (strcmp(lib_name, "ldap") == 0)
        vftabl_addr = &krb5_ldap_kdb_function_table;
#endif
    if (!vftabl_addr) {
        krb5_set_error_message(kcontext, KRB5_KDB_DBTYPE_NOTFOUND,
                               "Unable to find requested database type: %s",
                               lib_name);
        return KRB5_PLUGIN_OP_NOTSUPP;
    }

    lib = calloc(1, sizeof(*lib));
    if (lib == NULL)
        return ENOMEM;

    strlcpy(lib->name, lib_name, sizeof(lib->name));
    memcpy(&lib->vftabl, vftabl_addr, sizeof(kdb_vftabl));
    kdb_setup_opt_functions(lib);

    status = lib->vftabl.init_library();
    if (status)
        goto cleanup;

    *libptr = lib;
    return 0;

cleanup:
    free(lib);
    return status;
}

#else /* KDB5_STATIC_LINK*/

static char *db_dl_location[] = DEFAULT_KDB_LIB_PATH;
#define db_dl_n_locations (sizeof(db_dl_location) / sizeof(db_dl_location[0]))

static krb5_error_code
kdb_load_library(krb5_context kcontext, char *lib_name, db_library *lib)
{
    krb5_error_code status = 0;
    int     ndx;
    void  **vftabl_addrs = NULL;
    /* N.B.: If this is "const" but not "static", the Solaris 10
       native compiler has trouble building the library because of
       absolute relocations needed in read-only section ".rodata".
       When it's static, it goes into ".picdata", which is
       read-write.  */
    static const char *const dbpath_names[] = {
        KDB_MODULE_SECTION, KRB5_CONF_DB_MODULE_DIR, NULL,
    };
    const char *filebases[2];
    char **profpath = NULL;
    char **path = NULL;

    filebases[0] = lib_name;
    filebases[1] = NULL;

    *lib = calloc((size_t) 1, sizeof(**lib));
    if (*lib == NULL)
        return ENOMEM;

    strlcpy((*lib)->name, lib_name, sizeof((*lib)->name));

    /* Fetch the list of directories specified in the config
       file(s) first.  */
    status = profile_get_values(kcontext->profile, dbpath_names, &profpath);
    if (status != 0 && status != PROF_NO_RELATION)
        goto clean_n_exit;
    ndx = 0;
    if (profpath)
        while (profpath[ndx] != NULL)
            ndx++;

    path = calloc(ndx + db_dl_n_locations, sizeof (char *));
    if (path == NULL) {
        status = ENOMEM;
        goto clean_n_exit;
    }
    if (ndx)
        memcpy(path, profpath, ndx * sizeof(profpath[0]));
    memcpy(path + ndx, db_dl_location, db_dl_n_locations * sizeof(char *));
    status = 0;

    if ((status = krb5int_open_plugin_dirs ((const char **) path,
                                            filebases,
                                            &(*lib)->dl_dir_handle, &kcontext->err))) {
        const char *err_str = krb5_get_error_message(kcontext, status);
        status = KRB5_KDB_DBTYPE_NOTFOUND;
        krb5_set_error_message (kcontext, status,
                                "Unable to find requested database type: %s", err_str);
        krb5_free_error_message (kcontext, err_str);
        goto clean_n_exit;
    }

    if ((status = krb5int_get_plugin_dir_data (&(*lib)->dl_dir_handle, "kdb_function_table",
                                               &vftabl_addrs, &kcontext->err))) {
        const char *err_str = krb5_get_error_message(kcontext, status);
        status = KRB5_KDB_DBTYPE_INIT;
        krb5_set_error_message (kcontext, status,
                                "plugin symbol 'kdb_function_table' lookup failed: %s", err_str);
        krb5_free_error_message (kcontext, err_str);
        goto clean_n_exit;
    }

    if (vftabl_addrs[0] == NULL) {
        /* No plugins! */
        status = KRB5_KDB_DBTYPE_NOTFOUND;
        krb5_set_error_message (kcontext, status,
                                _("Unable to load requested database module '%s': plugin symbol 'kdb_function_table' not found"),
                                lib_name);
        goto clean_n_exit;
    }

    if (((kdb_vftabl *)vftabl_addrs[0])->maj_ver !=
        KRB5_KDB_DAL_MAJOR_VERSION) {
        status = KRB5_KDB_DBTYPE_MISMATCH;
        goto clean_n_exit;
    }

    memcpy(&(*lib)->vftabl, vftabl_addrs[0], sizeof(kdb_vftabl));
    kdb_setup_opt_functions(*lib);

    if ((status = (*lib)->vftabl.init_library()))
        goto clean_n_exit;

clean_n_exit:
    krb5int_free_plugin_dir_data(vftabl_addrs);
    /* Both of these DTRT with NULL.  */
    profile_free_list(profpath);
    free(path);
    if (status && *lib) {
        if (PLUGIN_DIR_OPEN((&(*lib)->dl_dir_handle)))
            krb5int_close_plugin_dirs (&(*lib)->dl_dir_handle);
        free(*lib);
        *lib = NULL;
    }
    return status;
}

#endif /* end of _KDB5_STATIC_LINK */

static krb5_error_code
kdb_find_library(krb5_context kcontext, char *lib_name, db_library *lib)
{
    /* lock here so that no two threads try to do the same at the same time */
    krb5_error_code status = 0;
    int     locked = 0;
    db_library curr_elt, prev_elt = NULL;
    static int kdb_db2_pol_err_loaded = 0;

    if (!strcmp(DB2_NAME, lib_name) && (kdb_db2_pol_err_loaded == 0)) {
        initialize_adb_error_table();
        kdb_db2_pol_err_loaded = 1;
    }

    if ((status = kdb_lock_list()) != 0)
        goto clean_n_exit;
    locked = 1;

    curr_elt = lib_list;
    while (curr_elt != NULL) {
        if (strcmp(lib_name, curr_elt->name) == 0) {
            *lib = curr_elt;
            goto clean_n_exit;
        }
        prev_elt = curr_elt;
        curr_elt = curr_elt->next;
    }

    /* module not found. create and add to list */
    status = kdb_load_library(kcontext, lib_name, lib);
    if (status)
        goto clean_n_exit;

    if (prev_elt) {
        /* prev_elt points to the last element in the list */
        prev_elt->next = *lib;
        (*lib)->prev = prev_elt;
    } else {
        lib_list = *lib;
    }

clean_n_exit:
    if (*lib)
        (*lib)->reference_cnt++;

    if (locked)
        kdb_unlock_list();

    return status;
}

static krb5_error_code
kdb_free_library(db_library lib)
{
    krb5_error_code status = 0;
    int     locked = 0;

    if ((status = kdb_lock_list()) != 0)
        goto clean_n_exit;
    locked = 1;

    lib->reference_cnt--;

    if (lib->reference_cnt == 0) {
        status = lib->vftabl.fini_library();
        if (status)
            goto clean_n_exit;

        /* close the library */
        if (PLUGIN_DIR_OPEN((&lib->dl_dir_handle)))
            krb5int_close_plugin_dirs (&lib->dl_dir_handle);

        if (lib->prev == NULL)
            lib_list = lib->next;  /* first element in the list */
        else
            lib->prev->next = lib->next;

        if (lib->next)
            lib->next->prev = lib->prev;
        free(lib);
    }

clean_n_exit:
    if (locked)
        kdb_unlock_list();

    return status;
}

krb5_error_code
krb5_db_setup_lib_handle(krb5_context kcontext)
{
    char   *library = NULL;
    krb5_error_code status = 0;
    db_library lib = NULL;
    kdb5_dal_handle *dal_handle = NULL;

    dal_handle = calloc((size_t) 1, sizeof(kdb5_dal_handle));
    if (dal_handle == NULL) {
        status = ENOMEM;
        goto clean_n_exit;
    }

    library = kdb_get_library_name(kcontext);
    if (library == NULL) {
        status = KRB5_KDB_DBTYPE_NOTFOUND;
        goto clean_n_exit;
    }

    status = kdb_find_library(kcontext, library, &lib);
    if (status)
        goto clean_n_exit;

    dal_handle->lib_handle = lib;
    kcontext->dal_handle = dal_handle;

clean_n_exit:
    free(library);

    if (status) {
        free(dal_handle);
        if (lib)
            kdb_free_library(lib);
    }

    return status;
}

static krb5_error_code
kdb_free_lib_handle(krb5_context kcontext)
{
    krb5_error_code status = 0;
    krb5_keylist_node *old_keylist = kcontext->dal_handle->master_keylist;

    status = kdb_free_library(kcontext->dal_handle->lib_handle);
    if (status)
        return status;
    /* The dal_handle holds an alias to the most recent mkey_list. */
    if (kcontext->dal_handle->free_keylist) {
        kcontext->dal_handle->master_keylist = NULL; /* Force freeing. */
        krb5_db_free_mkey_list(kcontext, old_keylist);
    }
    krb5_free_principal(kcontext, kcontext->dal_handle->master_princ);
    free(kcontext->dal_handle);
    kcontext->dal_handle = NULL;
    return 0;
}

static krb5_error_code
get_vftabl(krb5_context kcontext, kdb_vftabl **vftabl_ptr)
{
    krb5_error_code status;

    *vftabl_ptr = NULL;
    if (kcontext->dal_handle == NULL) {
        status = krb5_db_setup_lib_handle(kcontext);
        if (status)
            return status;
    }
    *vftabl_ptr = &kcontext->dal_handle->lib_handle->vftabl;
    return 0;
}

/*
 *      External functions... DAL API
 */
krb5_error_code
krb5_db_open(krb5_context kcontext, char **db_args, int mode)
{
    krb5_error_code status;
    char *section;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    status = get_conf_section(kcontext, &section);
    if (status)
        return status;
    status = v->init_module(kcontext, section, db_args, mode);
    free(section);
    return status;
}

krb5_error_code
krb5_db_inited(krb5_context kcontext)
{
    return !(kcontext && kcontext->dal_handle &&
             kcontext->dal_handle->db_context);
}

krb5_error_code
krb5_db_create(krb5_context kcontext, char **db_args)
{
    krb5_error_code status;
    char *section;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->create == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    status = get_conf_section(kcontext, &section);
    if (status)
        return status;
    status = v->create(kcontext, section, db_args);
    free(section);
    return status;
}

krb5_error_code
krb5_db_fini(krb5_context kcontext)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    /* Do nothing if module was never loaded. */
    if (kcontext->dal_handle == NULL)
        return 0;

    v = &kcontext->dal_handle->lib_handle->vftabl;
    status = v->fini_module(kcontext);

    if (status)
        return status;

    return kdb_free_lib_handle(kcontext);
}

krb5_error_code
krb5_db_destroy(krb5_context kcontext, char **db_args)
{
    krb5_error_code status;
    char *section;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->destroy == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    status = get_conf_section(kcontext, &section);
    if (status)
        return status;
    status = v->destroy(kcontext, section, db_args);
    free(section);
    return status;
}

krb5_error_code
krb5_db_get_age(krb5_context kcontext, char *db_name, time_t *t)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->get_age == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->get_age(kcontext, db_name, t);
}

krb5_error_code
krb5_db_lock(krb5_context kcontext, int lock_mode)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->lock == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->lock(kcontext, lock_mode);
}

krb5_error_code
krb5_db_unlock(krb5_context kcontext)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->unlock == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->unlock(kcontext);
}

krb5_error_code
krb5_db_get_principal(krb5_context kcontext, krb5_const_principal search_for,
                      unsigned int flags, krb5_db_entry **entry)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    *entry = NULL;
    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->get_principal == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->get_principal(kcontext, search_for, flags, entry);
}

void
krb5_db_free_principal(krb5_context kcontext, krb5_db_entry *entry)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return;
    v->free_principal(kcontext, entry);
}

static void
free_db_args(krb5_context kcontext, char **db_args)
{
    int i;
    if (db_args) {
        /* XXX Is this right?  Or are we borrowing storage from
           the caller?  */
        for (i = 0; db_args[i]; i++)
            krb5_db_free(kcontext, db_args[i]);
        free(db_args);
    }
}

static krb5_error_code
extract_db_args_from_tl_data(krb5_context kcontext, krb5_tl_data **start,
                             krb5_int16 *count, char ***db_argsp)
{
    char **db_args = NULL;
    int db_args_size = 0;
    krb5_tl_data *prev, *curr, *next;
    krb5_error_code status;

    /* Giving db_args as part of tl data causes db2 to store the
       tl_data as such.  To prevent this, tl_data is collated and
       passed as a separate argument.  Currently supports only one
       principal, but passing it as a separate argument makes it
       difficult for kadmin remote to pass arguments to server.  */
    prev = NULL, curr = *start;
    while (curr) {
        if (curr->tl_data_type == KRB5_TL_DB_ARGS) {
            char  **t;
            /* Since this is expected to be NULL terminated string and
               this could come from any client, do a check before
               passing it to db.  */
            if (((char *) curr->tl_data_contents)[curr->tl_data_length - 1] !=
                '\0') {
                /* Not null terminated. Dangerous input.  */
                status = EINVAL;
                goto clean_n_exit;
            }

            db_args_size++;
            t = realloc(db_args, sizeof(char *) * (db_args_size + 1));  /* 1 for NULL */
            if (t == NULL) {
                status = ENOMEM;
                goto clean_n_exit;
            }

            db_args = t;
            db_args[db_args_size - 1] = (char *) curr->tl_data_contents;
            db_args[db_args_size] = NULL;

            next = curr->tl_data_next;
            if (prev == NULL) {
                /* current node is the first in the linked list. remove it */
                *start = curr->tl_data_next;
            } else {
                prev->tl_data_next = curr->tl_data_next;
            }
            (*count)--;
            krb5_db_free(kcontext, curr);

            /* previous does not change */
            curr = next;
        } else {
            prev = curr;
            curr = curr->tl_data_next;
        }
    }
    status = 0;
clean_n_exit:
    if (status != 0) {
        free_db_args(kcontext, db_args);
        db_args = NULL;
    }
    *db_argsp = db_args;
    return status;
}

krb5_error_code
krb5int_put_principal_no_log(krb5_context kcontext, krb5_db_entry *entry)
{
    kdb_vftabl *v;
    krb5_error_code status;
    char **db_args;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->put_principal == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    status = extract_db_args_from_tl_data(kcontext, &entry->tl_data,
                                          &entry->n_tl_data,
                                          &db_args);
    if (status)
        return status;
    status = v->put_principal(kcontext, entry, db_args);
    free_db_args(kcontext, db_args);
    return status;
}

krb5_error_code
krb5_db_put_principal(krb5_context kcontext, krb5_db_entry *entry)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;
    char  **db_args = NULL;
    kdb_incr_update_t *upd = NULL;
    char *princ_name = NULL;
    kdb_log_context *log_ctx;
    int ulog_locked = 0;

    log_ctx = kcontext->kdblog_context;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->put_principal == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;

    status = extract_db_args_from_tl_data(kcontext, &entry->tl_data,
                                          &entry->n_tl_data,
                                          &db_args);
    if (status)
        goto clean_n_exit;

    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER)) {
        upd = k5alloc(sizeof(*upd), &status);
        if (upd == NULL)
            goto clean_n_exit;
        if ((status = ulog_conv_2logentry(kcontext, entry, upd)))
            goto clean_n_exit;
    }

    status = ulog_lock(kcontext, KRB5_LOCKMODE_EXCLUSIVE);
    if (status != 0)
        goto err_lock;
    ulog_locked = 1;

    if (upd != NULL) {
        status = krb5_unparse_name(kcontext, entry->princ, &princ_name);
        if (status != 0)
            goto err_lock;

        upd->kdb_princ_name.utf8str_t_val = princ_name;
        upd->kdb_princ_name.utf8str_t_len = strlen(princ_name);

        if ((status = ulog_add_update(kcontext, upd)) != 0)
            goto err_lock;
    }

    status = v->put_principal(kcontext, entry, db_args);
    if (status == 0 && upd != NULL)
        (void) ulog_finish_update(kcontext, upd);

err_lock:
    if (ulog_locked)
        ulog_lock(kcontext, KRB5_LOCKMODE_UNLOCK);

clean_n_exit:
    free_db_args(kcontext, db_args);
    ulog_free_entries(upd, 1);
    return status;
}

krb5_error_code
krb5int_delete_principal_no_log(krb5_context kcontext,
                                krb5_principal search_for)
{
    kdb_vftabl *v;
    krb5_error_code status;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->delete_principal == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->delete_principal(kcontext, search_for);
}

krb5_error_code
krb5_db_delete_principal(krb5_context kcontext, krb5_principal search_for)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;
    kdb_incr_update_t upd;
    char *princ_name = NULL;
    kdb_log_context *log_ctx;

    log_ctx = kcontext->kdblog_context;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    status = ulog_lock(kcontext, KRB5_LOCKMODE_EXCLUSIVE);
    if (status)
        return status;

    /*
     * We'll be sharing the same locks as db for logging
     */
    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER)) {
        if ((status = krb5_unparse_name(kcontext, search_for, &princ_name))) {
            ulog_lock(kcontext, KRB5_LOCKMODE_UNLOCK);
            return status;
        }

        (void) memset(&upd, 0, sizeof (kdb_incr_update_t));

        upd.kdb_princ_name.utf8str_t_val = princ_name;
        upd.kdb_princ_name.utf8str_t_len = strlen(princ_name);

        if ((status = ulog_delete_update(kcontext, &upd)) != 0) {
            ulog_lock(kcontext, KRB5_LOCKMODE_UNLOCK);
            free(princ_name);
            return status;
        }

        free(princ_name);
    }

    if (v->delete_principal == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;

    status = v->delete_principal(kcontext, search_for);

    /*
     * We need to commit our update upon success
     */
    if (!status)
        if (log_ctx && (log_ctx->iproprole == IPROP_MASTER))
            (void) ulog_finish_update(kcontext, &upd);

    ulog_lock(kcontext, KRB5_LOCKMODE_UNLOCK);

    return status;
}

krb5_error_code
krb5_db_iterate(krb5_context kcontext, char *match_entry,
                int (*func)(krb5_pointer, krb5_db_entry *),
                krb5_pointer func_arg)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->iterate == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->iterate(kcontext, match_entry, func, func_arg);
}

krb5_error_code
krb5_db_fetch_mkey_list(krb5_context context, krb5_principal mname,
                        const krb5_keyblock *mkey, krb5_kvno mkvno,
                        krb5_keylist_node **mkey_list)
{
    kdb_vftabl *v;
    krb5_error_code status = 0;
    krb5_keylist_node *local_keylist;

    status = get_vftabl(context, &v);
    if (status)
        return status;
    if (!context->dal_handle->master_princ) {
        status = krb5_copy_principal(context, mname,
                                     &context->dal_handle->master_princ);
        if (status)
            return status;
    }
    if (mkey_list == NULL)
        mkey_list = &local_keylist;
    status = v->fetch_master_key_list(context, mname, mkey, mkvno, mkey_list);
    if (status == 0) {
        /* The dal_handle holds an alias to the most recent master_keylist. */
        krb5_keylist_node *old_keylist = context->dal_handle->master_keylist;
        context->dal_handle->master_keylist = *mkey_list;
        if (context->dal_handle->free_keylist)
            krb5_db_free_mkey_list(context, old_keylist);
        context->dal_handle->free_keylist = (mkey_list == &local_keylist);
    }
    return status;
}

void
krb5_db_free_mkey_list(krb5_context context, krb5_keylist_node *mkey_list)
{
    krb5_keylist_node *cur, *prev;

    /*
     * The dal_handle holds onto the most recent master keylist that has been
     * fetched throughout the lifetime of the context; if this function is
     * called on that keylist, then the dal_handle is updated to indicate that
     * the keylist should be freed on next call to krb5_db_fetch_mkey_list() or
     * when the database is closed.  Otherwise, the master_keylist is freed.
     * Either way, the caller must not access this master keylist after calling
     * this function.
     */
    if (context && context->dal_handle->master_keylist == mkey_list) {
        context->dal_handle->free_keylist = 1;
        return;
    }
    for (cur = mkey_list; cur != NULL;) {
        prev = cur;
        cur = cur->next;
        krb5_free_keyblock_contents(context, &prev->keyblock);
        krb5_xfree(prev);
    }
}

krb5_error_code
krb5_db_store_master_key(krb5_context kcontext, char *keyfile,
                         krb5_principal mname, krb5_kvno kvno,
                         krb5_keyblock * key, char *master_pwd)
{
    krb5_keylist_node list;

    list.kvno = kvno;
    list.keyblock = *key;
    list.next = NULL;
    return krb5_db_store_master_key_list(kcontext, keyfile, mname, &list,
                                         master_pwd);
}

krb5_error_code
krb5_db_store_master_key_list(krb5_context kcontext, char *keyfile,
                              krb5_principal mname, krb5_keylist_node *keylist,
                              char *master_pwd)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->store_master_key_list == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->store_master_key_list(kcontext, keyfile, mname, keylist,
                                    master_pwd);
}

char   *krb5_mkey_pwd_prompt1 = KRB5_KDC_MKEY_1;
char   *krb5_mkey_pwd_prompt2 = KRB5_KDC_MKEY_2;

krb5_error_code
krb5_db_fetch_mkey(krb5_context context, krb5_principal mname,
                   krb5_enctype etype, krb5_boolean fromkeyboard,
                   krb5_boolean twice, char *db_args, krb5_kvno *kvno,
                   krb5_data *salt, krb5_keyblock *key)
{
    krb5_error_code retval;
    char    password[BUFSIZ];
    krb5_data pwd;
    unsigned int size = sizeof(password);
    krb5_keyblock tmp_key;

    memset(&tmp_key, 0, sizeof(tmp_key));

    if (fromkeyboard) {
        krb5_data scratch;

        if ((retval = krb5_read_password(context, krb5_mkey_pwd_prompt1,
                                         twice ? krb5_mkey_pwd_prompt2 : 0,
                                         password, &size))) {
            goto clean_n_exit;
        }

        pwd.data = password;
        pwd.length = size;
        if (!salt) {
            retval = krb5_principal2salt(context, mname, &scratch);
            if (retval)
                goto clean_n_exit;
        }
        retval =
            krb5_c_string_to_key(context, etype, &pwd, salt ? salt : &scratch,
                                 key);
        /*
         * If a kvno pointer was passed in and it dereferences the IGNORE_VNO
         * value then it should be assigned the value of the kvno associated
         * with the current mkey princ key if that princ entry is available
         * otherwise assign 1 which is the default kvno value for the mkey
         * princ.
         */
        if (kvno != NULL && *kvno == IGNORE_VNO) {
            krb5_error_code rc;
            krb5_db_entry *master_entry;

            rc = krb5_db_get_principal(context, mname, 0, &master_entry);
            if (rc == 0) {
                *kvno = (krb5_kvno) master_entry->key_data->key_data_kvno;
                krb5_db_free_principal(context, master_entry);
            } else
                *kvno = 1;
        }

        if (!salt)
            free(scratch.data);
        zap(password, sizeof(password));        /* erase it */

    } else {
        kdb_vftabl *v;

        if (context->dal_handle == NULL) {
            retval = krb5_db_setup_lib_handle(context);
            if (retval)
                goto clean_n_exit;
        }

        /* get the enctype from the stash */
        tmp_key.enctype = ENCTYPE_UNKNOWN;

        v = &context->dal_handle->lib_handle->vftabl;
        retval = v->fetch_master_key(context, mname, &tmp_key, kvno, db_args);

        if (retval)
            goto clean_n_exit;

        key->contents = malloc(tmp_key.length);
        if (key->contents == NULL) {
            retval = ENOMEM;
            goto clean_n_exit;
        }

        key->magic = tmp_key.magic;
        key->enctype = tmp_key.enctype;
        key->length = tmp_key.length;
        memcpy(key->contents, tmp_key.contents, tmp_key.length);
    }

clean_n_exit:
    if (tmp_key.contents) {
        zap(tmp_key.contents, tmp_key.length);
        krb5_db_free(context, tmp_key.contents);
    }
    return retval;
}

krb5_error_code
krb5_dbe_fetch_act_key_list(krb5_context context, krb5_principal princ,
                            krb5_actkvno_node **act_key_list)
{
    krb5_error_code retval = 0;
    krb5_db_entry *entry;

    if (act_key_list == NULL)
        return (EINVAL);

    retval = krb5_db_get_principal(context, princ, 0, &entry);
    if (retval == KRB5_KDB_NOENTRY)
        return KRB5_KDB_NOMASTERKEY;
    else if (retval)
        return retval;

    retval = krb5_dbe_lookup_actkvno(context, entry, act_key_list);

    if (*act_key_list == NULL) {
        krb5_actkvno_node *tmp_actkvno;
        /*
         * for mkey princ entries without KRB5_TL_ACTKVNO data provide a default
         */

        tmp_actkvno = (krb5_actkvno_node *) malloc(sizeof(krb5_actkvno_node));
        if (tmp_actkvno == NULL) {
            krb5_db_free_principal(context, entry);
            return ENOMEM;
        }

        memset(tmp_actkvno, 0, sizeof(krb5_actkvno_node));
        tmp_actkvno->act_time = 0; /* earliest time possible */
        /* use most current key */
        tmp_actkvno->act_kvno = entry->key_data[0].key_data_kvno;
        *act_key_list = tmp_actkvno;
    }

    krb5_db_free_principal(context, entry);
    return retval;
}

/*
 * Locates the "active" mkey used when encrypting a princ's keys.  Note, the
 * caller must NOT free the output act_mkey.
 */

krb5_error_code
krb5_dbe_find_act_mkey(krb5_context context, krb5_keylist_node *mkey_list,
                       krb5_actkvno_node *act_mkey_list, krb5_kvno *act_kvno,
                       krb5_keyblock **act_mkey)
{
    krb5_kvno tmp_act_kvno;
    krb5_error_code retval;
    krb5_keylist_node *cur_keyblock = mkey_list;
    krb5_actkvno_node   *prev_actkvno, *cur_actkvno;
    krb5_timestamp      now;
    krb5_boolean        found = FALSE;

    if (act_mkey_list == NULL) {
        *act_kvno = 0;
        *act_mkey = NULL;
        return 0;
    }

    if ((retval = krb5_timeofday(context, &now)))
        return (retval);

    /*
     * The list should be sorted in time, early to later so if the first entry
     * is later than now, this is a problem.  The fallback in this case is to
     * return the earlist activation entry.
     */
    if (act_mkey_list->act_time > now) {
        while (cur_keyblock && cur_keyblock->kvno != act_mkey_list->act_kvno)
            cur_keyblock = cur_keyblock->next;
        if (cur_keyblock) {
            *act_mkey = &cur_keyblock->keyblock;
            if (act_kvno != NULL)
                *act_kvno = cur_keyblock->kvno;
            return (0);
        } else {
            return (KRB5_KDB_NOACTMASTERKEY);
        }
    }

    /* find the most current entry <= now */
    for (prev_actkvno = cur_actkvno = act_mkey_list; cur_actkvno != NULL;
         prev_actkvno = cur_actkvno, cur_actkvno = cur_actkvno->next) {

        if (cur_actkvno->act_time == now) {
            tmp_act_kvno = cur_actkvno->act_kvno;
            found = TRUE;
            break;
        } else if (cur_actkvno->act_time > now && prev_actkvno->act_time <= now) {
            tmp_act_kvno = prev_actkvno->act_kvno;
            found = TRUE;
            break;
        }
    }

    if (!found) {
        /*
         * The end of the list was encountered and all entries are < now so use
         * the latest entry.
         */
        if (prev_actkvno->act_time <= now)
            tmp_act_kvno = prev_actkvno->act_kvno;
        else
            return KRB5_KDB_NOACTMASTERKEY;  /* This shouldn't happen. */

    }

    while (cur_keyblock && cur_keyblock->kvno != tmp_act_kvno)
        cur_keyblock = cur_keyblock->next;

    if (cur_keyblock) {
        *act_mkey = &cur_keyblock->keyblock;
        if (act_kvno != NULL)
            *act_kvno = tmp_act_kvno;
        return (0);
    } else {
        return KRB5_KDB_NO_MATCHING_KEY;
    }
}

/*
 * Locates the mkey used to protect a princ's keys.  Note, the caller must not
 * free the output key.
 */
krb5_error_code
krb5_dbe_find_mkey(krb5_context context, krb5_keylist_node *mkey_list,
                   krb5_db_entry *entry, krb5_keyblock **mkey)
{
    krb5_kvno mkvno;
    krb5_error_code retval;
    krb5_keylist_node *cur_keyblock = mkey_list;

    retval = krb5_dbe_get_mkvno(context, entry, mkey_list, &mkvno);
    if (retval)
        return (retval);

    while (cur_keyblock && cur_keyblock->kvno != mkvno)
        cur_keyblock = cur_keyblock->next;

    if (cur_keyblock) {
        *mkey = &cur_keyblock->keyblock;
        return (0);
    } else {
        return KRB5_KDB_NO_MATCHING_KEY;
    }
}

void   *
krb5_db_alloc(krb5_context kcontext, void *ptr, size_t size)
{
    krb5_error_code status;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return NULL;
    return v->alloc(kcontext, ptr, size);
}

void
krb5_db_free(krb5_context kcontext, void *ptr)
{
    krb5_error_code status;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return;
    v->free(kcontext, ptr);
}

/* has to be modified */

krb5_error_code
krb5_dbe_find_enctype(krb5_context kcontext, krb5_db_entry *dbentp,
                      krb5_int32 ktype, krb5_int32 stype, krb5_int32 kvno,
                      krb5_key_data **kdatap)
{
    krb5_int32 start = 0;
    return krb5_dbe_search_enctype(kcontext, dbentp, &start, ktype, stype,
                                   kvno, kdatap);
}

krb5_error_code
krb5_dbe_search_enctype(krb5_context kcontext, krb5_db_entry *dbentp,
                        krb5_int32 *start, krb5_int32 ktype, krb5_int32 stype,
                        krb5_int32 kvno, krb5_key_data ** kdatap)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    return v->dbe_search_enctype(kcontext, dbentp, start, ktype, stype, kvno,
                                 kdatap);
}

#define REALM_SEP_STRING        "@"

krb5_error_code
krb5_db_setup_mkey_name(krb5_context context, const char *keyname,
                        const char *realm, char **fullname,
                        krb5_principal *principal)
{
    krb5_error_code retval;
    char   *fname;

    if (!keyname)
        keyname = KRB5_KDB_M_NAME;      /* XXX external? */

    if (asprintf(&fname, "%s%s%s", keyname, REALM_SEP_STRING, realm) < 0)
        return ENOMEM;

    if ((retval = krb5_parse_name(context, fname, principal)))
        return retval;
    if (fullname)
        *fullname = fname;
    else
        free(fname);
    return 0;
}

krb5_error_code
krb5_dbe_lookup_last_pwd_change(krb5_context context, krb5_db_entry *entry,
                                krb5_timestamp *stamp)
{
    krb5_tl_data tl_data;
    krb5_error_code code;
    krb5_int32 tmp;

    tl_data.tl_data_type = KRB5_TL_LAST_PWD_CHANGE;

    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
        return (code);

    if (tl_data.tl_data_length != 4) {
        *stamp = 0;
        return (0);
    }

    krb5_kdb_decode_int32(tl_data.tl_data_contents, tmp);

    *stamp = (krb5_timestamp) tmp;

    return (0);
}

krb5_error_code
krb5_dbe_lookup_last_admin_unlock(krb5_context context, krb5_db_entry *entry,
                                  krb5_timestamp *stamp)
{
    krb5_tl_data tl_data;
    krb5_error_code code;
    krb5_int32 tmp;

    tl_data.tl_data_type = KRB5_TL_LAST_ADMIN_UNLOCK;

    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
        return (code);

    if (tl_data.tl_data_length != 4) {
        *stamp = 0;
        return (0);
    }

    krb5_kdb_decode_int32(tl_data.tl_data_contents, tmp);

    *stamp = (krb5_timestamp) tmp;

    return (0);
}

krb5_error_code
krb5_dbe_lookup_tl_data(krb5_context context, krb5_db_entry *entry,
                        krb5_tl_data *ret_tl_data)
{
    krb5_tl_data *tl_data;

    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next) {
        if (tl_data->tl_data_type == ret_tl_data->tl_data_type) {
            *ret_tl_data = *tl_data;
            return (0);
        }
    }

    /*
     * If the requested record isn't found, return zero bytes.  If it
     * ever means something to have a zero-length tl_data, this code
     * and its callers will have to be changed.
     */

    ret_tl_data->tl_data_length = 0;
    ret_tl_data->tl_data_contents = NULL;
    return (0);
}

krb5_error_code
krb5_dbe_create_key_data(krb5_context context, krb5_db_entry *entry)
{
    if ((entry->key_data =
         (krb5_key_data *) krb5_db_alloc(context, entry->key_data,
                                         (sizeof(krb5_key_data) *
                                          (entry->n_key_data + 1)))) == NULL)
        return (ENOMEM);

    memset(entry->key_data + entry->n_key_data, 0, sizeof(krb5_key_data));
    entry->n_key_data++;

    return 0;
}

krb5_error_code
krb5_dbe_update_mod_princ_data(krb5_context context, krb5_db_entry *entry,
                               krb5_timestamp mod_date,
                               krb5_const_principal mod_princ)
{
    krb5_tl_data tl_data;

    krb5_error_code retval = 0;
    krb5_octet *nextloc = 0;
    char   *unparse_mod_princ = 0;
    unsigned int unparse_mod_princ_size;

    if ((retval = krb5_unparse_name(context, mod_princ, &unparse_mod_princ)))
        return (retval);

    unparse_mod_princ_size = strlen(unparse_mod_princ) + 1;

    if ((nextloc = (krb5_octet *) malloc(unparse_mod_princ_size + 4))
        == NULL) {
        free(unparse_mod_princ);
        return (ENOMEM);
    }

    tl_data.tl_data_type = KRB5_TL_MOD_PRINC;
    tl_data.tl_data_length = unparse_mod_princ_size + 4;
    tl_data.tl_data_contents = nextloc;

    /* Mod Date */
    krb5_kdb_encode_int32(mod_date, nextloc);

    /* Mod Princ */
    memcpy(nextloc + 4, unparse_mod_princ, unparse_mod_princ_size);

    retval = krb5_dbe_update_tl_data(context, entry, &tl_data);

    free(unparse_mod_princ);
    free(nextloc);

    return (retval);
}

krb5_error_code
krb5_dbe_lookup_mod_princ_data(krb5_context context, krb5_db_entry *entry,
                               krb5_timestamp *mod_time,
                               krb5_principal *mod_princ)
{
    krb5_tl_data tl_data;
    krb5_error_code code;

    *mod_princ = NULL;
    *mod_time = 0;

    tl_data.tl_data_type = KRB5_TL_MOD_PRINC;

    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
        return (code);

    if ((tl_data.tl_data_length < 5) ||
        (tl_data.tl_data_contents[tl_data.tl_data_length - 1] != '\0'))
        return (KRB5_KDB_TRUNCATED_RECORD);

    /* Mod Date */
    krb5_kdb_decode_int32(tl_data.tl_data_contents, *mod_time);

    /* Mod Princ */
    if ((code = krb5_parse_name(context,
                                (const char *) (tl_data.tl_data_contents + 4),
                                mod_princ)))
        return (code);

    return (0);
}

krb5_error_code
krb5_dbe_lookup_mkvno(krb5_context context, krb5_db_entry *entry,
                      krb5_kvno *mkvno)
{
    krb5_tl_data tl_data;
    krb5_error_code code;
    krb5_int16 tmp;

    tl_data.tl_data_type = KRB5_TL_MKVNO;

    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
        return (code);

    if (tl_data.tl_data_length == 0) {
        *mkvno = 0; /* Indicates KRB5_TL_MKVNO data not present */
        return (0);
    } else if (tl_data.tl_data_length != 2) {
        return (KRB5_KDB_TRUNCATED_RECORD);
    }

    krb5_kdb_decode_int16(tl_data.tl_data_contents, tmp);
    *mkvno = (krb5_kvno) tmp;
    return (0);
}

krb5_error_code
krb5_dbe_get_mkvno(krb5_context context, krb5_db_entry *entry,
                   krb5_keylist_node *mkey_list, krb5_kvno *mkvno)
{
    krb5_error_code code;
    krb5_kvno kvno;

    if (mkey_list == NULL)
        return EINVAL;

    /* Output the value from entry tl_data if present. */
    code = krb5_dbe_lookup_mkvno(context, entry, &kvno);
    if (code != 0)
        return code;
    if (kvno != 0) {
        *mkvno = kvno;
        return 0;
    }

    /* Determine the minimum kvno in mkey_list and output that. */
    kvno = (krb5_kvno) -1;
    while (mkey_list != NULL) {
        if (mkey_list->kvno < kvno)
            kvno = mkey_list->kvno;
        mkey_list = mkey_list->next;
    }
    *mkvno = kvno;
    return 0;
}

krb5_error_code
krb5_dbe_update_mkvno(krb5_context context, krb5_db_entry *entry,
                      krb5_kvno mkvno)
{
    krb5_tl_data tl_data;
    krb5_octet buf[2]; /* this is the encoded size of an int16 */
    krb5_int16 tmp_kvno = (krb5_int16) mkvno;

    tl_data.tl_data_type = KRB5_TL_MKVNO;
    tl_data.tl_data_length = sizeof(buf);
    krb5_kdb_encode_int16(tmp_kvno, buf);
    tl_data.tl_data_contents = buf;

    return (krb5_dbe_update_tl_data(context, entry, &tl_data));
}

krb5_error_code
krb5_dbe_lookup_mkey_aux(krb5_context context, krb5_db_entry *entry,
                         krb5_mkey_aux_node **mkey_aux_data_list)
{
    krb5_tl_data tl_data;
    krb5_int16 version;
    krb5_mkey_aux_node *head_data = NULL, *new_data = NULL,
        *prev_data = NULL;
    krb5_octet *curloc; /* current location pointer */
    krb5_error_code code;

    tl_data.tl_data_type = KRB5_TL_MKEY_AUX;
    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
        return (code);

    if (tl_data.tl_data_contents == NULL) {
        *mkey_aux_data_list = NULL;
        return (0);
    } else {
        /* get version to determine how to parse the data */
        krb5_kdb_decode_int16(tl_data.tl_data_contents, version);
        if (version == 1) {
            /* variable size, must be at least 10 bytes */
            if (tl_data.tl_data_length < 10)
                return (KRB5_KDB_TRUNCATED_RECORD);

            /* curloc points to first tuple entry in the tl_data_contents */
            curloc = tl_data.tl_data_contents + sizeof(version);

            while (curloc < (tl_data.tl_data_contents + tl_data.tl_data_length)) {

                new_data = (krb5_mkey_aux_node *) malloc(sizeof(krb5_mkey_aux_node));
                if (new_data == NULL) {
                    krb5_dbe_free_mkey_aux_list(context, head_data);
                    return (ENOMEM);
                }
                memset(new_data, 0, sizeof(krb5_mkey_aux_node));

                krb5_kdb_decode_int16(curloc, new_data->mkey_kvno);
                curloc += sizeof(krb5_ui_2);
                krb5_kdb_decode_int16(curloc, new_data->latest_mkey.key_data_kvno);
                curloc += sizeof(krb5_ui_2);
                krb5_kdb_decode_int16(curloc, new_data->latest_mkey.key_data_type[0]);
                curloc += sizeof(krb5_ui_2);
                krb5_kdb_decode_int16(curloc, new_data->latest_mkey.key_data_length[0]);
                curloc += sizeof(krb5_ui_2);

                new_data->latest_mkey.key_data_contents[0] = (krb5_octet *)
                    malloc(new_data->latest_mkey.key_data_length[0]);

                if (new_data->latest_mkey.key_data_contents[0] == NULL) {
                    krb5_dbe_free_mkey_aux_list(context, head_data);
                    free(new_data);
                    return (ENOMEM);
                }
                memcpy(new_data->latest_mkey.key_data_contents[0], curloc,
                       new_data->latest_mkey.key_data_length[0]);
                curloc += new_data->latest_mkey.key_data_length[0];

                /* always using key data ver 1 for mkeys */
                new_data->latest_mkey.key_data_ver = 1;

                new_data->next = NULL;
                if (prev_data != NULL)
                    prev_data->next = new_data;
                else
                    head_data = new_data;
                prev_data = new_data;
            }
        } else {
            krb5_set_error_message(context, KRB5_KDB_BAD_VERSION,
                                   "Illegal version number for KRB5_TL_MKEY_AUX %d\n",
                                   version);
            return (KRB5_KDB_BAD_VERSION);
        }
    }
    *mkey_aux_data_list = head_data;
    return (0);
}

#if KRB5_TL_MKEY_AUX_VER == 1
krb5_error_code
krb5_dbe_update_mkey_aux(krb5_context context, krb5_db_entry *entry,
                         krb5_mkey_aux_node *mkey_aux_data_list)
{
    krb5_tl_data tl_data;
    krb5_int16 version, tmp_kvno;
    unsigned char *nextloc;
    krb5_mkey_aux_node *aux_data_entry;

    if (!mkey_aux_data_list) {
        /* delete the KRB5_TL_MKEY_AUX from the entry */
        krb5_dbe_delete_tl_data(context, entry, KRB5_TL_MKEY_AUX);
        return (0);
    }

    memset(&tl_data, 0, sizeof(tl_data));
    tl_data.tl_data_type = KRB5_TL_MKEY_AUX;
    /*
     * determine out how much space to allocate.  Note key_data_ver not stored
     * as this is hard coded to one and is accounted for in
     * krb5_dbe_lookup_mkey_aux.
     */
    tl_data.tl_data_length = sizeof(version); /* version */
    for (aux_data_entry = mkey_aux_data_list; aux_data_entry != NULL;
         aux_data_entry = aux_data_entry->next) {

        tl_data.tl_data_length += (sizeof(krb5_ui_2) + /* mkey_kvno */
                                   sizeof(krb5_ui_2) + /* latest_mkey kvno */
                                   sizeof(krb5_ui_2) + /* latest_mkey enctype */
                                   sizeof(krb5_ui_2) + /* latest_mkey length */
                                   aux_data_entry->latest_mkey.key_data_length[0]);
    }

    tl_data.tl_data_contents = (krb5_octet *) malloc(tl_data.tl_data_length);
    if (tl_data.tl_data_contents == NULL)
        return (ENOMEM);

    nextloc = tl_data.tl_data_contents;
    version = KRB5_TL_MKEY_AUX_VER;
    krb5_kdb_encode_int16(version, nextloc);
    nextloc += sizeof(krb5_ui_2);

    for (aux_data_entry = mkey_aux_data_list; aux_data_entry != NULL;
         aux_data_entry = aux_data_entry->next) {

        tmp_kvno = (krb5_int16) aux_data_entry->mkey_kvno;
        krb5_kdb_encode_int16(tmp_kvno, nextloc);
        nextloc += sizeof(krb5_ui_2);

        krb5_kdb_encode_int16(aux_data_entry->latest_mkey.key_data_kvno,
                              nextloc);
        nextloc += sizeof(krb5_ui_2);

        krb5_kdb_encode_int16(aux_data_entry->latest_mkey.key_data_type[0],
                              nextloc);
        nextloc += sizeof(krb5_ui_2);

        krb5_kdb_encode_int16(aux_data_entry->latest_mkey.key_data_length[0],
                              nextloc);
        nextloc += sizeof(krb5_ui_2);

        if (aux_data_entry->latest_mkey.key_data_length[0] > 0) {
            memcpy(nextloc, aux_data_entry->latest_mkey.key_data_contents[0],
                   aux_data_entry->latest_mkey.key_data_length[0]);
            nextloc += aux_data_entry->latest_mkey.key_data_length[0];
        }
    }

    return (krb5_dbe_update_tl_data(context, entry, &tl_data));
}
#endif /* KRB5_TL_MKEY_AUX_VER == 1 */

#if KRB5_TL_ACTKVNO_VER == 1
/*
 * If version of the KRB5_TL_ACTKVNO data is KRB5_TL_ACTKVNO_VER == 1 then size of
 * a actkvno tuple {act_kvno, act_time} entry is:
 */
#define ACTKVNO_TUPLE_SIZE (sizeof(krb5_int16) + sizeof(krb5_int32))
#define act_kvno(cp) (cp) /* return pointer to start of act_kvno data */
#define act_time(cp) ((cp) + sizeof(krb5_int16)) /* return pointer to start of act_time data */
#endif

krb5_error_code
krb5_dbe_lookup_actkvno(krb5_context context, krb5_db_entry *entry,
                        krb5_actkvno_node **actkvno_list)
{
    krb5_tl_data tl_data;
    krb5_error_code code;
    krb5_int16 version, tmp_kvno;
    krb5_actkvno_node *head_data = NULL, *new_data = NULL, *prev_data = NULL;
    unsigned int num_actkvno, i;
    krb5_octet *next_tuple;

    memset(&tl_data, 0, sizeof(tl_data));
    tl_data.tl_data_type = KRB5_TL_ACTKVNO;

    if ((code = krb5_dbe_lookup_tl_data(context, entry, &tl_data)))
        return (code);

    if (tl_data.tl_data_contents == NULL) {
        *actkvno_list = NULL;
        return (0);
    } else {
        /* get version to determine how to parse the data */
        krb5_kdb_decode_int16(tl_data.tl_data_contents, version);
        if (version == 1) {

            /* variable size, must be at least 8 bytes */
            if (tl_data.tl_data_length < 8)
                return (KRB5_KDB_TRUNCATED_RECORD);

            /*
             * Find number of tuple entries, remembering to account for version
             * field.
             */
            num_actkvno = (tl_data.tl_data_length - sizeof(version)) /
                ACTKVNO_TUPLE_SIZE;
            prev_data = NULL;
            /* next_tuple points to first tuple entry in the tl_data_contents */
            next_tuple = tl_data.tl_data_contents + sizeof(version);
            for (i = 0; i < num_actkvno; i++) {
                new_data = (krb5_actkvno_node *) malloc(sizeof(krb5_actkvno_node));
                if (new_data == NULL) {
                    krb5_dbe_free_actkvno_list(context, head_data);
                    return (ENOMEM);
                }
                memset(new_data, 0, sizeof(krb5_actkvno_node));

                /* using tmp_kvno to avoid type mismatch */
                krb5_kdb_decode_int16(act_kvno(next_tuple), tmp_kvno);
                new_data->act_kvno = (krb5_kvno) tmp_kvno;
                krb5_kdb_decode_int32(act_time(next_tuple), new_data->act_time);

                if (prev_data != NULL)
                    prev_data->next = new_data;
                else
                    head_data = new_data;
                prev_data = new_data;
                next_tuple += ACTKVNO_TUPLE_SIZE;
            }
        } else {
            krb5_set_error_message (context, KRB5_KDB_BAD_VERSION,
                                    "Illegal version number for KRB5_TL_ACTKVNO %d\n",
                                    version);
            return (KRB5_KDB_BAD_VERSION);
        }
    }
    *actkvno_list = head_data;
    return (0);
}

/*
 * Add KRB5_TL_ACTKVNO TL data entries to krb5_db_entry *entry
 */
#if KRB5_TL_ACTKVNO_VER == 1
krb5_error_code
krb5_dbe_update_actkvno(krb5_context context, krb5_db_entry *entry,
                        const krb5_actkvno_node *actkvno_list)
{
    krb5_error_code retval = 0;
    krb5_int16 version, tmp_kvno;
    krb5_tl_data new_tl_data;
    unsigned char *nextloc;
    const krb5_actkvno_node *cur_actkvno;
    krb5_octet *tmpptr;

    if (actkvno_list == NULL)
        return EINVAL;

    memset(&new_tl_data, 0, sizeof(new_tl_data));
    /* allocate initial KRB5_TL_ACTKVNO tl_data entry */
    new_tl_data.tl_data_length = sizeof(version);
    new_tl_data.tl_data_contents = (krb5_octet *) malloc(new_tl_data.tl_data_length);
    if (new_tl_data.tl_data_contents == NULL)
        return ENOMEM;

    /* add the current version # for the data format used for KRB5_TL_ACTKVNO */
    version = KRB5_TL_ACTKVNO_VER;
    krb5_kdb_encode_int16(version, (unsigned char *) new_tl_data.tl_data_contents);

    for (cur_actkvno = actkvno_list; cur_actkvno != NULL;
         cur_actkvno = cur_actkvno->next) {

        new_tl_data.tl_data_length += ACTKVNO_TUPLE_SIZE;
        tmpptr = realloc(new_tl_data.tl_data_contents, new_tl_data.tl_data_length);
        if (tmpptr == NULL) {
            free(new_tl_data.tl_data_contents);
            return ENOMEM;
        } else {
            new_tl_data.tl_data_contents = tmpptr;
        }

        /*
         * Using realloc so tl_data_contents is required to correctly calculate
         * next location to store new tuple.
         */
        nextloc = new_tl_data.tl_data_contents + new_tl_data.tl_data_length - ACTKVNO_TUPLE_SIZE;
        /* using tmp_kvno to avoid type mismatch issues */
        tmp_kvno = (krb5_int16) cur_actkvno->act_kvno;
        krb5_kdb_encode_int16(tmp_kvno, nextloc);
        nextloc += sizeof(krb5_ui_2);
        krb5_kdb_encode_int32((krb5_ui_4)cur_actkvno->act_time, nextloc);
    }

    new_tl_data.tl_data_type = KRB5_TL_ACTKVNO;
    retval = krb5_dbe_update_tl_data(context, entry, &new_tl_data);
    free(new_tl_data.tl_data_contents);

    return (retval);
}
#endif /* KRB5_TL_ACTKVNO_VER == 1 */

krb5_error_code
krb5_dbe_update_last_pwd_change(krb5_context context, krb5_db_entry *entry,
                                krb5_timestamp stamp)
{
    krb5_tl_data tl_data;
    krb5_octet buf[4];          /* this is the encoded size of an int32 */

    tl_data.tl_data_type = KRB5_TL_LAST_PWD_CHANGE;
    tl_data.tl_data_length = sizeof(buf);
    krb5_kdb_encode_int32((krb5_int32) stamp, buf);
    tl_data.tl_data_contents = buf;

    return (krb5_dbe_update_tl_data(context, entry, &tl_data));
}

krb5_error_code
krb5_dbe_update_last_admin_unlock(krb5_context context, krb5_db_entry *entry,
                                  krb5_timestamp stamp)
{
    krb5_tl_data tl_data;
    krb5_octet buf[4];          /* this is the encoded size of an int32 */

    tl_data.tl_data_type = KRB5_TL_LAST_ADMIN_UNLOCK;
    tl_data.tl_data_length = sizeof(buf);
    krb5_kdb_encode_int32((krb5_int32) stamp, buf);
    tl_data.tl_data_contents = buf;

    return (krb5_dbe_update_tl_data(context, entry, &tl_data));
}

krb5_error_code
krb5_dbe_delete_tl_data(krb5_context context, krb5_db_entry *entry,
                        krb5_int16 tl_data_type)
{
    krb5_tl_data *tl_data, *prev_tl_data, *free_tl_data;

    /*
     * Find existing entries of the specified type and remove them from the
     * entry's tl_data list.
     */

    for (prev_tl_data = tl_data = entry->tl_data; tl_data != NULL;) {
        if (tl_data->tl_data_type == tl_data_type) {
            if (tl_data == entry->tl_data) {
                /* remove from head */
                entry->tl_data = tl_data->tl_data_next;
                prev_tl_data = entry->tl_data;
            } else if (tl_data->tl_data_next == NULL) {
                /* remove from tail */
                prev_tl_data->tl_data_next = NULL;
            } else {
                /* remove in between */
                prev_tl_data->tl_data_next = tl_data->tl_data_next;
            }
            free_tl_data = tl_data;
            tl_data = tl_data->tl_data_next;
            krb5_dbe_free_tl_data(context, free_tl_data);
            entry->n_tl_data--;
        } else {
            prev_tl_data = tl_data;
            tl_data = tl_data->tl_data_next;
        }
    }

    return (0);
}

krb5_error_code
krb5_dbe_update_tl_data(krb5_context context, krb5_db_entry *entry,
                        krb5_tl_data *new_tl_data)
{
    krb5_tl_data *tl_data = NULL;
    krb5_octet *tmp;

    /*
     * Copy the new data first, so we can fail cleanly if malloc()
     * fails.
     */
    if ((tmp =
         (krb5_octet *) krb5_db_alloc(context, NULL,
                                      new_tl_data->tl_data_length)) == NULL)
        return (ENOMEM);

    /*
     * Find an existing entry of the specified type and point at
     * it, or NULL if not found.
     */

    if (new_tl_data->tl_data_type != KRB5_TL_DB_ARGS) { /* db_args can be multiple */
        for (tl_data = entry->tl_data; tl_data;
             tl_data = tl_data->tl_data_next)
            if (tl_data->tl_data_type == new_tl_data->tl_data_type)
                break;
    }

    /* If necessary, chain a new record in the beginning and point at it.  */

    if (!tl_data) {
        tl_data = krb5_db_alloc(context, NULL, sizeof(krb5_tl_data));
        if (tl_data == NULL) {
            free(tmp);
            return (ENOMEM);
        }
        memset(tl_data, 0, sizeof(krb5_tl_data));
        tl_data->tl_data_next = entry->tl_data;
        entry->tl_data = tl_data;
        entry->n_tl_data++;
    }

    /* fill in the record */

    if (tl_data->tl_data_contents)
        krb5_db_free(context, tl_data->tl_data_contents);

    tl_data->tl_data_type = new_tl_data->tl_data_type;
    tl_data->tl_data_length = new_tl_data->tl_data_length;
    tl_data->tl_data_contents = tmp;
    memcpy(tmp, new_tl_data->tl_data_contents, tl_data->tl_data_length);

    return (0);
}

/* change password functions */
krb5_error_code
krb5_dbe_cpw(krb5_context kcontext, krb5_keyblock *master_key,
             krb5_key_salt_tuple *ks_tuple, int ks_tuple_count, char *passwd,
             int new_kvno, krb5_boolean keepold, krb5_db_entry *db_entry)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    return v->change_pwd(kcontext, master_key, ks_tuple, ks_tuple_count,
                         passwd, new_kvno, keepold, db_entry);
}

/* policy management functions */
krb5_error_code
krb5_db_create_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->create_policy == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->create_policy(kcontext, policy);
}

krb5_error_code
krb5_db_get_policy(krb5_context kcontext, char *name, osa_policy_ent_t *policy)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->get_policy == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->get_policy(kcontext, name, policy);
}

krb5_error_code
krb5_db_put_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->put_policy == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->put_policy(kcontext, policy);
}

krb5_error_code
krb5_db_iter_policy(krb5_context kcontext, char *match_entry,
                    osa_adb_iter_policy_func func, void *data)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->iter_policy == NULL)
        return 0;
    return v->iter_policy(kcontext, match_entry, func, data);
}

krb5_error_code
krb5_db_delete_policy(krb5_context kcontext, char *policy)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->delete_policy == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->delete_policy(kcontext, policy);
}

void
krb5_db_free_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status || v->free_policy == NULL)
        return;
    v->free_policy(kcontext, policy);
}

krb5_error_code
krb5_db_promote(krb5_context kcontext, char **db_args)
{
    krb5_error_code status;
    char *section;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->promote_db == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    status = get_conf_section(kcontext, &section);
    if (status)
        return status;
    status = v->promote_db(kcontext, section, db_args);
    free(section);
    return status;
}

static krb5_error_code
decrypt_iterator(krb5_context kcontext, const krb5_key_data * key_data,
                 krb5_keyblock *dbkey, krb5_keysalt *keysalt)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;
    krb5_keylist_node *n = kcontext->dal_handle->master_keylist;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    for (; n; n = n->next) {
        krb5_clear_error_message(kcontext);
        status = v->decrypt_key_data(kcontext, &n->keyblock, key_data, dbkey,
                                     keysalt);
        if (status == 0)
            return 0;
    }
    return status;
}

krb5_error_code
krb5_dbe_decrypt_key_data(krb5_context kcontext, const krb5_keyblock *mkey,
                          const krb5_key_data *key_data, krb5_keyblock *dbkey,
                          krb5_keysalt *keysalt)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;
    krb5_keylist_node *n = kcontext->dal_handle->master_keylist;
    krb5_keyblock *cur_mkey;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (mkey || !n)
        return v->decrypt_key_data(kcontext, mkey, key_data, dbkey, keysalt);
    status = decrypt_iterator(kcontext, key_data, dbkey, keysalt);
    if (status == 0)
        return 0;
    if (kcontext->dal_handle->master_keylist) {
        /* Try reloading master keys. */
        cur_mkey = &kcontext->dal_handle->master_keylist->keyblock;
        if (krb5_db_fetch_mkey_list(kcontext,
                                    kcontext->dal_handle->master_princ,
                                    cur_mkey, -1, NULL) == 0)
            return decrypt_iterator(kcontext, key_data, dbkey, keysalt);
    }
    return status;
}

krb5_error_code
krb5_dbe_encrypt_key_data(krb5_context kcontext, const krb5_keyblock *mkey,
                          const krb5_keyblock *dbkey,
                          const krb5_keysalt *keysalt, int keyver,
                          krb5_key_data *key_data)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    return v->encrypt_key_data(kcontext, mkey, dbkey, keysalt, keyver,
                               key_data);
}

krb5_error_code
krb5_db_get_context(krb5_context context, void **db_context)
{
    *db_context = KRB5_DB_GET_DB_CONTEXT(context);
    if (*db_context == NULL)
        return KRB5_KDB_DBNOTINITED;
    return 0;
}

krb5_error_code
krb5_db_set_context(krb5_context context, void *db_context)
{
    KRB5_DB_GET_DB_CONTEXT(context) = db_context;

    return 0;
}

krb5_error_code
krb5_db_sign_authdata(krb5_context kcontext, unsigned int flags,
                      krb5_const_principal client_princ, krb5_db_entry *client,
                      krb5_db_entry *server, krb5_db_entry *krbtgt,
                      krb5_keyblock *client_key, krb5_keyblock *server_key,
                      krb5_keyblock *krbtgt_key, krb5_keyblock *session_key,
                      krb5_timestamp authtime, krb5_authdata **tgt_auth_data,
                      krb5_authdata ***signed_auth_data)
{
    krb5_error_code status = 0;
    kdb_vftabl *v;

    *signed_auth_data = NULL;
    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->sign_authdata == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->sign_authdata(kcontext, flags, client_princ, client, server,
                            krbtgt, client_key, server_key, krbtgt_key,
                            session_key, authtime, tgt_auth_data,
                            signed_auth_data);
}

krb5_error_code
krb5_db_check_transited_realms(krb5_context kcontext,
                               const krb5_data *tr_contents,
                               const krb5_data *client_realm,
                               const krb5_data *server_realm)
{
    krb5_error_code status;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status)
        return status;
    if (v->check_transited_realms == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->check_transited_realms(kcontext, tr_contents, client_realm,
                                     server_realm);
}

krb5_error_code
krb5_db_check_policy_as(krb5_context kcontext, krb5_kdc_req *request,
                        krb5_db_entry *client, krb5_db_entry *server,
                        krb5_timestamp kdc_time, const char **status,
                        krb5_data *e_data)
{
    krb5_error_code ret;
    kdb_vftabl *v;

    *status = NULL;
    *e_data = empty_data();
    ret = get_vftabl(kcontext, &v);
    if (ret)
        return ret;
    if (v->check_policy_as == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->check_policy_as(kcontext, request, client, server, kdc_time,
                              status, e_data);
}

krb5_error_code
krb5_db_check_policy_tgs(krb5_context kcontext, krb5_kdc_req *request,
                         krb5_db_entry *server, krb5_ticket *ticket,
                         const char **status, krb5_data *e_data)
{
    krb5_error_code ret;
    kdb_vftabl *v;

    *status = NULL;
    *e_data = empty_data();
    ret = get_vftabl(kcontext, &v);
    if (ret)
        return ret;
    if (v->check_policy_tgs == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->check_policy_tgs(kcontext, request, server, ticket, status,
                               e_data);
}

void
krb5_db_audit_as_req(krb5_context kcontext, krb5_kdc_req *request,
                     krb5_db_entry *client, krb5_db_entry *server,
                     krb5_timestamp authtime, krb5_error_code error_code)
{
    krb5_error_code status;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status || v->audit_as_req == NULL)
        return;
    v->audit_as_req(kcontext, request, client, server, authtime, error_code);
}

void
krb5_db_refresh_config(krb5_context kcontext)
{
    krb5_error_code status;
    kdb_vftabl *v;

    status = get_vftabl(kcontext, &v);
    if (status || v->refresh_config == NULL)
        return;
    v->refresh_config(kcontext);
}

krb5_error_code
krb5_db_check_allowed_to_delegate(krb5_context kcontext,
                                  krb5_const_principal client,
                                  const krb5_db_entry *server,
                                  krb5_const_principal proxy)
{
    krb5_error_code ret;
    kdb_vftabl *v;

    ret = get_vftabl(kcontext, &v);
    if (ret)
        return ret;
    if (v->check_allowed_to_delegate == NULL)
        return KRB5_PLUGIN_OP_NOTSUPP;
    return v->check_allowed_to_delegate(kcontext, client, server, proxy);
}
