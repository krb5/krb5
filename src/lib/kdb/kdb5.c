/*
 * Copyright 2006, 2009 by the Massachusetts Institute of Technology.
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
#include <assert.h>
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

#ifdef _KDB5_STATIC_LINK
#undef _KDB5_DYNAMIC_LINK
#else
#undef _KDB5_DYNAMIC_LINK
/* to avoid redefinition problem */
#define _KDB5_DYNAMIC_LINK
#endif

static db_library lib_list;

/*
 * Helper Functions
 */

MAKE_INIT_FUNCTION(kdb_init_lock_list);
MAKE_FINI_FUNCTION(kdb_fini_lock_list);

int
kdb_init_lock_list(void)
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
kdb_fini_lock_list(void)
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

#define kdb_init_lib_lock(a) 0
#define kdb_destroy_lib_lock(a) (void)0
#define kdb_lock_lib_lock(a, b) 0
#define kdb_unlock_lib_lock(a, b) (void)0

/* Caller must free result*/

static char *
kdb_get_conf_section(krb5_context kcontext)
{
    krb5_error_code status = 0;
    char   *result = NULL;
    char   *value = NULL;

    if (kcontext->default_realm == NULL)
	return NULL;
    /* The profile has to have been initialized.  If the profile was
       not initialized, expect nothing less than a crash.  */
    status = profile_get_string(kcontext->profile,
				/* realms */
				KDB_REALM_SECTION,
				kcontext->default_realm,
				/* under the realm name, database_module */
				KDB_MODULE_POINTER,
				/* default value is the realm name itself */
				kcontext->default_realm,
				&value);

    if (status) {
	/* some problem */
	result = strdup(kcontext->default_realm);
	/* let NULL be handled by the caller */
    } else {
	result = strdup(value);
	/* free profile string */
	profile_release_string(value);
    }

    return result;
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
    if (status) {
	goto clean_n_exit;
    }

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
    if (value) {
	/* free profile string */
	profile_release_string(value);
    }

    if (lib) {
	/* free profile string */
	profile_release_string(lib);
    }
    return result;
}

static void
kdb_setup_opt_functions(db_library lib)
{
    if (lib->vftabl.set_master_key == NULL) {
	lib->vftabl.set_master_key = kdb_def_set_mkey;
    }

    if (lib->vftabl.set_master_key_list == NULL) {
	lib->vftabl.set_master_key_list = kdb_def_set_mkey_list;
    }

    if (lib->vftabl.get_master_key == NULL) {
	lib->vftabl.get_master_key = kdb_def_get_mkey;
    }

    if (lib->vftabl.get_master_key_list == NULL) {
	lib->vftabl.get_master_key_list = kdb_def_get_mkey_list;
    }

    if (lib->vftabl.fetch_master_key == NULL) {
	lib->vftabl.fetch_master_key = krb5_db_def_fetch_mkey;
    }

    if (lib->vftabl.verify_master_key == NULL) {
	lib->vftabl.verify_master_key = krb5_def_verify_master_key;
    }

    if (lib->vftabl.fetch_master_key_list == NULL) {
	lib->vftabl.fetch_master_key_list = krb5_def_fetch_mkey_list;
    }

    if (lib->vftabl.store_master_key_list == NULL) {
	lib->vftabl.store_master_key_list = krb5_def_store_mkey_list;
    }

    if (lib->vftabl.dbe_search_enctype == NULL) {
	lib->vftabl.dbe_search_enctype = krb5_dbe_def_search_enctype;
    }

    if (lib->vftabl.db_change_pwd == NULL) {
	lib->vftabl.db_change_pwd = krb5_dbe_def_cpw;
    }

    if (lib->vftabl.store_master_key == NULL) {
	lib->vftabl.store_master_key = krb5_def_store_mkey;
    }

    if (lib->vftabl.promote_db == NULL) {
	lib->vftabl.promote_db = krb5_def_promote_db;
    }
    
    if (lib->vftabl.dbekd_decrypt_key_data == NULL) {
	lib->vftabl.dbekd_decrypt_key_data = krb5_dbekd_def_decrypt_key_data;
    }

    if (lib->vftabl.dbekd_encrypt_key_data == NULL) {
	lib->vftabl.dbekd_encrypt_key_data = krb5_dbekd_def_encrypt_key_data;
    }
}

static int kdb_db2_pol_err_loaded = 0;
#ifdef _KDB5_STATIC_LINK
#define DEF_SYMBOL(a) extern kdb_vftabl krb5_db_vftabl_ ## a
#define GET_SYMBOL(a) (krb5_db_vftabl_ ## a)
static krb5_error_code
kdb_load_library(krb5_context kcontext, char *lib_name, db_library * lib)
{
    krb5_error_code status;
    void   *vftabl_addr = NULL;
    char    buf[KRB5_MAX_ERR_STR];

    if (!strcmp("kdb_db2", lib_name) && (kdb_db2_pol_err_loaded == 0)) {
	initialize_adb_error_table();
	kdb_db2_pol_err_loaded = 1;
    }

    *lib = calloc((size_t) 1, sizeof(**lib));
    if (*lib == NULL) {
	status = ENOMEM;
	goto clean_n_exit;
    }

    status = kdb_init_lib_lock(*lib);
    if (status) {
	goto clean_n_exit;
    }

    strlcpy((*lib)->name, lib_name, sizeof((*lib)->name));

#if !defined(KDB5_USE_LIB_KDB_DB2) && !defined(KDB5_USE_LIB_TEST)
#error No database module defined
#endif

#ifdef KDB5_USE_LIB_KDB_DB2
    if (strcmp(lib_name, "kdb_db2") == 0) {
	DEF_SYMBOL(kdb_db2);
	vftabl_addr = (void *) &GET_SYMBOL(kdb_db2);
    } else
#endif
#ifdef KDB5_USE_LIB_TEST
    if (strcmp(lib_name, "test") == 0) {
	DEF_SYMBOL(test);
	vftabl_addr = (void *) &GET_SYMBOL(test);
    } else
#endif
    {
	snprintf(buf, sizeof(buf),
		 "Program not built to support %s database type\n",
		 lib_name);
	status = KRB5_KDB_DBTYPE_NOSUP;
	krb5_db_set_err(kcontext, krb5_err_have_str, status, buf);
	goto clean_n_exit;
    }

    memcpy(&(*lib)->vftabl, vftabl_addr, sizeof(kdb_vftabl));

    kdb_setup_opt_functions(*lib);

    if ((status = (*lib)->vftabl.init_library())) {
	/* ERROR. library not initialized cleanly */
	snprintf(buf, sizeof(buf),
		 "%s library initialization failed, error code %ld\n",
		 lib_name, status);
	status = KRB5_KDB_DBTYPE_INIT;
	krb5_db_set_err(kcontext, krb5_err_have_str, status, buf);
	goto clean_n_exit;
    }

  clean_n_exit:
    if (status) {
	free(*lib), *lib = NULL;
    }
    return status;
}

#else /* KDB5_STATIC_LINK*/

static char *db_dl_location[] = DEFAULT_KDB_LIB_PATH;
#define db_dl_n_locations (sizeof(db_dl_location) / sizeof(db_dl_location[0]))

static krb5_error_code
kdb_load_library(krb5_context kcontext, char *lib_name, db_library * lib)
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

    if (!strcmp(DB2_NAME, lib_name) && (kdb_db2_pol_err_loaded == 0)) {
	initialize_adb_error_table();
	kdb_db2_pol_err_loaded = 1;
    }

    *lib = calloc((size_t) 1, sizeof(**lib));
    if (*lib == NULL) {
	status = ENOMEM;
	goto clean_n_exit;
    }

    status = kdb_init_lib_lock(*lib);
    if (status) {
	goto clean_n_exit;
    }

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

    memcpy(&(*lib)->vftabl, vftabl_addrs[0], sizeof(kdb_vftabl));
    kdb_setup_opt_functions(*lib);
    
    if ((status = (*lib)->vftabl.init_library())) {
        /* ERROR. library not initialized cleanly */
        goto clean_n_exit;
    }    
    
clean_n_exit:
    if (vftabl_addrs != NULL) { krb5int_free_plugin_dir_data (vftabl_addrs); }
    /* Both of these DTRT with NULL.  */
    profile_free_list(profpath);
    free(path);
    if (status) {
        if (*lib) {
	    kdb_destroy_lib_lock(*lib);
            if (PLUGIN_DIR_OPEN((&(*lib)->dl_dir_handle))) {
                krb5int_close_plugin_dirs (&(*lib)->dl_dir_handle);
            }
	    free(*lib);
	    *lib = NULL;
	}
    }
    return status;
}

#endif /* end of _KDB5_STATIC_LINK */

static krb5_error_code
kdb_find_library(krb5_context kcontext, char *lib_name, db_library * lib)
{
    /* lock here so that no two threads try to do the same at the same time */
    krb5_error_code status = 0;
    int     locked = 0;
    db_library curr_elt, prev_elt = NULL;

    if ((status = kdb_lock_list()) != 0) {
	goto clean_n_exit;
    }
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
    if (status) {
	goto clean_n_exit;
    }

    if (prev_elt) {
	/* prev_elt points to the last element in the list */
	prev_elt->next = *lib;
	(*lib)->prev = prev_elt;
    } else {
	lib_list = *lib;
    }

  clean_n_exit:
    if (*lib) {
	(*lib)->reference_cnt++;
    }

    if (locked) {
	kdb_unlock_list();
    }

    return status;
}

static krb5_error_code
kdb_free_library(db_library lib)
{
    krb5_error_code status = 0;
    int     locked = 0;

    if ((status = kdb_lock_list()) != 0) {
	goto clean_n_exit;
    }
    locked = 1;

    lib->reference_cnt--;

    if (lib->reference_cnt == 0) {
	status = lib->vftabl.fini_library();
	if (status) {
	    goto clean_n_exit;
	}

	/* close the library */
        if (PLUGIN_DIR_OPEN((&lib->dl_dir_handle))) {
            krb5int_close_plugin_dirs (&lib->dl_dir_handle);
        }
        
	kdb_destroy_lib_lock(lib);

	if (lib->prev == NULL) {
	    /* first element in the list */
	    lib_list = lib->next;
	} else {
	    lib->prev->next = lib->next;
	}

	if (lib->next) {
	    lib->next->prev = lib->prev;
	}
	free(lib);
    }

  clean_n_exit:
    if (locked) {
	kdb_unlock_list();
    }

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
    if (status) {
	goto clean_n_exit;
    }

    dal_handle->lib_handle = lib;
    kcontext->dal_handle = dal_handle;

  clean_n_exit:
    free(library);

    if (status) {
	free(dal_handle);
	if (lib) {
	    kdb_free_library(lib);
	}
    }

    return status;
}

static krb5_error_code
kdb_free_lib_handle(krb5_context kcontext)
{
    krb5_error_code status = 0;

    status = kdb_free_library(kcontext->dal_handle->lib_handle);
    if (status) {
	goto clean_n_exit;
    }

    free(kcontext->dal_handle);
    kcontext->dal_handle = NULL;

  clean_n_exit:
    return status;
}

static void
get_errmsg (krb5_context kcontext, krb5_error_code err_code)
{
    kdb5_dal_handle *dal_handle;
    const char *e;
    if (err_code == 0)
	return;
    assert(kcontext != NULL);
    /* Must be called with dal_handle->lib_handle locked!  */
    assert(kcontext->dal_handle != NULL);
    dal_handle = kcontext->dal_handle;
    if (dal_handle->lib_handle->vftabl.errcode_2_string == NULL)
	return;
    e = dal_handle->lib_handle->vftabl.errcode_2_string(kcontext, err_code);
    assert (e != NULL);
    krb5_set_error_message(kcontext, err_code, "%s", e);
    if (dal_handle->lib_handle->vftabl.release_errcode_string)
	dal_handle->lib_handle->vftabl.release_errcode_string(kcontext, e);
}

/*
 *      External functions... DAL API
 */
krb5_error_code
krb5_db_open(krb5_context kcontext, char **db_args, int mode)
{
    krb5_error_code status = 0;
    char   *section = NULL;
    kdb5_dal_handle *dal_handle;

    section = kdb_get_conf_section(kcontext);
    if (section == NULL) {
	status = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (kcontext, status,
		"unable to determine configuration section for realm %s\n",
		kcontext->default_realm ? kcontext->default_realm : "[UNSET]");
	goto clean_n_exit;
    }

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.init_module(kcontext, section, db_args,
						   mode);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    if (section)
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
    krb5_error_code status = 0;
    char   *section = NULL;
    kdb5_dal_handle *dal_handle;

    section = kdb_get_conf_section(kcontext);
    if (section == NULL) {
	status = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (kcontext, status,
		"unable to determine configuration section for realm %s\n",
		kcontext->default_realm);
	goto clean_n_exit;
    }

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_create(kcontext, section, db_args);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    if (section)
	free(section);
    return status;
}

krb5_error_code
krb5_db_fini(krb5_context kcontext)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	/* module not loaded. So nothing to be done */
	goto clean_n_exit;
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.fini_module(kcontext);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

    if (status) {
	goto clean_n_exit;
    }

    status = kdb_free_lib_handle(kcontext);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_destroy(krb5_context kcontext, char **db_args)
{
    krb5_error_code status = 0;
    char   *section = NULL;
    kdb5_dal_handle *dal_handle;

    section = kdb_get_conf_section(kcontext);
    if (section == NULL) {
	status = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (kcontext, status,
		"unable to determine configuration section for realm %s\n",
		kcontext->default_realm);
	goto clean_n_exit;
    }

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_destroy(kcontext, section, db_args);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    if (section)
	free(section);
    return status;
}

krb5_error_code
krb5_db_get_age(krb5_context kcontext, char *db_name, time_t * t)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_get_age(kcontext, db_name, t);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_set_option(krb5_context kcontext, int option, void *value)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_set_option(kcontext, option, value);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_lock(krb5_context kcontext, int lock_mode)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    /* acquire an exclusive lock, ensures no other thread uses this context */
    status = kdb_lock_lib_lock(dal_handle->lib_handle, TRUE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_lock(kcontext, lock_mode);
    get_errmsg(kcontext, status);

    /* exclusive lock is still held, so no other thread could use this context */
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_unlock(krb5_context kcontext)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    /* normal lock acquired and exclusive lock released */
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_unlock(kcontext);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, TRUE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_get_principal(krb5_context kcontext,
		      krb5_const_principal search_for,
		      krb5_db_entry * entries,
		      int *nentries, krb5_boolean * more)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_get_principal(kcontext, search_for, 0,
							entries, nentries,
							more);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_get_principal_ext(krb5_context kcontext,
			  krb5_const_principal search_for,
			  unsigned int flags,
			  krb5_db_entry * entries,
			  int *nentries, krb5_boolean * more)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_get_principal(kcontext, search_for,
							flags,
							entries, nentries,
							more);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_free_principal(krb5_context kcontext, krb5_db_entry * entry, int count)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_free_principal(kcontext, entry,
							 count);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
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
extract_db_args_from_tl_data(krb5_context kcontext,
			     krb5_tl_data **start, krb5_int16 *count,
			     char ***db_argsp)
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
	    t = realloc(db_args, sizeof(char *) * (db_args_size + 1));	/* 1 for NULL */
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
krb5int_put_principal_no_log(krb5_context kcontext,
			     krb5_db_entry *entries, int *nentries)
{
    kdb5_dal_handle *dal_handle;
    krb5_error_code status;
    char **db_args;

    status = extract_db_args_from_tl_data(kcontext, &entries->tl_data,
					  &entries->n_tl_data,
					  &db_args);
    if (status)
	return status;
    assert (kcontext->dal_handle != NULL); /* XXX */
    dal_handle = kcontext->dal_handle;
    /* XXX Locking?  */
    status = dal_handle->lib_handle->vftabl.db_put_principal(kcontext, entries,
							     nentries,
							     db_args);
    get_errmsg(kcontext, status);
    free_db_args(kcontext, db_args);
    return status;
}

krb5_error_code
krb5_db_put_principal(krb5_context kcontext,
		      krb5_db_entry * entries, int *nentries)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;
    char  **db_args = NULL;
    kdb_incr_update_t *upd, *fupd = 0;
    char *princ_name = NULL;
    kdb_log_context *log_ctx;
    int i;
    int ulog_locked = 0;

    log_ctx = kcontext->kdblog_context;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    status = extract_db_args_from_tl_data(kcontext, &entries->tl_data,
					  &entries->n_tl_data,
					  &db_args);
    if (status)
	goto clean_n_exit;

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    /*
     * We need the lock since ulog_conv_2logentry() does a get
     */
    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER)) {
	if (!(upd = (kdb_incr_update_t *)
	  malloc(sizeof (kdb_incr_update_t)* *nentries))) {
	    status = errno;
	    goto err_lock;
	}
	fupd = upd;

	(void) memset(upd, 0, sizeof(kdb_incr_update_t)* *nentries);

        if ((status = ulog_conv_2logentry(kcontext, entries, upd, *nentries))) {
	    goto err_lock;
	}
    }

    status = ulog_lock(kcontext, KRB5_LOCKMODE_EXCLUSIVE);
    if (status != 0)
	goto err_lock;
    ulog_locked = 1;

    for (i = 0; i < *nentries; i++) {
	/*
	 * We'll be sharing the same locks as db for logging
	 */
        if (fupd) {
		if ((status = krb5_unparse_name(kcontext, entries->princ,
		    &princ_name)))
			goto err_lock;

		upd->kdb_princ_name.utf8str_t_val = princ_name;
		upd->kdb_princ_name.utf8str_t_len = strlen(princ_name);

                if ((status = ulog_add_update(kcontext, upd)) != 0)
			goto err_lock;
		upd++;
        }
    }

    status = dal_handle->lib_handle->vftabl.db_put_principal(kcontext, entries,
							     nentries,
							     db_args);
    get_errmsg(kcontext, status);
    if (status == 0 && fupd) {
	upd = fupd;
	for (i = 0; i < *nentries; i++) {
	    (void) ulog_finish_update(kcontext, upd);
	    upd++;
	}
    }
err_lock:
    if (ulog_locked)
	ulog_lock(kcontext, KRB5_LOCKMODE_UNLOCK);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    free_db_args(kcontext, db_args);

    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER))
	ulog_free_entries(fupd, *nentries);

    return status;
}

krb5_error_code
krb5int_delete_principal_no_log(krb5_context kcontext,
				krb5_principal search_for,
				int *nentries)
{
    kdb5_dal_handle *dal_handle;
    krb5_error_code status;

    assert (kcontext->dal_handle != NULL); /* XXX */

    dal_handle = kcontext->dal_handle;
    /* XXX Locking?  */
    status = dal_handle->lib_handle->vftabl.db_delete_principal(kcontext,
								 search_for,
								 nentries);
    get_errmsg(kcontext, status);
    return status;
}

krb5_error_code
krb5_db_delete_principal(krb5_context kcontext,
			 krb5_principal search_for, int *nentries)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;
    kdb_incr_update_t upd;
    char *princ_name = NULL;
    kdb_log_context *log_ctx;

    log_ctx = kcontext->kdblog_context;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = ulog_lock(kcontext, KRB5_LOCKMODE_EXCLUSIVE);
    if (status) {
	kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);
	return status;
    }

    /*
     * We'll be sharing the same locks as db for logging
     */
    if (log_ctx && (log_ctx->iproprole == IPROP_MASTER)) {
	if ((status = krb5_unparse_name(kcontext, search_for, &princ_name))) {
	    ulog_lock(kcontext, KRB5_LOCKMODE_UNLOCK);
	    (void) kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);
	    return status;
	}

	(void) memset(&upd, 0, sizeof (kdb_incr_update_t));

	upd.kdb_princ_name.utf8str_t_val = princ_name;
	upd.kdb_princ_name.utf8str_t_len = strlen(princ_name);

	if ((status = ulog_delete_update(kcontext, &upd)) != 0) {
		ulog_lock(kcontext, KRB5_LOCKMODE_UNLOCK);
		free(princ_name);
		(void) kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);
		return status;
	}

	free(princ_name);
    }

    status = dal_handle->lib_handle->vftabl.db_delete_principal(kcontext,
								 search_for,
								 nentries);
    get_errmsg(kcontext, status);

    /*
     * We need to commit our update upon success
     */
    if (!status)
	if (log_ctx && (log_ctx->iproprole == IPROP_MASTER))
		(void) ulog_finish_update(kcontext, &upd);

    ulog_lock(kcontext, KRB5_LOCKMODE_UNLOCK);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_iterate(krb5_context kcontext,
		char *match_entry,
		int (*func) (krb5_pointer, krb5_db_entry *),
		krb5_pointer func_arg)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_iterate(kcontext,
						       match_entry,
						       func, func_arg);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_supported_realms(krb5_context kcontext, char **realms)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_supported_realms(kcontext, realms);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_free_supported_realms(krb5_context kcontext, char **realms)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_free_supported_realms(kcontext,
								realms);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_set_master_key_ext(krb5_context kcontext,
			   char *pwd, krb5_keyblock * key)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.set_master_key(kcontext, pwd, key);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_set_mkey(krb5_context context, krb5_keyblock * key)
{
    return krb5_db_set_master_key_ext(context, NULL, key);
}

krb5_error_code
krb5_db_set_mkey_list(krb5_context kcontext,
                      krb5_keylist_node * keylist)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
        status = krb5_db_setup_lib_handle(kcontext);
        if (status) {
            goto clean_n_exit;
        }
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
        goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.set_master_key_list(kcontext, keylist);
    get_errmsg(kcontext, status);

    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_get_mkey(krb5_context kcontext, krb5_keyblock ** key)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    /* Let's use temp key and copy it later to avoid memory problems
       when freed by the caller.  */
    status = dal_handle->lib_handle->vftabl.get_master_key(kcontext, key);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_get_mkey_list(krb5_context kcontext, krb5_keylist_node ** keylist)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
        status = krb5_db_setup_lib_handle(kcontext);
        if (status) {
            goto clean_n_exit;
        }
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
        goto clean_n_exit;
    }

    /* Let's use temp key and copy it later to avoid memory problems
       when freed by the caller.  */
    status = dal_handle->lib_handle->vftabl.get_master_key_list(kcontext, keylist);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_fetch_mkey_list(krb5_context     context,
                   krb5_principal        mname,
                   const krb5_keyblock * mkey,
                   krb5_kvno             mkvno,
                   krb5_keylist_node  **mkey_list)
{
    kdb5_dal_handle *dal_handle;
    krb5_error_code status = 0;

    if (context->dal_handle == NULL) {
        status = krb5_db_setup_lib_handle(context);
        if (status) {
            goto clean_n_exit;
        }
    }

    dal_handle = context->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
        goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.fetch_master_key_list(context,
        mname,
        mkey,
        mkvno,
        mkey_list);
    get_errmsg(context, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

    if (status) {
        goto clean_n_exit;
    }

clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_free_mkey_list(krb5_context    context,
                       krb5_keylist_node  *mkey_list)
{
    krb5_keylist_node *cur, *prev;

    for (cur = mkey_list; cur != NULL;) {
        prev = cur;
        cur = cur->next;
        krb5_free_keyblock_contents(context, &prev->keyblock);
        krb5_xfree(prev);
    }

    return 0;
}

krb5_error_code
krb5_db_store_master_key(krb5_context kcontext,
			 char *keyfile,
			 krb5_principal mname,
			 krb5_kvno kvno,
			 krb5_keyblock * key, char *master_pwd)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.store_master_key(kcontext,
							     keyfile,
							     mname,
							     kvno,
							     key, master_pwd);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_store_master_key_list(krb5_context kcontext,
			      char *keyfile,
			      krb5_principal mname,
			      krb5_keylist_node *keylist,
			      char *master_pwd)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.store_master_key_list(kcontext,
								  keyfile,
								  mname,
								  keylist,
								  master_pwd);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

char   *krb5_mkey_pwd_prompt1 = KRB5_KDC_MKEY_1;
char   *krb5_mkey_pwd_prompt2 = KRB5_KDC_MKEY_2;

krb5_error_code
krb5_db_fetch_mkey(krb5_context    context,
                   krb5_principal  mname,
                   krb5_enctype    etype,
                   krb5_boolean    fromkeyboard,
                   krb5_boolean    twice,
                   char          * db_args,
                   krb5_kvno     * kvno,
                   krb5_data     * salt,
                   krb5_keyblock * key)
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
            int nentries = 1;
            krb5_boolean more;
            krb5_error_code rc;
            krb5_db_entry master_entry;

            rc = krb5_db_get_principal(context, mname,
                &master_entry, &nentries, &more);

            if (rc == 0 && nentries == 1 && more == FALSE) 
                *kvno = (krb5_kvno) master_entry.key_data->key_data_kvno;
            else
                *kvno = 1;

            if (rc == 0 && nentries)
                krb5_db_free_principal(context, &master_entry, nentries);
        }

	if (!salt)
	    free(scratch.data);
	zap(password, sizeof(password));	/* erase it */

    } else {
	kdb5_dal_handle *dal_handle;

	if (context->dal_handle == NULL) {
	    retval = krb5_db_setup_lib_handle(context);
	    if (retval) {
		goto clean_n_exit;
	    }
	}

	dal_handle = context->dal_handle;
	retval = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
	if (retval) {
	    goto clean_n_exit;
	}

        /* get the enctype from the stash */
	tmp_key.enctype = ENCTYPE_UNKNOWN;

	retval = dal_handle->lib_handle->vftabl.fetch_master_key(context,
								 mname,
								 &tmp_key,
								 kvno,
								 db_args);
	get_errmsg(context, retval);
	kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

	if (retval) {
	    goto clean_n_exit;
	}

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
krb5_db_verify_master_key(krb5_context     kcontext,
                          krb5_principal   mprinc,
                          krb5_kvno        kvno,
                          krb5_keyblock  * mkey)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.verify_master_key(kcontext,
                                                              mprinc,
                                                              kvno,
                                                              mkey);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_dbe_fetch_act_key_list(krb5_context         context,
                            krb5_principal       princ,
                            krb5_actkvno_node  **act_key_list)
{
    krb5_error_code retval = 0;
    krb5_db_entry entry;
    int nprinc;
    krb5_boolean more;

    if (act_key_list == NULL)
        return (EINVAL);

    nprinc = 1;
    if ((retval = krb5_db_get_principal(context, princ, &entry,
                                        &nprinc, &more))) {
        return (retval);
    }

    if (nprinc != 1) {
        if (nprinc) {
            krb5_db_free_principal(context, &entry, nprinc);
            return (KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
        } else {
            return(KRB5_KDB_NOMASTERKEY);
        }
    } else if (more) {
        krb5_db_free_principal(context, &entry, nprinc);
        return (KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    }

    retval = krb5_dbe_lookup_actkvno(context, &entry, act_key_list);

    if (*act_key_list == NULL) {
        krb5_actkvno_node *tmp_actkvno;
        /*
         * for mkey princ entries without KRB5_TL_ACTKVNO data provide a default
         */

        tmp_actkvno = (krb5_actkvno_node *) malloc(sizeof(krb5_actkvno_node));
        if (tmp_actkvno == NULL)
            return (ENOMEM);

        memset(tmp_actkvno, 0, sizeof(krb5_actkvno_node));
        tmp_actkvno->act_time = 0; /* earliest time possible */
        /* use most current key */
        tmp_actkvno->act_kvno = entry.key_data[0].key_data_kvno;
        *act_key_list = tmp_actkvno;
    }

    krb5_db_free_principal(context, &entry, nprinc);
    return retval;
}

/*
 * Locates the "active" mkey used when encrypting a princ's keys.  Note, the
 * caller must NOT free the output act_mkey.
 */

krb5_error_code
krb5_dbe_find_act_mkey(krb5_context         context,
                       krb5_keylist_node  *mkey_list,
                       krb5_actkvno_node   *act_mkey_list,
                       krb5_kvno           *act_kvno,
                       krb5_keyblock      **act_mkey)
{
    krb5_kvno tmp_act_kvno;
    krb5_error_code retval;
    krb5_keylist_node *cur_keyblock = mkey_list;
    krb5_actkvno_node   *prev_actkvno, *cur_actkvno;
    krb5_timestamp	now;
    krb5_boolean	found = FALSE;

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
        if (prev_actkvno->act_time <= now) {
            tmp_act_kvno = prev_actkvno->act_kvno;
        } else {
            /* XXX this shouldn't happen */
            return (KRB5_KDB_NOACTMASTERKEY);
        }
    }

    while (cur_keyblock && cur_keyblock->kvno != tmp_act_kvno)
        cur_keyblock = cur_keyblock->next;

    if (cur_keyblock) {
        *act_mkey = &cur_keyblock->keyblock;
        if (act_kvno != NULL)
            *act_kvno = tmp_act_kvno;
        return (0);
    } else {
        return (KRB5_KDB_NO_MATCHING_KEY);
    }
}

/*
 * Locates the mkey used to protect a princ's keys.  Note, the caller must not
 * free the output key.
 */
krb5_error_code
krb5_dbe_find_mkey(krb5_context         context,
                   krb5_keylist_node  * mkey_list,
                   krb5_db_entry      * entry,
                   krb5_keyblock     ** mkey)
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
        return (KRB5_KDB_NO_MATCHING_KEY);
    }
}

void   *
krb5_db_alloc(krb5_context kcontext, void *ptr, size_t size)
{
    krb5_error_code status;
    kdb5_dal_handle *dal_handle;
    void   *new_ptr = NULL;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;

    new_ptr = dal_handle->lib_handle->vftabl.db_alloc(kcontext, ptr, size);

  clean_n_exit:
    return new_ptr;
}

void
krb5_db_free(krb5_context kcontext, void *ptr)
{
    krb5_error_code status;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;

    dal_handle->lib_handle->vftabl.db_free(kcontext, ptr);

  clean_n_exit:
    return;
}

/* has to be modified */

krb5_error_code
krb5_dbe_find_enctype(krb5_context kcontext,
		      krb5_db_entry * dbentp,
		      krb5_int32 ktype,
		      krb5_int32 stype,
		      krb5_int32 kvno, krb5_key_data ** kdatap)
{
    krb5_int32 start = 0;
    return krb5_dbe_search_enctype(kcontext, dbentp, &start, ktype, stype,
				   kvno, kdatap);
}

krb5_error_code
krb5_dbe_search_enctype(krb5_context kcontext,
			krb5_db_entry * dbentp,
			krb5_int32 * start,
			krb5_int32 ktype,
			krb5_int32 stype,
			krb5_int32 kvno, krb5_key_data ** kdatap)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.dbe_search_enctype(kcontext,
							       dbentp,
							       start,
							       ktype,
							       stype,
							       kvno, kdatap);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

#define	REALM_SEP_STRING	"@"

krb5_error_code
krb5_db_setup_mkey_name(krb5_context context,
			const char *keyname,
			const char *realm,
			char **fullname, krb5_principal * principal)
{
    krb5_error_code retval;
    char   *fname;

    if (!keyname)
	keyname = KRB5_KDB_M_NAME;	/* XXX external? */

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
krb5_dbe_lookup_last_pwd_change(context, entry, stamp)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_timestamp *stamp;
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
krb5_dbe_lookup_tl_data(context, entry, ret_tl_data)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_tl_data *ret_tl_data;
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
krb5_dbe_create_key_data(context, entry)
    krb5_context context;
    krb5_db_entry *entry;
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
krb5_dbe_update_mod_princ_data(context, entry, mod_date, mod_princ)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_timestamp mod_date;
    krb5_const_principal mod_princ;
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
krb5_dbe_lookup_mod_princ_data(context, entry, mod_time, mod_princ)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_timestamp *mod_time;
    krb5_principal *mod_princ;
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
krb5_dbe_lookup_mkvno(krb5_context	context,
		      krb5_db_entry	*entry,
		      krb5_kvno		*mkvno)
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
krb5_dbe_get_mkvno(krb5_context        context,
                   krb5_db_entry     * entry,
                   krb5_keylist_node * mkey_list,
                   krb5_kvno         * mkvno)
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
krb5_dbe_update_mkvno(krb5_context    context,
                      krb5_db_entry * entry,
                      krb5_kvno       mkvno)
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
krb5_dbe_lookup_mkey_aux(krb5_context          context,
                         krb5_db_entry       * entry,
                         krb5_mkey_aux_node ** mkey_aux_data_list)
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
krb5_dbe_update_mkey_aux(krb5_context         context,
                         krb5_db_entry      * entry,
                         krb5_mkey_aux_node * mkey_aux_data_list)
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
    if (tl_data.tl_data_contents == NULL) {
        return (ENOMEM);
    }

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
krb5_dbe_lookup_actkvno(krb5_context context,
                        krb5_db_entry *entry,
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
krb5_dbe_update_actkvno(krb5_context context,
                        krb5_db_entry *entry,
                        const krb5_actkvno_node *actkvno_list)
{
    krb5_error_code retval = 0;
    krb5_int16 version, tmp_kvno;
    krb5_tl_data new_tl_data;
    unsigned char *nextloc;
    const krb5_actkvno_node *cur_actkvno;
    krb5_octet *tmpptr;

    if (actkvno_list == NULL) {
        return (EINVAL);
    }

    memset(&new_tl_data, 0, sizeof(new_tl_data));
    /* allocate initial KRB5_TL_ACTKVNO tl_data entry */
    new_tl_data.tl_data_length = sizeof(version);
    new_tl_data.tl_data_contents = (krb5_octet *) malloc(new_tl_data.tl_data_length);
    if (new_tl_data.tl_data_contents == NULL)
        return (ENOMEM);

    /* add the current version # for the data format used for KRB5_TL_ACTKVNO */
    version = KRB5_TL_ACTKVNO_VER;
    krb5_kdb_encode_int16(version, (unsigned char *) new_tl_data.tl_data_contents);

    for (cur_actkvno = actkvno_list; cur_actkvno != NULL;
         cur_actkvno = cur_actkvno->next) {

        new_tl_data.tl_data_length += ACTKVNO_TUPLE_SIZE;
        tmpptr = realloc(new_tl_data.tl_data_contents, new_tl_data.tl_data_length);
        if (tmpptr == NULL) {
            free(new_tl_data.tl_data_contents);
            return (ENOMEM);
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
krb5_dbe_update_last_pwd_change(context, entry, stamp)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_timestamp stamp;
{
    krb5_tl_data tl_data;
    krb5_octet buf[4];		/* this is the encoded size of an int32 */

    tl_data.tl_data_type = KRB5_TL_LAST_PWD_CHANGE;
    tl_data.tl_data_length = sizeof(buf);
    krb5_kdb_encode_int32((krb5_int32) stamp, buf);
    tl_data.tl_data_contents = buf;

    return (krb5_dbe_update_tl_data(context, entry, &tl_data));
}

krb5_error_code
krb5_dbe_delete_tl_data(krb5_context context,
                        krb5_db_entry *entry,
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
krb5_dbe_update_tl_data(context, entry, new_tl_data)
    krb5_context context;
    krb5_db_entry *entry;
    krb5_tl_data *new_tl_data;
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

    if (new_tl_data->tl_data_type != KRB5_TL_DB_ARGS) {	/* db_args can be multiple */
	for (tl_data = entry->tl_data; tl_data;
	     tl_data = tl_data->tl_data_next)
	    if (tl_data->tl_data_type == new_tl_data->tl_data_type)
		break;
    }

    /* If necessary, chain a new record in the beginning and point at it.  */

    if (!tl_data) {
	if ((tl_data =
	     (krb5_tl_data *) krb5_db_alloc(context, NULL,
					    sizeof(krb5_tl_data)))
	    == NULL) {
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
krb5_dbe_cpw(krb5_context kcontext,
	     krb5_keyblock * master_key,
	     krb5_key_salt_tuple * ks_tuple,
	     int ks_tuple_count,
	     char *passwd,
	     int new_kvno, krb5_boolean keepold, krb5_db_entry * db_entry)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_change_pwd(kcontext,
							  master_key,
							  ks_tuple,
							  ks_tuple_count,
							  passwd,
							  new_kvno,
							  keepold, db_entry);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

/* policy management functions */
krb5_error_code
krb5_db_create_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_create_policy(kcontext, policy);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_get_policy(krb5_context kcontext, char *name,
		   osa_policy_ent_t * policy, int *cnt)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_get_policy(kcontext, name, policy,
						     cnt);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_put_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_put_policy(kcontext, policy);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_iter_policy(krb5_context kcontext, char *match_entry,
		    osa_adb_iter_policy_func func, void *data)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_iter_policy(kcontext, match_entry,
						      func, data);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_delete_policy(krb5_context kcontext, char *policy)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status = dal_handle->lib_handle->vftabl.db_delete_policy(kcontext, policy);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

void
krb5_db_free_policy(krb5_context kcontext, osa_policy_ent_t policy)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    dal_handle->lib_handle->vftabl.db_free_policy(kcontext, policy);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return;
}

krb5_error_code
krb5_db_promote(krb5_context kcontext, char **db_args)
{
    krb5_error_code status = 0;
    char   *section = NULL;
    kdb5_dal_handle *dal_handle;

    section = kdb_get_conf_section(kcontext);
    if (section == NULL) {
	status = KRB5_KDB_SERVER_INTERNAL_ERR;
	krb5_set_error_message (kcontext, status,
		"unable to determine configuration section for realm %s\n",
		kcontext->default_realm);
	goto clean_n_exit;
    }

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.promote_db(kcontext, section, db_args);
    get_errmsg(kcontext, status);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    if (section)
	free(section);
    return status;
}

krb5_error_code
krb5_dbekd_decrypt_key_data( krb5_context 	  kcontext,
			     const krb5_keyblock	* mkey,
			     const krb5_key_data	* key_data,
			     krb5_keyblock 	* dbkey,
			     krb5_keysalt 	* keysalt)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.dbekd_decrypt_key_data(kcontext,
	    mkey, key_data, dbkey, keysalt);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_dbekd_encrypt_key_data( krb5_context 		  kcontext,
			     const krb5_keyblock	* mkey,
			     const krb5_keyblock 	* dbkey,
			     const krb5_keysalt		* keysalt,
			     int			  keyver,
			     krb5_key_data	        * key_data)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.dbekd_encrypt_key_data(kcontext,
	    mkey, dbkey, keysalt, keyver, key_data);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

krb5_error_code
krb5_db_get_context(krb5_context context, void **db_context)
{
    *db_context = KRB5_DB_GET_DB_CONTEXT(context);
    if (*db_context == NULL) {
	return KRB5_KDB_DBNOTINITED;
    }

    return 0;
}

krb5_error_code
krb5_db_set_context(krb5_context context, void *db_context)
{
    KRB5_DB_GET_DB_CONTEXT(context) = db_context;

    return 0;
}

krb5_error_code
krb5_db_invoke(krb5_context kcontext,
	       unsigned int method,
	       const krb5_data *req,
	       krb5_data *rep)
{
    krb5_error_code status = 0;
    kdb5_dal_handle *dal_handle;

    if (kcontext->dal_handle == NULL) {
	status = krb5_db_setup_lib_handle(kcontext);
	if (status) {
	    goto clean_n_exit;
	}
    }

    dal_handle = kcontext->dal_handle;
    if (dal_handle->lib_handle->vftabl.db_invoke == NULL) {
	status = KRB5_KDB_DBTYPE_NOSUP;
	goto clean_n_exit;
    }

    status = kdb_lock_lib_lock(dal_handle->lib_handle, FALSE);
    if (status) {
	goto clean_n_exit;
    }

    status =
	dal_handle->lib_handle->vftabl.db_invoke(kcontext,
						 method,
						 req,
						 rep);
    kdb_unlock_lib_lock(dal_handle->lib_handle, FALSE);

  clean_n_exit:
    return status;
}

