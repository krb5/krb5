/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    "k5-int.h"
#include    <kdb.h>
#include    <ctype.h>
#include    <pwd.h>
#include    "server_internal.h"

kadm5_ret_t
adb_policy_init(kadm5_server_handle_t handle)
{
    /* now policy is initialized as part of database. No seperate call needed */
    if( krb5_db_inited( handle->context ) )
        return KADM5_OK;

    return krb5_db_open( handle->context, NULL,
                         KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_ADMIN );
}

kadm5_ret_t
adb_policy_close(kadm5_server_handle_t handle)
{
    /* will be taken care by database close */
    return KADM5_OK;
}

kadm5_ret_t
init_pwqual(kadm5_server_handle_t handle)
{
    krb5_error_code ret;
    pwqual_handle *list, *h;
    const char *dict_file = NULL;

    ret = k5_plugin_register(handle->context, PLUGIN_INTERFACE_PWQUAL,
                             "dict", pwqual_dict_init);
    if (ret != 0)
        return ret;

    ret = k5_plugin_register(handle->context, PLUGIN_INTERFACE_PWQUAL,
                             "policy", pwqual_policy_init);
    if (ret != 0)
        return ret;

    ret = k5_pwqual_load(handle->context, &list);
    if (ret != 0)
        return ret;

    if (handle->params.mask & KADM5_CONFIG_DICT_FILE)
        dict_file = handle->params.dict_file;

    for (h = list; *h != NULL; h++) {
        ret = k5_pwqual_open(handle->context, *h, dict_file);
        if (ret != 0) {
            /* Close any previously opened modules and error out. */
            for (; h > list; h--)
                k5_pwqual_close(handle->context, *(h - 1));
            k5_pwqual_free_handles(handle->context, list);
            return ret;
        }
    }

    handle->qual_handles = list;
    return 0;
}

/* Check a password against all available password quality plugin modules. */
kadm5_ret_t
passwd_check(kadm5_server_handle_t handle, const char *password,
             kadm5_policy_ent_t policy, krb5_principal princ)
{
    krb5_error_code ret;
    pwqual_handle *h;

    for (h = handle->qual_handles; *h != NULL; h++) {
        ret = k5_pwqual_check(handle->context, *h, password, policy, princ);
        if (ret != 0)
            return ret;
    }
    return 0;
}

void
destroy_pwqual(kadm5_server_handle_t handle)
{
    pwqual_handle *h;

    for (h = handle->qual_handles; *h != NULL; h++)
        k5_pwqual_close(handle->context, *h);
    k5_pwqual_free_handles(handle->context, handle->qual_handles);
    handle->qual_handles = NULL;
}
