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

/* for strcasecmp */
#include    <string.h>

#include    "server_internal.h"

#include <plugin_manager.h>
#include <plugin_pwd_qlty.h>


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

/* some of this is stolen from gatekeeper ... */
/* passwd_check -  returns KADM5_OK if password passes the validation.*/
kadm5_ret_t
passwd_check(kadm5_server_handle_t srv_handle,
             char *password, int use_policy, kadm5_policy_ent_t pol,
             krb5_principal principal)
{

    int ret = 0;

    plhandle plugin_handle = plugin_manager_get_service(srv_handle->context->pl_handle, "plugin_pwd_qlty");

    ret = plugin_pwd_qlty_check(plugin_handle, srv_handle, password, use_policy, pol, principal);

    return ret;
}
