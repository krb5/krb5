/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 *
 */

#include    <gssrpc/rpc.h>
#include    <kadm5/admin.h>
#include    <kadm5/kadm_rpc.h>
#include    "client_internal.h"
#include    <string.h>

kadm5_ret_t kadm5_get_privs(void *server_handle, long *privs)
{
    getprivs_ret r;
    enum clnt_stat s;
    kadm5_server_handle_t handle = server_handle;

    memset(&r, 0, sizeof(getprivs_ret));

    s = get_privs_2(&handle->api_version, &r, handle->clnt);
    if (s != RPC_SUCCESS)
        return KADM5_RPC_ERROR;
    else if (r.code == KADM5_OK)
        *privs = r.privs;

    return r.code;
}
