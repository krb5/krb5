/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <netdb.h>
#include "autoconf.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <string.h>
#include <com_err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fake-addrinfo.h>
#include <k5-int.h> /* for KRB5_ADM_DEFAULT_PORT */
#include <krb5.h>
#ifdef __STDC__
#include <stdlib.h>
#endif

#include <kadm5/admin.h>
#include <kadm5/kadm_rpc.h>
#include "client_internal.h"
#include <iprop_hdr.h>
#include "iprop.h"

#include <gssrpc/rpc.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <gssrpc/auth_gssapi.h>

#define ADM_CCACHE  "/tmp/ovsec_adm.XXXXXX"

enum init_type { INIT_PASS, INIT_SKEY, INIT_CREDS, INIT_ANONYMOUS };

static kadm5_ret_t
init_any(krb5_context context, char *client_name, enum init_type init_type,
         char *pass, krb5_ccache ccache_in, char *service_name,
         kadm5_config_params *params, krb5_ui_4 struct_version,
         krb5_ui_4 api_version, char **db_args, void **server_handle);

static kadm5_ret_t
get_init_creds(kadm5_server_handle_t handle, char *client_name,
               enum init_type init_type, char *pass, krb5_ccache ccache_in,
               char *svcname_in, char *realm, char *full_svcname,
               unsigned int full_svcname_len);

static kadm5_ret_t
gic_iter(kadm5_server_handle_t handle, enum init_type init_type,
         krb5_ccache ccache, krb5_principal client, char *pass,
         char *svcname, char *realm, char *full_svcname,
         unsigned int full_svcname_len);

static kadm5_ret_t
connect_to_server(const char *hostname, int port, int *fd);

static kadm5_ret_t
setup_gss(kadm5_server_handle_t handle, kadm5_config_params *params_in,
          char *client_name, char *full_svcname);

static void
rpc_auth(kadm5_server_handle_t handle, kadm5_config_params *params_in,
         gss_cred_id_t gss_client_creds, gss_name_t gss_target);

kadm5_ret_t
kadm5_init_with_creds(krb5_context context, char *client_name,
                      krb5_ccache ccache, char *service_name,
                      kadm5_config_params *params, krb5_ui_4 struct_version,
                      krb5_ui_4 api_version, char **db_args,
                      void **server_handle)
{
    return init_any(context, client_name, INIT_CREDS, NULL, ccache,
                    service_name, params, struct_version, api_version, db_args,
                    server_handle);
}

kadm5_ret_t
kadm5_init_with_password(krb5_context context, char *client_name,
                         char *pass, char *service_name,
                         kadm5_config_params *params, krb5_ui_4 struct_version,
                         krb5_ui_4 api_version, char **db_args,
                         void **server_handle)
{
    return init_any(context, client_name, INIT_PASS, pass, NULL, service_name,
                    params, struct_version, api_version, db_args,
                    server_handle);
}

kadm5_ret_t
kadm5_init_anonymous(krb5_context context, char *client_name,
                     char *service_name, kadm5_config_params *params,
                     krb5_ui_4 struct_version, krb5_ui_4 api_version,
                     char **db_args, void **server_handle)
{
    return init_any(context, client_name, INIT_ANONYMOUS, NULL, NULL,
                    service_name, params, struct_version, api_version,
                    db_args, server_handle);
}

kadm5_ret_t
kadm5_init(krb5_context context, char *client_name, char *pass,
           char *service_name, kadm5_config_params *params,
           krb5_ui_4 struct_version, krb5_ui_4 api_version, char **db_args,
           void **server_handle)
{
    return init_any(context, client_name, INIT_PASS, pass, NULL, service_name,
                    params, struct_version, api_version, db_args,
                    server_handle);
}

kadm5_ret_t
kadm5_init_with_skey(krb5_context context, char *client_name,
                     char *keytab, char *service_name,
                     kadm5_config_params *params, krb5_ui_4 struct_version,
                     krb5_ui_4 api_version, char **db_args,
                     void **server_handle)
{
    return init_any(context, client_name, INIT_SKEY, keytab, NULL,
                    service_name, params, struct_version, api_version, db_args,
                    server_handle);
}

static kadm5_ret_t
init_any(krb5_context context, char *client_name, enum init_type init_type,
         char *pass, krb5_ccache ccache_in, char *service_name,
         kadm5_config_params *params_in, krb5_ui_4 struct_version,
         krb5_ui_4 api_version, char **db_args, void **server_handle)
{
    int fd = -1;

    krb5_boolean iprop_enable;
    int port;
    rpcprog_t rpc_prog;
    rpcvers_t rpc_vers;
    char full_svcname[BUFSIZ];
    char *realm;
    krb5_ccache ccache;

    kadm5_server_handle_t handle;
    kadm5_config_params params_local;

    int code = 0;
    generic_ret *r;

    initialize_ovk_error_table();
/*      initialize_adb_error_table(); */
    initialize_ovku_error_table();

    if (! server_handle) {
        return EINVAL;
    }

    if (! (handle = malloc(sizeof(*handle)))) {
        return ENOMEM;
    }
    memset(handle, 0, sizeof(*handle));
    if (! (handle->lhandle = malloc(sizeof(*handle)))) {
        free(handle);
        return ENOMEM;
    }

    handle->magic_number = KADM5_SERVER_HANDLE_MAGIC;
    handle->struct_version = struct_version;
    handle->api_version = api_version;
    handle->clnt = 0;
    handle->client_socket = -1;
    handle->cache_name = 0;
    handle->destroy_cache = 0;
    handle->context = 0;
    *handle->lhandle = *handle;
    handle->lhandle->api_version = KADM5_API_VERSION_4;
    handle->lhandle->struct_version = KADM5_STRUCT_VERSION;
    handle->lhandle->lhandle = handle->lhandle;

    handle->context = context;

    if(client_name == NULL) {
        free(handle);
        return EINVAL;
    }

    /*
     * Verify the version numbers before proceeding; we can't use
     * CHECK_HANDLE because not all fields are set yet.
     */
    GENERIC_CHECK_HANDLE(handle, KADM5_OLD_LIB_API_VERSION,
                         KADM5_NEW_LIB_API_VERSION);

    /*
     * Acquire relevant profile entries.  In version 2, merge values
     * in params_in with values from profile, based on
     * params_in->mask.
     *
     * In version 1, we've given a realm (which may be NULL) instead
     * of params_in.  So use that realm, make params_in contain an
     * empty mask, and behave like version 2.
     */
    memset(&params_local, 0, sizeof(params_local));
    if (params_in && (params_in->mask & KADM5_CONFIG_REALM))
        realm = params_in->realm;
    else
        realm = NULL;

#if 0 /* Since KDC config params can now be put in krb5.conf, these
         could show up even when you're just using the remote kadmin
         client.  */
#define ILLEGAL_PARAMS (KADM5_CONFIG_DBNAME | KADM5_CONFIG_ADBNAME |    \
                        KADM5_CONFIG_ADB_LOCKFILE |                     \
                        KADM5_CONFIG_ACL_FILE | KADM5_CONFIG_DICT_FILE  \
                        | KADM5_CONFIG_STASH_FILE |                     \
                        KADM5_CONFIG_MKEY_NAME | KADM5_CONFIG_ENCTYPE   \
                        | KADM5_CONFIG_MAX_LIFE |                       \
                        KADM5_CONFIG_MAX_RLIFE |                        \
                        KADM5_CONFIG_EXPIRATION | KADM5_CONFIG_FLAGS |  \
                        KADM5_CONFIG_ENCTYPES | KADM5_CONFIG_MKEY_FROM_KBD)

    if (params_in && params_in->mask & ILLEGAL_PARAMS) {
        free(handle);
        return KADM5_BAD_CLIENT_PARAMS;
    }
#endif

    if ((code = kadm5_get_config_params(handle->context, 0,
                                        params_in, &handle->params))) {
        free(handle);
        return(code);
    }

#define REQUIRED_PARAMS (KADM5_CONFIG_REALM |           \
                         KADM5_CONFIG_ADMIN_SERVER |    \
                         KADM5_CONFIG_KADMIND_PORT)

    if ((handle->params.mask & REQUIRED_PARAMS) != REQUIRED_PARAMS) {
        free(handle);
        return KADM5_MISSING_KRB5_CONF_PARAMS;
    }

    /*
     * Get credentials.  Also does some fallbacks in case kadmin/fqdn
     * principal doesn't exist.
     */
    code = get_init_creds(handle, client_name, init_type, pass, ccache_in,
                          service_name, realm, full_svcname,
                          sizeof(full_svcname));
    if (code)
        goto error;

    /* If the service_name and client_name are iprop-centric, use the iprop
     * port and RPC identifiers. */
    iprop_enable = (service_name != NULL &&
                    strstr(service_name, KIPROP_SVC_NAME) != NULL &&
                    strstr(client_name, KIPROP_SVC_NAME) != NULL);
    if (iprop_enable) {
        port = handle->params.iprop_port;
        rpc_prog = KRB5_IPROP_PROG;
        rpc_vers = KRB5_IPROP_VERS;
    } else {
        port = handle->params.kadmind_port;
        rpc_prog = KADM;
        rpc_vers = KADMVERS;
    }

    code = connect_to_server(handle->params.admin_server, port, &fd);
    if (code)
        goto error;

    handle->clnt = clnttcp_create(NULL, rpc_prog, rpc_vers, &fd, 0, 0);
    if (handle->clnt == NULL) {
        code = KADM5_RPC_ERROR;
#ifdef DEBUG
        clnt_pcreateerror("clnttcp_create");
#endif
        goto error;
    }
    handle->client_socket = fd;
    handle->lhandle->clnt = handle->clnt;
    handle->lhandle->client_socket = fd;

    /* now that handle->clnt is set, we can check the handle */
    if ((code = _kadm5_check_handle((void *) handle)))
        goto error;

    /*
     * The RPC connection is open; establish the GSS-API
     * authentication context.
     */
    code = setup_gss(handle, params_in,
                     (init_type == INIT_CREDS) ? client_name : NULL,
                     full_svcname);
    if (code)
        goto error;

    /*
     * Bypass the remainder of the code and return straightaway
     * if the gss service requested is kiprop
     */
    if (iprop_enable) {
        code = 0;
        *server_handle = (void *) handle;
        goto cleanup;
    }

    r = init_2(&handle->api_version, handle->clnt);
    if (r == NULL) {
        code = KADM5_RPC_ERROR;
#ifdef DEBUG
        clnt_perror(handle->clnt, "init_2 null resp");
#endif
        goto error;
    }
    /* Drop down to v3 wire protocol if server does not support v4 */
    if (r->code == KADM5_NEW_SERVER_API_VERSION &&
        handle->api_version == KADM5_API_VERSION_4) {
        handle->api_version = KADM5_API_VERSION_3;
        r = init_2(&handle->api_version, handle->clnt);
        if (r == NULL) {
            code = KADM5_RPC_ERROR;
            goto error;
        }
    }
    /* Drop down to v2 wire protocol if server does not support v3 */
    if (r->code == KADM5_NEW_SERVER_API_VERSION &&
        handle->api_version == KADM5_API_VERSION_3) {
        handle->api_version = KADM5_API_VERSION_2;
        r = init_2(&handle->api_version, handle->clnt);
        if (r == NULL) {
            code = KADM5_RPC_ERROR;
            goto error;
        }
    }
    if (r->code) {
        code = r->code;
        goto error;
    }

    *server_handle = (void *) handle;

    goto cleanup;

error:
    /*
     * Note that it is illegal for this code to execute if "handle"
     * has not been allocated and initialized.  I.e., don't use "goto
     * error" before the block of code at the top of the function
     * that allocates and initializes "handle".
     */
    if (handle->destroy_cache && handle->cache_name) {
        if (krb5_cc_resolve(handle->context,
                            handle->cache_name, &ccache) == 0)
            (void) krb5_cc_destroy (handle->context, ccache);
    }
    if (handle->cache_name)
        free(handle->cache_name);
    if(handle->clnt && handle->clnt->cl_auth)
        AUTH_DESTROY(handle->clnt->cl_auth);
    if(handle->clnt)
        clnt_destroy(handle->clnt);
    if (fd != -1)
        close(fd);

    kadm5_free_config_params(handle->context, &handle->params);

cleanup:
    if (code)
        free(handle);

    return code;
}

/* Get initial credentials for authenticating to server.  Perform fallback from
 * kadmin/fqdn to kadmin/admin if svcname_in is NULL. */
static kadm5_ret_t
get_init_creds(kadm5_server_handle_t handle, char *client_name,
               enum init_type init_type, char *pass, krb5_ccache ccache_in,
               char *svcname_in, char *realm, char *full_svcname,
               unsigned int full_svcname_len)
{
    kadm5_ret_t code;
    krb5_principal client = NULL;
    krb5_ccache ccache = NULL;
    char svcname[BUFSIZ];

    /* NULL svcname means use host-based. */
    if (svcname_in == NULL) {
        code = kadm5_get_admin_service_name(handle->context,
                                            handle->params.realm,
                                            svcname, sizeof(svcname));
        if (code)
            goto error;
    } else {
        strncpy(svcname, svcname_in, sizeof(svcname));
        svcname[sizeof(svcname)-1] = '\0';
    }
    /*
     * Acquire a service ticket for svcname@realm in the name of
     * client_name, using password pass (which could be NULL), and
     * create a ccache to store them in.  If INIT_CREDS, use the
     * ccache we were provided instead.
     */
    code = krb5_parse_name(handle->context, client_name, &client);
    if (code)
        goto error;

    if (init_type == INIT_CREDS) {
        ccache = ccache_in;
        if (asprintf(&handle->cache_name, "%s:%s",
                     krb5_cc_get_type(handle->context, ccache),
                     krb5_cc_get_name(handle->context, ccache)) < 0) {
            handle->cache_name = NULL;
            code = ENOMEM;
            goto error;
        }
    } else {
        static int counter = 0;

        if (asprintf(&handle->cache_name, "MEMORY:kadm5_%u", counter++) < 0) {
            handle->cache_name = NULL;
            code = ENOMEM;
            goto error;
        }
        code = krb5_cc_resolve(handle->context, handle->cache_name,
                               &ccache);
        if (code)
            goto error;

        code = krb5_cc_initialize (handle->context, ccache, client);
        if (code)
            goto error;

        handle->destroy_cache = 1;
    }
    handle->lhandle->cache_name = handle->cache_name;

    code = gic_iter(handle, init_type, ccache, client, pass, svcname, realm,
                    full_svcname, full_svcname_len);
    if ((code == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN
         || code == KRB5_CC_NOTFOUND) && svcname_in == NULL) {
        /* Retry with old host-independent service principal. */
        code = gic_iter(handle, init_type, ccache, client, pass,
                        KADM5_ADMIN_SERVICE, realm, full_svcname,
                        full_svcname_len);
    }
    /* Improved error messages */
    if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY) code = KADM5_BAD_PASSWORD;
    if (code == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN)
        code = KADM5_SECURE_PRINC_MISSING;

error:
    krb5_free_principal(handle->context, client);
    if (ccache != NULL && init_type != INIT_CREDS)
        krb5_cc_close(handle->context, ccache);
    return code;
}

/* Perform one iteration of attempting to get credentials.  This includes
 * searching existing ccache for requested service if INIT_CREDS. */
static kadm5_ret_t
gic_iter(kadm5_server_handle_t handle, enum init_type init_type,
         krb5_ccache ccache, krb5_principal client, char *pass, char *svcname,
         char *realm, char *full_svcname, unsigned int full_svcname_len)
{
    kadm5_ret_t code;
    krb5_context ctx;
    krb5_keytab kt;
    krb5_get_init_creds_opt *opt = NULL;
    krb5_creds mcreds, outcreds;
    int n;

    ctx = handle->context;
    kt = NULL;
    memset(full_svcname, 0, full_svcname_len);
    memset(&opt, 0, sizeof(opt));
    memset(&mcreds, 0, sizeof(mcreds));
    memset(&outcreds, 0, sizeof(outcreds));

    code = ENOMEM;
    if (realm) {
        n = snprintf(full_svcname, full_svcname_len, "%s@%s",
                     svcname, realm);
        if (n < 0 || n >= (int) full_svcname_len)
            goto error;
    } else {
        /* krb5_princ_realm(client) is not null terminated */
        n = snprintf(full_svcname, full_svcname_len, "%s@%.*s",
                     svcname, krb5_princ_realm(ctx, client)->length,
                     krb5_princ_realm(ctx, client)->data);
        if (n < 0 || n >= (int) full_svcname_len)
            goto error;
    }

    /* Credentials for kadmin don't need to be forwardable or proxiable. */
    if (init_type != INIT_CREDS) {
        code = krb5_get_init_creds_opt_alloc(ctx, &opt);
        krb5_get_init_creds_opt_set_forwardable(opt, 0);
        krb5_get_init_creds_opt_set_proxiable(opt, 0);
        krb5_get_init_creds_opt_set_out_ccache(ctx, opt, ccache);
        if (init_type == INIT_ANONYMOUS)
            krb5_get_init_creds_opt_set_anonymous(opt, 1);
    }

    if (init_type == INIT_PASS || init_type == INIT_ANONYMOUS) {
        code = krb5_get_init_creds_password(ctx, &outcreds, client, pass,
                                            krb5_prompter_posix,
                                            NULL, 0,
                                            full_svcname, opt);
        if (code)
            goto error;
    } else if (init_type == INIT_SKEY) {
        if (pass) {
            code = krb5_kt_resolve(ctx, pass, &kt);
            if (code)
                goto error;
        }
        code = krb5_get_init_creds_keytab(ctx, &outcreds, client, kt,
                                          0, full_svcname, opt);
        if (pass)
            krb5_kt_close(ctx, kt);
        if (code)
            goto error;
    } else if (init_type == INIT_CREDS) {
        mcreds.client = client;
        code = krb5_parse_name(ctx, full_svcname, &mcreds.server);
        if (code)
            goto error;
        code = krb5_cc_retrieve_cred(ctx, ccache, 0,
                                     &mcreds, &outcreds);
        krb5_free_principal(ctx, mcreds.server);
        if (code)
            goto error;
    }
error:
    krb5_free_cred_contents(ctx, &outcreds);
    if (opt)
        krb5_get_init_creds_opt_free(ctx, opt);
    return code;
}

/* Set *fd to a socket connected to hostname and port. */
static kadm5_ret_t
connect_to_server(const char *hostname, int port, int *fd)
{
    struct addrinfo hint, *addrs, *a;
    char portbuf[32];
    int err, s;
    kadm5_ret_t code;

    /* Look up the server's addresses. */
    (void) snprintf(portbuf, sizeof(portbuf), "%d", port);
    memset(&hint, 0, sizeof(hint));
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_ADDRCONFIG;
#ifdef AI_NUMERICSERV
    hint.ai_flags |= AI_NUMERICSERV;
#endif
    err = getaddrinfo(hostname, portbuf, &hint, &addrs);
    if (err != 0)
        return KADM5_CANT_RESOLVE;

    /* Try to connect to each address until we succeed. */
    for (a = addrs; a != NULL; a = a->ai_next) {
        s = socket(a->ai_family, a->ai_socktype, 0);
        if (s == -1) {
            code = KADM5_FAILURE;
            goto cleanup;
        }
        err = connect(s, a->ai_addr, a->ai_addrlen);
        if (err == 0) {
            *fd = s;
            code = 0;
            goto cleanup;
        }
        close(s);
    }

    /* We didn't succeed on any address. */
    code = KADM5_RPC_ERROR;
cleanup:
    freeaddrinfo(addrs);
    return code;
}

/* Acquire GSSAPI credentials and set up RPC auth flavor. */
static kadm5_ret_t
setup_gss(kadm5_server_handle_t handle, kadm5_config_params *params_in,
          char *client_name, char *full_svcname)
{
    kadm5_ret_t code;
    OM_uint32 gssstat, minor_stat;
    gss_buffer_desc buf;
    gss_name_t gss_client;
    gss_name_t gss_target;
    gss_cred_id_t gss_client_creds;
    const char *c_ccname_orig;
    char *ccname_orig;

    code = KADM5_GSS_ERROR;
    gss_client_creds = GSS_C_NO_CREDENTIAL;
    ccname_orig = NULL;
    gss_client = gss_target = GSS_C_NO_NAME;

    /* Temporarily use the kadm5 cache. */
    gssstat = gss_krb5_ccache_name(&minor_stat, handle->cache_name,
                                   &c_ccname_orig);
    if (gssstat != GSS_S_COMPLETE) {
        code = KADM5_GSS_ERROR;
        goto error;
    }
    if (c_ccname_orig)
        ccname_orig = strdup(c_ccname_orig);
    else
        ccname_orig = 0;

    buf.value = full_svcname;
    buf.length = strlen((char *)buf.value) + 1;
    gssstat = gss_import_name(&minor_stat, &buf,
                              (gss_OID) gss_nt_krb5_name, &gss_target);
    if (gssstat != GSS_S_COMPLETE) {
        code = KADM5_GSS_ERROR;
        goto error;
    }

    if (client_name) {
        buf.value = client_name;
        buf.length = strlen((char *)buf.value) + 1;
        gssstat = gss_import_name(&minor_stat, &buf,
                                  (gss_OID) gss_nt_krb5_name, &gss_client);
    } else gss_client = GSS_C_NO_NAME;

    if (gssstat != GSS_S_COMPLETE) {
        code = KADM5_GSS_ERROR;
        goto error;
    }

    gssstat = gss_acquire_cred(&minor_stat, gss_client, 0,
                               GSS_C_NULL_OID_SET, GSS_C_INITIATE,
                               &gss_client_creds, NULL, NULL);
    if (gssstat != GSS_S_COMPLETE) {
        code = KADM5_GSS_ERROR;
#if 0 /* for debugging only */
        {
            OM_uint32 maj_status, min_status, message_context = 0;
            gss_buffer_desc status_string;
            do {
                maj_status = gss_display_status(&min_status,
                                                gssstat,
                                                GSS_C_GSS_CODE,
                                                GSS_C_NO_OID,
                                                &message_context,
                                                &status_string);
                if (maj_status == GSS_S_COMPLETE) {
                    fprintf(stderr, "MAJ: %.*s\n",
                            (int) status_string.length,
                            (char *)status_string.value);
                    gss_release_buffer(&min_status, &status_string);
                } else {
                    fprintf(stderr,
                            "MAJ? gss_display_status returns 0x%lx?!\n",
                            (unsigned long) maj_status);
                    message_context = 0;
                }
            } while (message_context != 0);
            do {
                maj_status = gss_display_status(&min_status,
                                                minor_stat,
                                                GSS_C_MECH_CODE,
                                                GSS_C_NO_OID,
                                                &message_context,
                                                &status_string);
                if (maj_status == GSS_S_COMPLETE) {
                    fprintf(stderr, "MIN: %.*s\n",
                            (int) status_string.length,
                            (char *)status_string.value);
                    gss_release_buffer(&min_status, &status_string);
                } else {
                    fprintf(stderr,
                            "MIN? gss_display_status returns 0x%lx?!\n",
                            (unsigned long) maj_status);
                    message_context = 0;
                }
            } while (message_context != 0);
        }
#endif
        goto error;
    }

    /*
     * Do actual creation of RPC auth handle.  Implements auth flavor
     * fallback.
     */
    rpc_auth(handle, params_in, gss_client_creds, gss_target);

error:
    if (gss_client_creds != GSS_C_NO_CREDENTIAL)
        (void) gss_release_cred(&minor_stat, &gss_client_creds);

    if (gss_client)
        gss_release_name(&minor_stat, &gss_client);
    if (gss_target)
        gss_release_name(&minor_stat, &gss_target);

    /* Revert to prior gss_krb5 ccache. */
    if (ccname_orig) {
        gssstat = gss_krb5_ccache_name(&minor_stat, ccname_orig, NULL);
        if (gssstat) {
            return KADM5_GSS_ERROR;
        }
        free(ccname_orig);
    } else {
        gssstat = gss_krb5_ccache_name(&minor_stat, NULL, NULL);
        if (gssstat) {
            return KADM5_GSS_ERROR;
        }
    }

    if (handle->clnt->cl_auth == NULL) {
        return KADM5_GSS_ERROR;
    }
    return 0;
}

/* Create RPC auth handle.  Do auth flavor fallback if needed. */
static void
rpc_auth(kadm5_server_handle_t handle, kadm5_config_params *params_in,
         gss_cred_id_t gss_client_creds, gss_name_t gss_target)
{
    OM_uint32 gssstat, minor_stat;
    struct rpc_gss_sec sec;

    /* Allow unauthenticated option for testing. */
    if (params_in != NULL && (params_in->mask & KADM5_CONFIG_NO_AUTH))
        return;

    /* Use RPCSEC_GSS by default. */
    if (params_in == NULL ||
        !(params_in->mask & KADM5_CONFIG_OLD_AUTH_GSSAPI)) {
        sec.mech = gss_mech_krb5;
        sec.qop = GSS_C_QOP_DEFAULT;
        sec.svc = RPCSEC_GSS_SVC_PRIVACY;
        sec.cred = gss_client_creds;
        sec.req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;

        handle->clnt->cl_auth = authgss_create(handle->clnt,
                                               gss_target, &sec);
        if (handle->clnt->cl_auth != NULL)
            return;
    }

    if (params_in != NULL && (params_in->mask & KADM5_CONFIG_AUTH_NOFALLBACK))
        return;

    /* Fall back to old AUTH_GSSAPI. */
    handle->clnt->cl_auth = auth_gssapi_create(handle->clnt,
                                               &gssstat,
                                               &minor_stat,
                                               gss_client_creds,
                                               gss_target,
                                               (gss_OID) gss_mech_krb5,
                                               GSS_C_MUTUAL_FLAG
                                               | GSS_C_REPLAY_FLAG,
                                               0, NULL, NULL, NULL);
}

kadm5_ret_t
kadm5_destroy(void *server_handle)
{
    krb5_ccache            ccache = NULL;
    int                    code = KADM5_OK;
    kadm5_server_handle_t      handle =
        (kadm5_server_handle_t) server_handle;

    CHECK_HANDLE(server_handle);

    if (handle->destroy_cache && handle->cache_name) {
        if ((code = krb5_cc_resolve(handle->context,
                                    handle->cache_name, &ccache)) == 0)
            code = krb5_cc_destroy (handle->context, ccache);
    }
    if (handle->cache_name)
        free(handle->cache_name);
    if (handle->clnt && handle->clnt->cl_auth)
        AUTH_DESTROY(handle->clnt->cl_auth);
    if (handle->clnt)
        clnt_destroy(handle->clnt);
    if (handle->client_socket != -1)
        close(handle->client_socket);
    if (handle->lhandle)
        free (handle->lhandle);

    kadm5_free_config_params(handle->context, &handle->params);

    handle->magic_number = 0;
    free(handle);

    return code;
}
/* not supported on client */
kadm5_ret_t kadm5_lock(void *server_handle)
{
    return EINVAL;
}

/* not supported on client */
kadm5_ret_t kadm5_unlock(void *server_handle)
{
    return EINVAL;
}

kadm5_ret_t kadm5_flush(void *server_handle)
{
    return KADM5_OK;
}

int _kadm5_check_handle(void *handle)
{
    CHECK_HANDLE(handle);
    return 0;
}

krb5_error_code kadm5_init_krb5_context (krb5_context *ctx)
{
    return krb5_init_context(ctx);
}

/*
 * Stub function for kadmin.  It was created to eliminate the dependency on
 * libkdb's ulog functions.  The srv equivalent makes the actual calls.
 */
krb5_error_code
kadm5_init_iprop(void *handle, char **db_args)
{
    return (0);
}
