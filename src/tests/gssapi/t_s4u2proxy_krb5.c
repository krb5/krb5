/* -*- mode: c; indent-tabs-mode: nil -*- */
/* tests/gssapi/t_s4u2proxy_deleg.c - Test S4U2Proxy after krb5 auth */
/*
 * Copyright 2011 by the Massachusetts Institute of Technology.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi/gssapi_krb5.h>

/*
 * Usage: ./t_s4u2proxy_krb5 [--spnego] client_cache storage_cache
 *                                      service1 service2
 *
 * This program performs a regular Kerberos or SPNEGO authentication from the
 * default principal of client_cache to service1.  If that authentication
 * yields delegated credentials, the program stores those credentials in
 * sorage_ccache and uses that cache to perform a second authentication to
 * service2 using S4U2Proxy.
 *
 * The default keytab must contain keys for service1 and service2.  The default
 * ccache must contain a TGT for service1.  service1 and service2 must be given
 * as krb5 principal names.  This program assumes that krb5 or SPNEGO
 * authentication requires only one token exchange.
 */

static void
display_status_1(const char *m, OM_uint32 code, int type)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    msg_ctx = 0;
    while (1) {
        maj_stat = gss_display_status(&min_stat, code,
                                      type, GSS_C_NULL_OID,
                                      &msg_ctx, &msg);
        printf("%s: %s\n", m, (char *)msg.value);
        (void) gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }
}

static void
gsserr(OM_uint32 maj_stat, OM_uint32 min_stat, const char *msg)
{
    display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
    display_status_1(msg, min_stat, GSS_C_MECH_CODE);
    exit(1);
}

static void
krb5err(krb5_context context, krb5_error_code code, const char *msg)
{
    const char *emsg = krb5_get_error_message(context, code);

    printf("%s: %s\n", msg, emsg);
    krb5_free_error_message(context, emsg);
    exit(1);
}

int
main(int argc, char *argv[])
{
    const char *client_ccname, *storage_ccname, *service1, *service2;
    krb5_context context = NULL;
    krb5_error_code ret;
    krb5_boolean use_spnego = FALSE;
    krb5_ccache storage_ccache = NULL;
    krb5_principal client_princ = NULL;
    OM_uint32 minor, major;
    gss_buffer_desc buf, token;
    gss_OID mech;
    gss_OID_set_desc mechs;
    gss_name_t service1_name = GSS_C_NO_NAME;
    gss_name_t service2_name = GSS_C_NO_NAME;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_cred_id_t service1_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t deleg_cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_OID_desc spnego_mech = { 6, "\053\006\001\005\005\002" };

    /* Parse arguments. */
    if (argc >= 2 && strcmp(argv[1], "--spnego") == 0) {
        use_spnego = TRUE;
        argc--;
        argv++;
    }
    if (argc != 5) {
        fprintf(stderr, "./t_s4u2proxy_krb5 [--spnego] client_cache "
                "storage_ccache service1 service2\n");
        return 1;
    }
    client_ccname = argv[1];
    storage_ccname = argv[2];
    service1 = argv[3];
    service2 = argv[4];

    mech = use_spnego ? (gss_OID)&spnego_mech : (gss_OID)gss_mech_krb5;
    mechs.elements = mech;
    mechs.count = 1;
    ret = krb5_init_context(&context);
    if (ret)
        krb5err(context, ret, "krb5_init_context");

    /* Get GSS name and GSS_C_BOTH cred for service1, using the default
     * ccache. */
    buf.value = (char *)service1;
    buf.length = strlen(service1);
    major = gss_import_name(&minor, &buf, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                            &service1_name);
    if (GSS_ERROR(major))
        gsserr(major, minor, "gss_import_name(service1)");
    major = gss_acquire_cred(&minor, service1_name, GSS_C_INDEFINITE,
                             &mechs, GSS_C_BOTH, &service1_cred, NULL, NULL);
    if (GSS_ERROR(major))
        gsserr(major, minor, "gss_acquire_cred(service1)");

    /* Get GSS name for service2. */
    buf.value = (char *)service2;
    buf.length = strlen(service2);
    major = gss_import_name(&minor, &buf, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                            &service2_name);
    if (GSS_ERROR(major))
        gsserr(major, minor, "gss_import_name(service2)");

    /* Create initiator context and get the first token, using the client
     * ccache. */
    major = gss_krb5_ccache_name(&minor, client_ccname, NULL);
    if (GSS_ERROR(major))
        gsserr(major, minor, "gss_krb5_ccache_name(1)");
    token.value = NULL;
    token.length = 0;
    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL,
                                 &initiator_context, service1_name, mech,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, NULL, &token, NULL, NULL);
    if (GSS_ERROR(major))
        gsserr(major, minor, "gss_init_sec_context(1)");

    /* Pass the token to gss_accept_sec_context. */
    buf.value = NULL;
    buf.length = 0;
    major = gss_accept_sec_context(&minor, &acceptor_context,
                                   service1_cred, &token,
                                   GSS_C_NO_CHANNEL_BINDINGS, &client_name,
                                   NULL, &buf, NULL, NULL, &deleg_cred);
    if (major != GSS_S_COMPLETE)
        gsserr(major, minor, "gss_accept_sec_context(1)");
    gss_release_buffer(&minor, &token);

    /* Display and remember the client principal. */
    major = gss_display_name(&minor, client_name, &buf, NULL);
    if (major != GSS_S_COMPLETE)
        gsserr(major, minor, "gss_display_name(1)");
    printf("auth1: %.*s\n", (int)buf.length, (char *)buf.value);
    /* Assumes buffer is null-terminated, which in our implementation it is. */
    ret = krb5_parse_name(context, buf.value, &client_princ);
    if (ret)
        krb5err(context, ret, "krb5_parse_name");
    gss_release_buffer(&minor, &buf);

    if (deleg_cred == GSS_C_NO_CREDENTIAL) {
        printf("no credential delegated.\n");
        goto cleanup;
    }

    /* Store the delegated credentials. */
    ret = krb5_cc_resolve(context, storage_ccname, &storage_ccache);
    if (ret)
        krb5err(context, ret, "krb5_cc_resolve");
    ret = krb5_cc_initialize(context, storage_ccache, client_princ);
    if (ret)
        krb5err(context, ret, "krb5_cc_initialize");
    major = gss_krb5_copy_ccache(&minor, deleg_cred, storage_ccache);
    if (GSS_ERROR(major))
        gsserr(major, minor, "gss_krb5_copy_ccache");
    ret = krb5_cc_close(context, storage_ccache);
    if (ret)
        krb5err(context, ret, "krb5_cc_close");

    gss_delete_sec_context(&minor, &initiator_context, GSS_C_NO_BUFFER);
    gss_delete_sec_context(&minor, &acceptor_context, GSS_C_NO_BUFFER);

    /* Create initiator context and get the first token, using the storage
     * ccache. */
    major = gss_krb5_ccache_name(&minor, storage_ccname, NULL);
    if (GSS_ERROR(major))
        gsserr(major, minor, "gss_krb5_ccache_name(2)");
    token.value = NULL;
    token.length = 0;
    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL,
                                 &initiator_context, service2_name, mech,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, NULL, &token, NULL, NULL);
    if (GSS_ERROR(major))
        gsserr(major, minor, "gss_init_sec_context(2)");

    /* Pass the token to gss_accept_sec_context. */
    buf.value = NULL;
    buf.length = 0;
    major = gss_accept_sec_context(&minor, &acceptor_context,
                                   GSS_C_NO_CREDENTIAL, &token,
                                   GSS_C_NO_CHANNEL_BINDINGS, &client_name,
                                   NULL, &buf, NULL, NULL, &deleg_cred);
    if (major != GSS_S_COMPLETE)
        gsserr(major, minor, "gss_accept_sec_context(2)");
    gss_release_buffer(&minor, &token);

    major = gss_display_name(&minor, client_name, &buf, NULL);
    if (major != GSS_S_COMPLETE)
        gsserr(major, minor, "gss_display_name(2)");
    printf("auth2: %.*s\n", (int)buf.length, (char *)buf.value);
    gss_release_buffer(&minor, &buf);

cleanup:
    gss_release_name(&minor, &client_name);
    gss_release_name(&minor, &service1_name);
    gss_release_name(&minor, &service2_name);
    gss_release_cred(&minor, &service1_cred);
    gss_release_cred(&minor, &deleg_cred);
    gss_delete_sec_context(&minor, &initiator_context, GSS_C_NO_BUFFER);
    gss_delete_sec_context(&minor, &acceptor_context, GSS_C_NO_BUFFER);
    krb5_free_principal(context, client_princ);
    krb5_free_context(context);
    return 0;
}
