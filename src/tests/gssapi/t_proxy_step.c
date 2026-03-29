/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * Test program for step-based S4U2Proxy via the non-IAKERB gss_init_sec_context
 * path.
 *
 * Usage:
 *   t_proxy_step <user-name> <service-name>
 *
 * First acquires an impersonation credential for the named user using the
 * step-based krb5_gss_acquire_cred_impersonate_name_step() API (which sets
 * the use_step_proxy flag on the credential).  Then calls gss_init_sec_context()
 * toward the named service, routing each S4U2Proxy TGS-REQ to the KDC via
 * krb5_sendto_kdc() and using krb5_gss_get_proxy_realm() to determine the
 * target realm.  Accepts the resulting AP-REQ with gss_accept_sec_context()
 * and prints the authenticated client name.
 *
 * The default ccache must contain a TGT for the impersonator service, and
 * the default keytab must contain keys for the target service.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "k5-int.h"
#include "common.h"

/*
 * Send a raw Kerberos message to the KDC for realm and return the reply.
 * Aborts on network error.
 */
static void
kdc_roundtrip(krb5_context context, const gss_buffer_desc *request,
              const gss_buffer_desc *realm_buf, gss_buffer_desc *reply)
{
    krb5_error_code code;
    krb5_data req_data, realm_data, rep_data;
    int use_primary = 0;

    req_data = make_data(request->value, request->length);

    /* realm_buf is a raw byte string — not NUL-terminated.
     * Build a NUL-terminated copy for krb5_sendto_kdc. */
    realm_data.data = malloc(realm_buf->length + 1);
    if (realm_data.data == NULL) {
        fprintf(stderr, "t_proxy_step: out of memory\n");
        exit(1);
    }
    memcpy(realm_data.data, realm_buf->value, realm_buf->length);
    realm_data.data[realm_buf->length] = '\0';
    realm_data.length = realm_buf->length;

    memset(&rep_data, 0, sizeof(rep_data));
    code = krb5_sendto_kdc(context, &req_data, &realm_data,
                           &rep_data, &use_primary, 0 /* no_udp */);
    free(realm_data.data);
    if (code != 0) {
        com_err("t_proxy_step", code, "sending request to KDC");
        exit(1);
    }

    reply->value = rep_data.data;
    reply->length = rep_data.length;
}

/*
 * Drive krb5_gss_acquire_cred_impersonate_name_step() to completion,
 * sending each output TGS-REQ to the KDC and returning the finished
 * impersonation credential (which has use_step_proxy set).
 */
static gss_cred_id_t
acquire_step_cred(krb5_context kctx, gss_cred_id_t imp_cred,
                  gss_name_t user_name)
{
    OM_uint32 major, minor, time_rec;
    gss_cred_id_t step_cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc output_tok = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc target_realm = GSS_C_EMPTY_BUFFER;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;

    /* First call: no input token, no in-progress handle. */
    major = krb5_gss_acquire_cred_impersonate_name_step(
        &minor, imp_cred, user_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
        GSS_C_INITIATE, GSS_C_NO_BUFFER, &step_cred,
        &output_tok, &target_realm, &actual_mechs, &time_rec);
    gss_release_oid_set(&minor, &actual_mechs);
    if (major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED)
        check_gsserr("acquire_cred_impersonate_name_step (first)", major, minor);

    while (major == GSS_S_CONTINUE_NEEDED) {
        gss_buffer_desc reply = GSS_C_EMPTY_BUFFER;

        kdc_roundtrip(kctx, &output_tok, &target_realm, &reply);
        gss_release_buffer(&minor, &output_tok);
        gss_release_buffer(&minor, &target_realm);

        major = krb5_gss_acquire_cred_impersonate_name_step(
            &minor, imp_cred, user_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
            GSS_C_INITIATE, &reply, &step_cred,
            &output_tok, &target_realm, &actual_mechs, &time_rec);
        krb5_free_data_contents(kctx, (krb5_data *)&reply);
        gss_release_oid_set(&minor, &actual_mechs);
        if (GSS_ERROR(major))
            check_gsserr("acquire_cred_impersonate_name_step", major, minor);
    }

    gss_release_buffer(&minor, &output_tok);
    gss_release_buffer(&minor, &target_realm);
    return step_cred;
}

int
main(int argc, char *argv[])
{
    OM_uint32 major, minor, pr_major, req_flags;
    gss_cred_id_t imp_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t proxy_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t acc_cred = GSS_C_NO_CREDENTIAL;
    gss_name_t user_name = GSS_C_NO_NAME;
    gss_name_t service_name = GSS_C_NO_NAME;
    gss_ctx_id_t init_ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acc_ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc output_tok = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc realm_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc acc_output = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    gss_name_t src_name = GSS_C_NO_NAME;
    krb5_context kctx;
    krb5_error_code code;
    const char *user_str, *service_str;

    if (argc != 3) {
        fprintf(stderr, "usage: t_proxy_step <user-name> <service-name>\n");
        return 1;
    }
    user_str = argv[1];
    service_str = argv[2];

    code = krb5_init_context(&kctx);
    if (code != 0) {
        com_err("t_proxy_step", code, "krb5_init_context");
        return 1;
    }

    user_name = import_name(user_str);
    service_name = import_name(service_str);

    /* Acquire impersonator credentials from the default ccache. */
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             &mechset_krb5, GSS_C_INITIATE,
                             &imp_cred, NULL, NULL);
    check_gsserr("gss_acquire_cred (impersonator)", major, minor);

    /* Acquire acceptor credentials from the default keytab. */
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             &mechset_krb5, GSS_C_ACCEPT,
                             &acc_cred, NULL, NULL);
    check_gsserr("gss_acquire_cred (acceptor)", major, minor);

    /* Phase 1: Acquire an impersonation credential via step-based S4U2Self.
     * This sets use_step_proxy on the returned credential so that
     * gss_init_sec_context() will use the step-based S4U2Proxy path. */
    proxy_cred = acquire_step_cred(kctx, imp_cred, user_name);

    /*
     * Phase 2: Drive the S4U2Proxy exchange via gss_init_sec_context().
     * While krb5_gss_get_proxy_realm() returns GSS_S_COMPLETE, the output
     * token is a raw TGS-REQ to forward to the KDC identified by realm_buf.
     * Once the proxy exchange completes, gss_init_sec_context() returns
     * GSS_S_COMPLETE and output_tok contains the AP-REQ for the service.
     */
    req_flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    major = gss_init_sec_context(&minor, proxy_cred, &init_ctx, service_name,
                                 &mech_krb5, req_flags, 0,
                                 GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                 NULL, &output_tok, NULL, NULL);
    if (GSS_ERROR(major))
        check_gsserr("gss_init_sec_context (initial)", major, minor);

    while (major == GSS_S_CONTINUE_NEEDED) {
        pr_major = krb5_gss_get_proxy_realm(&minor, init_ctx, &realm_buf);
        if (pr_major == GSS_S_COMPLETE) {
            /* S4U2Proxy exchange in progress: route output_tok (TGS-REQ)
             * to the KDC and feed the reply back as the next input. */
            gss_buffer_desc kdc_reply = GSS_C_EMPTY_BUFFER;

            kdc_roundtrip(kctx, &output_tok, &realm_buf, &kdc_reply);
            gss_release_buffer(&minor, &output_tok);
            gss_release_buffer(&minor, &realm_buf);

            major = gss_init_sec_context(
                &minor, proxy_cred, &init_ctx, service_name,
                &mech_krb5, req_flags, 0, GSS_C_NO_CHANNEL_BINDINGS,
                &kdc_reply, NULL, &output_tok, NULL, NULL);
            krb5_free_data_contents(kctx, (krb5_data *)&kdc_reply);
            if (GSS_ERROR(major))
                check_gsserr("gss_init_sec_context (proxy step)", major, minor);
        } else {
            /* No active proxy exchange (GSS_S_UNAVAILABLE) — unexpected
             * CONTINUE_NEEDED with no proxy: shouldn't happen without
             * mutual auth. */
            gss_release_buffer(&minor, &realm_buf);
            if (pr_major != GSS_S_UNAVAILABLE)
                check_gsserr("krb5_gss_get_proxy_realm", pr_major, minor);
            errout("unexpected CONTINUE_NEEDED after S4U2Proxy exchange");
        }
    }

    /* Phase 3: Accept the AP-REQ and display the client's name. */
    major = gss_accept_sec_context(&minor, &acc_ctx, acc_cred,
                                   &output_tok, GSS_C_NO_CHANNEL_BINDINGS,
                                   &src_name, NULL, &acc_output,
                                   NULL, NULL, NULL);
    gss_release_buffer(&minor, &output_tok);
    gss_release_buffer(&minor, &acc_output);
    if (GSS_ERROR(major))
        check_gsserr("gss_accept_sec_context", major, minor);

    major = gss_display_name(&minor, src_name, &name_buf, NULL);
    check_gsserr("gss_display_name", major, minor);
    printf("proxy-auth: %.*s\n", (int)name_buf.length, (char *)name_buf.value);

    gss_release_buffer(&minor, &name_buf);
    gss_release_name(&minor, &src_name);
    gss_delete_sec_context(&minor, &init_ctx, GSS_C_NO_BUFFER);
    gss_delete_sec_context(&minor, &acc_ctx, GSS_C_NO_BUFFER);
    gss_release_cred(&minor, &proxy_cred);
    gss_release_cred(&minor, &imp_cred);
    gss_release_cred(&minor, &acc_cred);
    gss_release_name(&minor, &user_name);
    gss_release_name(&minor, &service_name);
    krb5_free_context(kctx);
    return 0;
}
