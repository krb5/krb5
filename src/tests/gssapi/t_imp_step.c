/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * Test program for krb5_gss_acquire_cred_impersonate_name_step().
 *
 * Usage:
 *   t_imp_step <user-name>
 *
 * Acquires impersonator credentials from the default ccache, then uses the
 * step-based API to acquire an S4U2Self impersonation credential for the
 * named user, driving the KDC exchange manually with krb5_sendto_kdc().
 *
 * Prints the impersonated principal name on success.
 *
 * Additional options:
 *   --bad-input   Pass a NULL input token on the second step; verify that the
 *                 parameter-validation error path cleans up the in-progress
 *                 handle without leaking it.
 *   --abandon     Abandon the exchange mid-way (release in-progress handle);
 *                 verify no crash or leak.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "k5-int.h"
#include "common.h"

static int opt_bad_input = 0;
static int opt_abandon = 0;

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

    req_data = make_data(request->value, request->length);

    /* realm_buf is a raw byte string from krb5_tkt_creds_step — not NUL-terminated.
     * Build a NUL-terminated copy for krb5_sendto_kdc. */
    realm_data.data = malloc(realm_buf->length + 1);
    if (realm_data.data == NULL) {
        fprintf(stderr, "t_imp_step: out of memory\n");
        exit(1);
    }
    memcpy(realm_data.data, realm_buf->value, realm_buf->length);
    realm_data.data[realm_buf->length] = '\0';
    realm_data.length = realm_buf->length;

    memset(&rep_data, 0, sizeof(rep_data));
    {
        int use_primary = 0;
        code = krb5_sendto_kdc(context, &req_data, &realm_data,
                               &rep_data, &use_primary, 0 /* no_udp */);
    }
    free(realm_data.data);
    if (code != 0) {
        com_err("t_imp_step", code, "sending request to KDC");
        exit(1);
    }

    reply->value = rep_data.data;
    reply->length = rep_data.length;
}

static void
test_step(const char *user_str)
{
    OM_uint32 major, minor, time_rec;
    gss_name_t user_name = GSS_C_NO_NAME;
    gss_cred_id_t imp_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t step_cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc output_tok, target_realm;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc name_buf;
    krb5_context kctx;
    krb5_error_code code;
    int step_count = 0;

    /* Acquire impersonator creds from the default ccache. */
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             &mechset_krb5, GSS_C_INITIATE,
                             &imp_cred, NULL, NULL);
    check_gsserr("gss_acquire_cred (impersonator)", major, minor);

    user_name = import_name(user_str);

    /* Create a krb5 context for kdc_roundtrip(). */
    code = krb5_init_context(&kctx);
    if (code != 0) {
        com_err("t_imp_step", code, "krb5_init_context");
        exit(1);
    }

    /* --- Step loop --- */
    step_cred = GSS_C_NO_CREDENTIAL;
    output_tok.value = NULL;
    output_tok.length = 0;
    target_realm.value = NULL;
    target_realm.length = 0;

    /* First call: no input token, no in-progress handle. */
    major = krb5_gss_acquire_cred_impersonate_name_step(
        &minor,
        imp_cred,
        user_name,
        GSS_C_INDEFINITE,
        GSS_C_NO_OID_SET,
        GSS_C_INITIATE,
        GSS_C_NO_BUFFER,      /* input_token: none on first call */
        &step_cred,           /* out: in-progress handle */
        &output_tok,
        &target_realm,
        &actual_mechs,
        &time_rec);

    if (major == GSS_S_COMPLETE) {
        /* Completed in a single call (unlikely but valid). */
        goto done;
    }
    if (major != GSS_S_CONTINUE_NEEDED) {
        check_gsserr("krb5_gss_acquire_cred_impersonate_name_step (first)",
                     major, minor);
    }
    step_count++;

    /* Test: abandon after first step — release in-progress handle, exit. */
    if (opt_abandon) {
        gss_release_cred(&minor, &step_cred);
        gss_release_buffer(&minor, &output_tok);
        gss_release_buffer(&minor, &target_realm);
        printf("abandon: ok (no crash)\n");
        goto cleanup;
    }

    /* Subsequent steps: send output_tok to KDC, feed reply back. */
    while (major == GSS_S_CONTINUE_NEEDED) {
        gss_buffer_desc reply_tok = {0, NULL};
        gss_buffer_t input_for_step;

        if (opt_bad_input && step_count == 1) {
            /* Pass NULL as input_token to trigger the parameter-validation
             * error path and verify that the in-progress handle is released. */
            input_for_step = GSS_C_NO_BUFFER;
        } else {
            kdc_roundtrip(kctx, &output_tok, &target_realm, &reply_tok);
            input_for_step = &reply_tok;
        }

        gss_release_buffer(&minor, &output_tok);
        gss_release_buffer(&minor, &target_realm);
        output_tok.value = NULL;
        output_tok.length = 0;
        target_realm.value = NULL;
        target_realm.length = 0;

        major = krb5_gss_acquire_cred_impersonate_name_step(
            &minor,
            imp_cred,
            user_name,
            GSS_C_INDEFINITE,
            GSS_C_NO_OID_SET,
            GSS_C_INITIATE,
            input_for_step,
            &step_cred,
            &output_tok,
            &target_realm,
            &actual_mechs,
            &time_rec);

        /* Free the KDC reply (allocated by kdc_roundtrip via krb5). */
        if (input_for_step == &reply_tok)
            krb5_free_data_contents(kctx, (krb5_data *)&reply_tok);

        step_count++;

        if (opt_bad_input) {
            if (!GSS_ERROR(major)) {
                fprintf(stderr, "t_imp_step: expected error for bad input\n");
                exit(1);
            }
            /* step_cred should have been set to GSS_C_NO_CREDENTIAL. */
            if (step_cred != GSS_C_NO_CREDENTIAL) {
                fprintf(stderr,
                        "t_imp_step: in-progress handle not cleared on error\n");
                exit(1);
            }
            printf("bad-input: correctly returned error\n");
            goto cleanup;
        }

        if (GSS_ERROR(major))
            check_gsserr("krb5_gss_acquire_cred_impersonate_name_step", major,
                         minor);
    }

done:
    /* Verify the result: display the impersonated user's name. */
    {
        gss_name_t cred_name = GSS_C_NO_NAME;
        major = gss_inquire_cred(&minor, step_cred, &cred_name,
                                 NULL, NULL, NULL);
        check_gsserr("gss_inquire_cred", major, minor);

        major = gss_display_name(&minor, cred_name, &name_buf, NULL);
        check_gsserr("gss_display_name", major, minor);

        printf("impersonated: %.*s\n", (int)name_buf.length,
               (char *)name_buf.value);

        gss_release_buffer(&minor, &name_buf);
        gss_release_name(&minor, &cred_name);
    }

    /* time_rec should be > 0 for a valid credential. */
    if (time_rec == 0) {
        fprintf(stderr, "t_imp_step: time_rec is zero\n");
        exit(1);
    }

cleanup:
    gss_release_cred(&minor, &step_cred);
    gss_release_cred(&minor, &imp_cred);
    gss_release_name(&minor, &user_name);
    gss_release_buffer(&minor, &output_tok);
    gss_release_buffer(&minor, &target_realm);
    gss_release_oid_set(&minor, &actual_mechs);
    krb5_free_context(kctx);
}

int
main(int argc, char **argv)
{
    int i;
    const char *user_str = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bad-input") == 0)
            opt_bad_input = 1;
        else if (strcmp(argv[i], "--abandon") == 0)
            opt_abandon = 1;
        else if (user_str == NULL)
            user_str = argv[i];
        else
            errout("usage: t_imp_step [--bad-input|--abandon] <user>");
    }
    if (user_str == NULL)
        errout("usage: t_imp_step [--bad-input|--abandon] <user>");

    test_step(user_str);
    return 0;
}
