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

static void
check(krb5_error_code code)
{
    if (code != 0) {
        com_err("t_imp_step", code, NULL);
        exit(1);
    }
}

static void
test_raw(const char *user_str, const char *cert_str)
{
    krb5_context context;
    krb5_ccache ccache;
    krb5_principal service, user = NULL;
    krb5_tkt_creds_context tcc;
    krb5_creds in = { 0 }, out;
    krb5_data cert;
    char *name, *cert_copy;

    check(krb5_init_context(&context));
    check(krb5_cc_default(context, &ccache));
    check(krb5_cc_get_principal(context, ccache, &service));
    if (strcmp(user_str, "-") != 0)
        check(krb5_parse_name(context, user_str, &user));
    cert_copy = strdup(cert_str);
    assert(cert_copy != NULL);
    cert = make_data(cert_copy, strlen(cert_copy));
    in.client = in.server = service;
    check(krb5_tkt_creds_init(context, ccache, &in, 0, &tcc));
    check(krb5_tkt_creds_set_s4u2self(context, tcc, user, &cert));
    memset(cert_copy, 0, cert.length);
    free(cert_copy);
    check(krb5_tkt_creds_get(context, tcc));
    check(krb5_tkt_creds_get_creds(context, tcc, &out));
    check(krb5_unparse_name(context, out.client, &name));
    printf("raw impersonated: %s\n", name);
    krb5_free_unparsed_name(context, name);
    krb5_free_cred_contents(context, &out);
    krb5_tkt_creds_free(context, tcc);
    krb5_free_principal(context, user);
    krb5_free_principal(context, service);
    krb5_cc_close(context, ccache);
    krb5_free_context(context);
}

/*
 * Test krb5_tkt_creds_set_s4u_ccache(), ccache isolation for S4U2Self and
 * S4U2Proxy, and mutual exclusion between set_s4u2self and set_s4u2proxy.
 */
static void
test_s4u_ccache(const char *user_str, const char *service2_str)
{
    krb5_context context;
    krb5_ccache imp_cc, s4u_cc;
    krb5_principal service1, service2, user;
    krb5_tkt_creds_context tcc;
    krb5_creds in, out, evidence, probe;
    krb5_error_code code;

    check(krb5_init_context(&context));
    check(krb5_cc_default(context, &imp_cc));
    check(krb5_cc_get_principal(context, imp_cc, &service1));
    check(krb5_parse_name(context, user_str, &user));
    check(krb5_parse_name(context, service2_str, &service2));
    check(krb5_cc_new_unique(context, "MEMORY", NULL, &s4u_cc));
    check(krb5_cc_initialize(context, s4u_cc, user));

    /* 1. S4U2Self without s4u_ccache must not store into impersonator ccache. */
    memset(&in, 0, sizeof(in));
    in.client = in.server = service1;
    check(krb5_tkt_creds_init(context, imp_cc, &in, 0, &tcc));
    check(krb5_tkt_creds_set_s4u2self(context, tcc, user, NULL));
    check(krb5_tkt_creds_get(context, tcc));
    check(krb5_tkt_creds_get_creds(context, tcc, &evidence));
    krb5_tkt_creds_free(context, tcc);
    assert(krb5_principal_compare(context, evidence.client, user));

    memset(&in, 0, sizeof(in));
    in.client = user;
    in.server = service1;
    code = krb5_cc_retrieve_cred(context, imp_cc, 0, &in, &probe);
    assert(code == KRB5_CC_NOTFOUND);

    /* 2. Mutual exclusion between set_s4u2self and set_s4u2proxy. */
    memset(&in, 0, sizeof(in));
    in.client = in.server = service1;
    check(krb5_tkt_creds_init(context, imp_cc, &in, 0, &tcc));
    check(krb5_tkt_creds_set_s4u2self(context, tcc, user, NULL));
    code = krb5_tkt_creds_set_s4u2proxy(context, tcc, &evidence.ticket);
    assert(code == EINVAL);
    krb5_tkt_creds_free(context, tcc);

    memset(&in, 0, sizeof(in));
    in.client = service1;
    in.server = service2;
    check(krb5_tkt_creds_init(context, imp_cc, &in, 0, &tcc));
    check(krb5_tkt_creds_set_s4u2proxy(context, tcc, &evidence.ticket));
    code = krb5_tkt_creds_set_s4u2self(context, tcc, user, NULL);
    assert(code == EINVAL);
    krb5_tkt_creds_free(context, tcc);

    /* 3. S4U2Self with s4u_ccache stores into s4u_cc and hits cache on reuse. */
    memset(&in, 0, sizeof(in));
    in.client = in.server = service1;
    check(krb5_tkt_creds_init(context, imp_cc, &in, 0, &tcc));
    check(krb5_tkt_creds_set_s4u2self(context, tcc, user, NULL));
    check(krb5_tkt_creds_set_s4u_ccache(context, tcc, s4u_cc));
    check(krb5_tkt_creds_get(context, tcc));
    check(krb5_tkt_creds_get_creds(context, tcc, &out));
    krb5_tkt_creds_free(context, tcc);
    krb5_free_cred_contents(context, &out);

    /* Still absent from impersonator ccache. */
    memset(&in, 0, sizeof(in));
    in.client = user;
    in.server = service1;
    code = krb5_cc_retrieve_cred(context, imp_cc, 0, &in, &probe);
    assert(code == KRB5_CC_NOTFOUND);

    /* Cached lookup via KRB5_GC_CACHED succeeds from s4u_cc. */
    memset(&in, 0, sizeof(in));
    in.client = in.server = service1;
    check(krb5_tkt_creds_init(context, imp_cc, &in, KRB5_GC_CACHED, &tcc));
    check(krb5_tkt_creds_set_s4u2self(context, tcc, user, NULL));
    check(krb5_tkt_creds_set_s4u_ccache(context, tcc, s4u_cc));
    check(krb5_tkt_creds_get(context, tcc));
    check(krb5_tkt_creds_get_creds(context, tcc, &out));
    krb5_tkt_creds_free(context, tcc);
    assert(krb5_principal_compare(context, out.client, user));
    krb5_free_cred_contents(context, &out);

    /* 4. Pre-populate impersonator ccache with service1 -> service2 ticket. */
    memset(&in, 0, sizeof(in));
    in.client = service1;
    in.server = service2;
    check(krb5_tkt_creds_init(context, imp_cc, &in, 0, &tcc));
    check(krb5_tkt_creds_get(context, tcc));
    check(krb5_tkt_creds_get_creds(context, tcc, &out));
    krb5_tkt_creds_free(context, tcc);
    assert(krb5_principal_compare(context, out.client, service1));
    krb5_free_cred_contents(context, &out);

    /* S4U2Proxy with KRB5_GC_CACHED and no s4u_ccache must not return
     * service1's own cached service2 ticket. */
    memset(&in, 0, sizeof(in));
    in.client = service1;
    in.server = service2;
    check(krb5_tkt_creds_init(context, imp_cc, &in, KRB5_GC_CACHED, &tcc));
    check(krb5_tkt_creds_set_s4u2proxy(context, tcc, &evidence.ticket));
    code = krb5_tkt_creds_get(context, tcc);
    assert(code == KRB5_CC_NOTFOUND);
    krb5_tkt_creds_free(context, tcc);

    /* S4U2Proxy without s4u_ccache obtains user -> service2 and does not
     * store it in imp_cc. */
    check(krb5_tkt_creds_init(context, imp_cc, &in, 0, &tcc));
    check(krb5_tkt_creds_set_s4u2proxy(context, tcc, &evidence.ticket));
    check(krb5_tkt_creds_get(context, tcc));
    check(krb5_tkt_creds_get_creds(context, tcc, &out));
    krb5_tkt_creds_free(context, tcc);
    assert(krb5_principal_compare(context, out.client, user));
    assert(data_eq(out.second_ticket, evidence.ticket));
    krb5_free_cred_contents(context, &out);

    memset(&in, 0, sizeof(in));
    in.client = user;
    in.server = service2;
    code = krb5_cc_retrieve_cred(context, imp_cc, 0, &in, &probe);
    assert(code == KRB5_CC_NOTFOUND);

    /* S4U2Proxy with s4u_ccache stores into s4u_cc and hits cache on reuse. */
    memset(&in, 0, sizeof(in));
    in.client = service1;
    in.server = service2;
    check(krb5_tkt_creds_init(context, imp_cc, &in, 0, &tcc));
    check(krb5_tkt_creds_set_s4u2proxy(context, tcc, &evidence.ticket));
    check(krb5_tkt_creds_set_s4u_ccache(context, tcc, s4u_cc));
    check(krb5_tkt_creds_get(context, tcc));
    check(krb5_tkt_creds_get_creds(context, tcc, &out));
    krb5_tkt_creds_free(context, tcc);
    assert(krb5_principal_compare(context, out.client, user));
    krb5_free_cred_contents(context, &out);

    check(krb5_tkt_creds_init(context, imp_cc, &in, KRB5_GC_CACHED, &tcc));
    check(krb5_tkt_creds_set_s4u2proxy(context, tcc, &evidence.ticket));
    check(krb5_tkt_creds_set_s4u_ccache(context, tcc, s4u_cc));
    check(krb5_tkt_creds_get(context, tcc));
    check(krb5_tkt_creds_get_creds(context, tcc, &out));
    krb5_tkt_creds_free(context, tcc);
    assert(krb5_principal_compare(context, out.client, user));
    krb5_free_cred_contents(context, &out);

    printf("s4u-ccache: ok\n");

    krb5_free_cred_contents(context, &evidence);
    krb5_cc_destroy(context, s4u_cc);
    krb5_cc_close(context, imp_cc);
    krb5_free_principal(context, service1);
    krb5_free_principal(context, service2);
    krb5_free_principal(context, user);
    krb5_free_context(context);
}

/*
 * Extract the TGS-REQ authenticator subkey using the TGT session key, mutate
 * the KDC reply's S4UUserID encoding (extending KerberosFlags to 5 bytes so
 * re-encoding produces different DER), re-sign the checksum over the wire
 * S4UUserID bytes, and verify krb5_tkt_creds_step() accepts the valid wire
 * checksum and rejects a tampered one.
 */
static void
test_raw_der_cksum(const char *user_str)
{
    krb5_context context;
    krb5_ccache ccache;
    krb5_principal service, user, tgt_princ;
    krb5_creds in, tgt, out;
    krb5_tkt_creds_context tcc;
    krb5_data empty = empty_data(), req = empty_data(), realm = empty_data();
    krb5_data rep = empty_data(), mod_uid = empty_data();
    krb5_data *cksum_der = NULL, *mod_rep = NULL, *nofast_req = NULL;
    krb5_data auth_plain = empty_data();
    krb5_kdc_req *tgs_req = NULL;
    krb5_ap_req *ap_req = NULL;
    krb5_authenticator *auth = NULL;
    krb5_kdc_rep *tgs_rep = NULL;
    krb5_pa_data *pa_ap, *pa_s4u;
    krb5_pa_s4u_x509_user *rep_s4u = NULL;
    krb5_checksum new_cksum;
    unsigned int flags = 0;
    int use_primary = 0, tamper;
    uint8_t *p, *uid_start, *buf;
    size_t uid_len, outer_len, a0_len, total_len, pos, i, j;
    krb5_error_code code;
    const uint8_t orig_opts[9] = {
        0xa4, 0x07, 0x03, 0x05, 0x00, 0x20, 0x00, 0x00, 0x00
    };
    const uint8_t ext_opts[10] = {
        0xa4, 0x08, 0x03, 0x06, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00
    };

    check(krb5_init_context(&context));
    check(krb5_cc_default(context, &ccache));
    check(krb5_cc_get_principal(context, ccache, &service));
    check(krb5_parse_name(context, user_str, &user));
    check(krb5_build_principal_ext(context, &tgt_princ,
                                   service->realm.length, service->realm.data,
                                   KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                   service->realm.length, service->realm.data,
                                   0));
    memset(&in, 0, sizeof(in));
    in.client = service;
    in.server = tgt_princ;
    check(krb5_cc_retrieve_cred(context, ccache, 0, &in, &tgt));

    for (tamper = 0; tamper <= 1; tamper++) {
        memset(&in, 0, sizeof(in));
        in.client = in.server = service;
        check(krb5_tkt_creds_init(context, ccache, &in, 0, &tcc));
        check(krb5_tkt_creds_set_s4u2self(context, tcc, user, NULL));
        check(krb5_tkt_creds_step(context, tcc, &empty, &req, &realm, &flags));
        assert(flags & KRB5_TKT_CREDS_STEP_FLAG_CONTINUE);

        /* Decrypt AP-REQ authenticator from TGS-REQ to get the subkey. */
        check(decode_krb5_tgs_req(&req, &tgs_req));
        pa_ap = krb5int_find_pa_data(context, tgs_req->padata,
                                     KRB5_PADATA_AP_REQ);
        assert(pa_ap != NULL);
        {
            krb5_data ap_data = make_data(pa_ap->contents, pa_ap->length);
            check(decode_krb5_ap_req(&ap_data, &ap_req));
        }
        check(alloc_data(&auth_plain, ap_req->authenticator.ciphertext.length));
        check(krb5_c_decrypt(context, &tgt.keyblock,
                             KRB5_KEYUSAGE_TGS_REQ_AUTH, NULL,
                             &ap_req->authenticator, &auth_plain));
        check(decode_krb5_authenticator(&auth_plain, &auth));
        assert(auth->subkey != NULL);

        /* Strip PA-FX-FAST so the KDC returns PA-S4U-X509-USER directly in
         * TGS-REP padata instead of encrypted inside a FAST response. */
        for (i = 0, j = 0; tgs_req->padata[i] != NULL; i++) {
            if (tgs_req->padata[i]->pa_type == KRB5_PADATA_FX_FAST) {
                free(tgs_req->padata[i]->contents);
                free(tgs_req->padata[i]);
            } else {
                tgs_req->padata[j++] = tgs_req->padata[i];
            }
        }
        tgs_req->padata[j] = NULL;
        check(encode_krb5_tgs_req(tgs_req, &nofast_req));

        /* Send non-FAST TGS-REQ to KDC and decode the TGS-REP. */
        check(krb5_sendto_kdc(context, nofast_req, &realm, &rep,
                              &use_primary, 0));
        krb5_free_data(context, nofast_req);
        nofast_req = NULL;
        check(decode_krb5_tgs_rep(&rep, &tgs_rep));
        pa_s4u = krb5int_find_pa_data(context, tgs_rep->padata,
                                      KRB5_PADATA_S4U_X509_USER);
        assert(pa_s4u != NULL);
        {
            krb5_data pa_data = make_data(pa_s4u->contents, pa_s4u->length);
            check(decode_krb5_pa_s4u_x509_user(&pa_data, &rep_s4u));
        }

        /* Parse outer SEQUENCE and [0] S4UUserID (short-form lengths). */
        p = pa_s4u->contents;
        assert(pa_s4u->length > 6 && p[0] == 0x30 && p[1] < 0x80);
        assert(p[2] == 0xa0 && p[3] < 0x80);
        a0_len = p[3];
        uid_start = p + 4;
        assert(uid_start[0] == 0x30 && uid_start[1] < 0x80);
        assert(a0_len >= sizeof(orig_opts));
        assert(memcmp(uid_start + a0_len - sizeof(orig_opts),
                      orig_opts, sizeof(orig_opts)) == 0);

        /* Extend [4] KerberosFlags from 4 bytes to 5 bytes (valid RFC 4120
         * BIT STRING; MIT's encoder always emits 4 bytes). */
        uid_len = a0_len + 1;
        check(alloc_data(&mod_uid, uid_len));
        memcpy(mod_uid.data, uid_start, a0_len - sizeof(orig_opts));
        ((uint8_t *)mod_uid.data)[1] = uid_start[1] + 1;
        memcpy(mod_uid.data + a0_len - sizeof(orig_opts),
               ext_opts, sizeof(ext_opts));

        check(krb5_c_make_checksum(context, rep_s4u->cksum.checksum_type,
                                   auth->subkey,
                                   KRB5_KEYUSAGE_PA_S4U_X509_USER_REPLY,
                                   &mod_uid, &new_cksum));
        if (tamper)
            ((uint8_t *)mod_uid.data)[uid_len - 1] ^= 0x01;

        check(encode_krb5_checksum(&new_cksum, &cksum_der));
        assert(uid_len < 0x80 && cksum_der->length < 0x80);
        outer_len = 2 + uid_len + 2 + cksum_der->length;
        assert(outer_len < 0x80);
        total_len = 2 + outer_len;
        buf = malloc(total_len);
        assert(buf != NULL);
        pos = 0;
        buf[pos++] = 0x30;
        buf[pos++] = outer_len;
        buf[pos++] = 0xa0;
        buf[pos++] = uid_len;
        memcpy(buf + pos, mod_uid.data, uid_len);
        pos += uid_len;
        buf[pos++] = 0xa1;
        buf[pos++] = cksum_der->length;
        memcpy(buf + pos, cksum_der->data, cksum_der->length);
        pos += cksum_der->length;
        assert(pos == total_len);

        free(pa_s4u->contents);
        pa_s4u->contents = buf;
        pa_s4u->length = total_len;

        check(encode_krb5_tgs_rep(tgs_rep, &mod_rep));
        krb5_free_data_contents(context, &req);
        krb5_free_data_contents(context, &realm);
        code = krb5_tkt_creds_step(context, tcc, mod_rep, &req, &realm,
                                   &flags);
        if (tamper) {
            assert(code == KRB5_KDCREP_MODIFIED);
        } else {
            check(code);
            assert(!(flags & KRB5_TKT_CREDS_STEP_FLAG_CONTINUE));
            check(krb5_tkt_creds_get_creds(context, tcc, &out));
            assert(krb5_principal_compare(context, out.client, user));
            krb5_free_cred_contents(context, &out);
        }

        krb5_tkt_creds_free(context, tcc);
        krb5_free_checksum_contents(context, &new_cksum);
        krb5_free_data(context, cksum_der);
        cksum_der = NULL;
        krb5_free_data(context, mod_rep);
        mod_rep = NULL;
        krb5_free_data_contents(context, &mod_uid);
        krb5_free_data_contents(context, &auth_plain);
        krb5_free_data_contents(context, &req);
        krb5_free_data_contents(context, &realm);
        krb5_free_data_contents(context, &rep);
        krb5_free_pa_s4u_x509_user(context, rep_s4u);
        rep_s4u = NULL;
        krb5_free_kdc_rep(context, tgs_rep);
        tgs_rep = NULL;
        krb5_free_authenticator(context, auth);
        auth = NULL;
        krb5_free_ap_req(context, ap_req);
        ap_req = NULL;
        krb5_free_kdc_req(context, tgs_req);
        tgs_req = NULL;
    }

    printf("raw-der-cksum: ok\n");

    krb5_free_cred_contents(context, &tgt);
    krb5_free_principal(context, tgt_princ);
    krb5_free_principal(context, user);
    krb5_free_principal(context, service);
    krb5_cc_close(context, ccache);
    krb5_free_context(context);
}

int
main(int argc, char **argv)
{
    int i;
    const char *user_str = NULL;

    if (argc == 4 && strcmp(argv[1], "--raw") == 0) {
        test_raw(argv[2], argv[3]);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--s4u-ccache") == 0) {
        test_s4u_ccache(argv[2], argv[3]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--raw-der-cksum") == 0) {
        test_raw_der_cksum(argv[2]);
        return 0;
    }

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
