/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/hooks. - test harness for send and recv hooks */
/*
 * Copyright (C) 2013 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "k5-int.h"
#include <krb5.h>

/*
 * SENDTO KDC HOOK TEST
 */

/* Global variables */

static krb5_context ctx;

/* Assert functins */

#ifndef assert_krb5_error_code
static void
assert_krb5_error_code_ex(krb5_error_code code,
                          const char *file,
                          const int line)
{
    const char *errmsg;

    if (code) {
        errmsg = krb5_get_error_message(ctx, code);
        fprintf(stderr, "%s:%d -- %s (code=%d)\n", file, line, errmsg, code);
        krb5_free_error_message(ctx, errmsg);
        exit(1);
    }
}

#define assert_krb5_error_code(code) \
    assert_krb5_error_code_ex((code), __FILE__, __LINE__)
#endif

/* Add simple test hook for an AS REQ. */

static krb5_error_code
krb5_send_as_req_test(krb5_context context,
                      void *data,
                      const krb5_data *realm,
                      const krb5_data *message,
                      krb5_data **new_message_out,
                      krb5_data **reply_out)
{
    krb5_kdc_req *as_req = NULL;
    krb5_error_code code;
    int cmp;

    assert(krb5_is_as_req(message));

    code = decode_krb5_as_req(message, &as_req);
    assert_krb5_error_code(code);

    assert(as_req->msg_type == KRB5_AS_REQ);
    assert((as_req->kdc_options & KDC_OPT_CANONICALIZE) == KDC_OPT_CANONICALIZE);
    assert(as_req->client->realm.length == realm->length);

    cmp = memcmp(as_req->client->realm.data, realm->data, realm->length);
    assert(cmp == 0);

    /* Remove the canonicalize flag. */
    as_req->kdc_options &= ~KDC_OPT_CANONICALIZE;

    /* Create new message for the KDC. */
    code = encode_krb5_as_req(as_req, new_message_out);
    assert_krb5_error_code(code);

    krb5_free_kdc_req(context, as_req);

    return 0;
}

static krb5_error_code
krb5_recv_as_rep_test(krb5_context context,
                      void *data,
                      krb5_error_code kdc_retval,
                      const krb5_data *realm,
                      const krb5_data *message,
                      const krb5_data *reply,
                      krb5_data **new_reply)
{
    krb5_kdc_rep *as_rep;
    krb5_error_code code;

    assert(krb5_is_as_rep(reply));

    code = decode_krb5_as_rep(reply, &as_rep);
    assert_krb5_error_code(code);

    assert(as_rep->msg_type == KRB5_AS_REP);
    assert(as_rep->ticket->enc_part.kvno == 1);

    assert(krb5_c_valid_enctype(as_rep->ticket->enc_part.enctype));

    krb5_free_kdc_rep(context, as_rep);

    return kdc_retval;
}

/* Create a fake error reply. */

static krb5_error_code
krb5_send_error_test(krb5_context context,
                     void *data,
                     const krb5_data *realm,
                     const krb5_data *message,
                     krb5_data **new_message_out,
                     krb5_data **reply_out)
{
    krb5_data text = {
        .magic = 0,
        .length = 16,
        .data = "CLIENT_NOT_FOUND",
    };
    krb5_data e_data = {
        .magic = 0,
    };
    krb5_error krb_error;
    krb5_principal client, server;
    krb5_error_code code;
    char realm_str[realm->length + 1];
    char princ_str[128] = {0};

    memcpy(realm_str, realm->data, realm->length);
    realm_str[sizeof(realm_str) - 1] = '\0';

    snprintf(princ_str, sizeof(princ_str), "invalid@%s", realm_str);
    code = krb5_parse_name(ctx, princ_str, &client);
    assert_krb5_error_code(code);

    snprintf(princ_str, sizeof(princ_str), "krbtgt@%s", realm_str);
    code = krb5_parse_name(ctx, princ_str, &server);
    assert_krb5_error_code(code);

    krb_error = (krb5_error) {
        .magic = 0,
        .ctime = 1971196337,
        .susec = 97008,
        .stime = 1458219390,
        .error = 6,
        .client = client,
        .server = server,
        .text = text,
        .e_data = e_data,
    };

    code = encode_krb5_error(&krb_error, reply_out);
    assert_krb5_error_code(code);

    return 0;
}

static krb5_error_code
krb5_recv_error_test(krb5_context context,
                     void *data,
                     krb5_error_code kdc_retval,
                     const krb5_data *realm,
                     const krb5_data *message,
                     const krb5_data *reply,
                     krb5_data **new_reply)
{
    /*
     * The krb5_send_error_test error test already creates a reply so this
     * hook should not be executed.
     */
    abort();
}

/* Modify KDC reply */

static krb5_error_code
krb5_recv_modify_reply(krb5_context context,
                       void *data,
                       krb5_error_code kdc_retval,
                       const krb5_data *realm,
                       const krb5_data *message,
                       const krb5_data *reply,
                       krb5_data **new_reply)
{
    krb5_kdc_rep *as_rep;
    krb5_error_code code;

    assert(krb5_is_as_rep(reply));

    code = decode_krb5_as_rep(reply, &as_rep);
    assert_krb5_error_code(code);

    as_rep->msg_type = KRB5_TGS_REP;

    code = encode_krb5_as_rep(as_rep, new_reply);
    assert_krb5_error_code(code);

    krb5_free_kdc_rep(context, as_rep);

    return kdc_retval;
}

static krb5_error_code
krb5_send_return_value_test(krb5_context context,
                            void *data,
                            const krb5_data *realm,
                            const krb5_data *message,
                            krb5_data **new_message_out,
                            krb5_data **reply_out)
{
    krb5_error_code code;

    assert(data != NULL);

    code = *(krb5_error_code *)data;

    return code;
}

static krb5_error_code
krb5_recv_return_value_test(krb5_context context,
                            void *data,
                            krb5_error_code kdc_retval,
                            const krb5_data *realm,
                            const krb5_data *message,
                            const krb5_data *reply,
                            krb5_data **new_reply)
{
    krb5_error_code code;

    assert(data != NULL);

    code = *(krb5_error_code *)data;

    return code;
}

int
main(int argc, char *argv[])
{
    const char *principal, *password;
    krb5_principal client;
    krb5_get_init_creds_opt *opts = NULL;
    krb5_creds creds = {
        .magic = 0,
    };
    krb5_error_code test_return_code;
    krb5_error_code code;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s princname password\n", argv[0]);
        exit(1);
    }
    principal = argv[1];
    password = argv[2];

    /* Init the krb5 context. */
    code = krb5_init_context(&ctx);
    assert_krb5_error_code(code);

    /* Set the canonicalize flag. */
    code = krb5_get_init_creds_opt_alloc(ctx, &opts);
    assert_krb5_error_code(code);

    krb5_get_init_creds_opt_set_canonicalize(opts, 1);

    /* Create a krb5 principal. */
    code = krb5_parse_name(ctx, principal, &client);
    assert_krb5_error_code(code);

    /* Set sendto_kdc hooks. */
    krb5_set_kdc_send_hook(ctx, krb5_send_as_req_test, NULL);
    krb5_set_kdc_recv_hook(ctx, krb5_recv_as_rep_test, NULL);

    /*
     * Init with the traditional interface. This will fail, the library will
     * detect that we modified the message.
     */
    code = krb5_get_init_creds_password(ctx,
                                        &creds,
                                        client,
                                        password,
                                        NULL,
                                        NULL,
                                        0,
                                        NULL,
                                        opts);
    assert(code == KRB5_KDCREP_MODIFIED);

    krb5_get_init_creds_opt_free(ctx, opts);
    opts = NULL;
    krb5_free_cred_contents(ctx, &creds);

    /* Use hooks to directly return an error packet. */

    krb5_set_kdc_send_hook(ctx, krb5_send_error_test, NULL);
    krb5_set_kdc_recv_hook(ctx, krb5_recv_error_test, NULL);

    code = krb5_get_init_creds_password(ctx,
                                        &creds,
                                        client,
                                        password,
                                        NULL,
                                        NULL,
                                        0,
                                        NULL,
                                        NULL);
    assert(code == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN);

    krb5_free_cred_contents(ctx, &creds);

    /* Use the post receive hook to modify the KDC reply */

    krb5_set_kdc_send_hook(ctx, NULL, NULL);
    krb5_set_kdc_recv_hook(ctx, krb5_recv_modify_reply, NULL);

    code = krb5_get_init_creds_password(ctx,
                                        &creds,
                                        client,
                                        password,
                                        NULL,
                                        NULL,
                                        0,
                                        NULL,
                                        NULL);
    assert(code == KRB5KRB_AP_ERR_MSG_TYPE);

    krb5_free_cred_contents(ctx, &creds);

    /* Test if the user data pointer works in the pre send hook. */

    test_return_code = KRB5KDC_ERR_PREAUTH_FAILED;

    krb5_set_kdc_send_hook(ctx, krb5_send_return_value_test, &test_return_code);
    krb5_set_kdc_recv_hook(ctx, NULL, NULL);

    code = krb5_get_init_creds_password(ctx,
                                        &creds,
                                        client,
                                        password,
                                        NULL,
                                        NULL,
                                        0,
                                        NULL,
                                        NULL);
    assert(code == KRB5KDC_ERR_PREAUTH_FAILED);

    krb5_free_cred_contents(ctx, &creds);

    /* Test if the user data pointer works in the post receive hook. */

    test_return_code = KRB5KDC_ERR_NULL_KEY;

    krb5_set_kdc_send_hook(ctx, NULL, NULL);
    krb5_set_kdc_recv_hook(ctx, krb5_recv_return_value_test, &test_return_code);

    code = krb5_get_init_creds_password(ctx,
                                        &creds,
                                        client,
                                        password,
                                        NULL,
                                        NULL,
                                        0,
                                        NULL,
                                        NULL);
    assert(code == KRB5KDC_ERR_NULL_KEY);

    krb5_free_cred_contents(ctx, &creds);

    krb5_free_principal(ctx, client);
    krb5_free_context(ctx);

    return 0;
}
