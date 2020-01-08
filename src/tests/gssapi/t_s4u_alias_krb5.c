/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2019 by the Massachusetts Institute of Technology.
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

/*
 * Usage: ./s4u_alias_krb5 client alias target
 *
 * The default ccache contains a TGT for the intermediate service.
 * An S4U2Self is made for client using alias as server name.  The
 * resulting ticket is used to make an S4U2Proxy request to target.
 */

#include <k5-int.h>

static krb5_context ctx;

static void
check(krb5_error_code code)
{
    const char *errmsg;

    if (code) {
        errmsg = krb5_get_error_message(ctx, code);
        fprintf(stderr, "%s\n", errmsg);
        krb5_free_error_message(ctx, errmsg);
        exit(1);
    }
}


static krb5_error_code
get_self_cred_from_kdc(krb5_context context,
                       krb5_flags options,
                       krb5_ccache ccache,
                       krb5_creds *in_creds,
                       krb5_principal impersonate,
                       krb5_creds **out_creds)
{
    krb5_error_code code;
    krb5_creds *out = NULL;
    krb5_tkt_creds_context tctx = NULL;

    code = krb5_tkt_creds_init(context, ccache, in_creds, options, &tctx);
    if (code)
        goto cleanup;

    code = krb5_tkt_creds_set_impersonate(context, tctx, impersonate);
    if (code)
        goto cleanup;

    code = krb5_tkt_creds_get(context, tctx);
    if (code)
        goto cleanup;

    /* Allocate a container. */
    out = k5alloc(sizeof(krb5_creds), &code);
    if (out == NULL)
        goto cleanup;

    code = krb5_tkt_creds_get_creds(context, tctx, out);
    if (code) {
        free(out);
        goto cleanup;
    }

    *out_creds = out;

cleanup:
    krb5_tkt_creds_free(context, tctx);
    return code;
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_ccache defcc;
    krb5_principal client, me, alias_me, target;
    krb5_creds in_creds = {0}, *out_creds = NULL;
    krb5_flags options;

    assert(argc == 4);
    check(krb5_init_context(&context));

    check(krb5_parse_name(context, argv[1], &client));
    check(krb5_parse_name_flags(context, argv[2],
                                KRB5_PRINCIPAL_PARSE_NO_REALM,
                                &alias_me));
    check(krb5_parse_name_flags(context, argv[3],
                                KRB5_PRINCIPAL_PARSE_NO_REALM,
                                &target));

    /* Open the default ccache and determine me */
    check(krb5_cc_default(context, &defcc));
    check(krb5_cc_get_principal(context, defcc, &me));

    options = KRB5_GC_NO_STORE | KRB5_GC_CANONICALIZE;

    /* S4U2Self using alias server name */
    in_creds.client = me;
    in_creds.server = alias_me;
    check(get_self_cred_from_kdc(context, options, defcc, &in_creds, client,
                                 &out_creds));

    /* S4U2Proxy using second ticket with alias server name */
    in_creds.client = me;
    in_creds.server = target;
    in_creds.second_ticket = out_creds->ticket;
    out_creds->ticket = empty_data();
    krb5_free_creds(context, out_creds);
    check(krb5_get_credentials(context, KRB5_GC_CONSTRAINED_DELEGATION |
                               options, defcc, &in_creds, &out_creds));
    free(in_creds.second_ticket.data);

    krb5_cc_close(context, defcc);
    krb5_free_principal(context, client);
    krb5_free_principal(context, me);
    krb5_free_principal(context, alias_me);
    krb5_free_principal(context, target);
    krb5_free_creds(context, out_creds);
    krb5_free_context(context);
    return 0;
}
