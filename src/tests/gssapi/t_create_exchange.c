/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/tests/gssapi/t_create_exchange.c - test create_sec_context */
/*
 * Copyright (C) 2017 by Red Hat, Inc.
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
 * This test program verifies that the gss_create_sec_context(),
 * gss_set_context_flags(), gss_init_sec_context(), and
 * gss_accept_sec_context() all interoperate correctly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "k5-int.h"
#include "k5-platform.h"
#include "common.h"
#include "mglueP.h"
#include "gssapiP_krb5.h"
#include "gssapi_ext.h"

static int
t_gss_handshake_create_init(gss_name_t target_name)
{
    /* Check that init_sec_context() accepts an empty sec context */
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc accept_token;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("t_gss_handshake_create_init(0)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &init_context);
    check_gsserr("t_gss_handshake_create_init(1)", maj_stat, min_stat);

    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech, 0, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_create_init(2)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    maj_stat = gss_accept_sec_context(&min_stat, &accept_context,
                                      cred, &init_token,
                                      GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                      NULL, &accept_token, NULL, NULL, NULL);
    check_gsserr("t_gss_handshake_create_init(3)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_release_buffer(&min_stat, &accept_token);

    (void)gss_delete_sec_context(&min_stat, &accept_context, NULL);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}


static int
t_gss_handshake_create_accept(gss_name_t target_name)
{
    /* Check that accept_sec_context() accepts an empty sec context */
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc accept_token;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("t_gss_handshake_create_accept(0)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &accept_context);
    check_gsserr("t_gss_handshake_create_accept(1)", maj_stat, min_stat);

    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech, 0, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_create_accept(2)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    maj_stat = gss_accept_sec_context(&min_stat, &accept_context,
                                      cred, &init_token,
                                      GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                      NULL, &accept_token, NULL, NULL, NULL);
    check_gsserr("t_gss_handshake_create_accept(3)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_release_buffer(&min_stat, &accept_token);

    (void)gss_delete_sec_context(&min_stat, &accept_context, NULL);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}


static int
t_gss_handshake_create_both(gss_name_t target_name)
{
    /* Check that both init/accept_sec_context() accept empty sec contexts */
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc accept_token;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("t_gss_handshake_create_both(0)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &init_context);
    check_gsserr("t_gss_handshake_create_both(1)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &accept_context);
    check_gsserr("t_gss_handshake_create_both(2)", maj_stat, min_stat);

    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech, 0, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_create_both(3)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    maj_stat = gss_accept_sec_context(&min_stat, &accept_context,
                                      cred, &init_token,
                                      GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                      NULL, &accept_token, NULL, NULL, NULL);
    check_gsserr("t_gss_handshake_create_both(4)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    (void)gss_release_buffer(&min_stat, &init_token);

    (void)gss_delete_sec_context(&min_stat, &accept_context, NULL);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}


static int
t_krb5_init_set_req_flags(gss_name_t target_name)
{
    /*
     * Check that req_flags set on the context appear on the context from
     * init_sec_context.
     */
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_union_ctx_id_t union_ctx;
    krb5_gss_ctx_id_t krb5_outer_context;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("t_gss_handshake_create_both(0)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &init_context);
    check_gsserr("t_gss_handshake_create_both(1)", maj_stat, min_stat);

    maj_stat = gss_set_context_flags(&min_stat, init_context,
                                     GSS_C_SEQUENCE_FLAG, 0);
    assert(maj_stat == GSS_S_COMPLETE);

    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech, 0, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_create_both(2)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    union_ctx = (gss_union_ctx_id_t)(init_context);
    assert(union_ctx != NULL);

    assert(union_ctx->internal_ctx_id != NULL);
    krb5_outer_context = (krb5_gss_ctx_id_t)(union_ctx->internal_ctx_id);

    assert(krb5_outer_context != NULL);


    /*
     * Assert that our SEQUENCE flag was set correctly.
     */
    assert(krb5_outer_context->gss_flags & GSS_C_SEQUENCE_FLAG);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}


static int
t_krb5_init_override_set_req_flags(gss_name_t target_name)
{
    /*
     * Check that req_flags set on the context appear on the context from
     * init_sec_context, but not if they're set on init_sec_context.
     */
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_union_ctx_id_t union_ctx;
    krb5_gss_ctx_id_t krb5_outer_context;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("t_gss_handshake_create_both(0)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &init_context);
    check_gsserr("t_gss_handshake_create_both(1)", maj_stat, min_stat);

    maj_stat = gss_set_context_flags(&min_stat, init_context,
                                     GSS_C_SEQUENCE_FLAG, 0);
    assert(maj_stat == GSS_S_COMPLETE);

    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech,
                                    GSS_C_REPLAY_FLAG, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_create_both(2)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    union_ctx = (gss_union_ctx_id_t)(init_context);
    assert(union_ctx != NULL);

    assert(union_ctx->internal_ctx_id != NULL);
    krb5_outer_context = (krb5_gss_ctx_id_t)(union_ctx->internal_ctx_id);

    assert(krb5_outer_context != NULL);

    /*
     * Assert that our SEQUENCE flag was ignored, and that the replay flag
     * was set correctly.
     */
    assert(krb5_outer_context->gss_flags & GSS_C_REPLAY_FLAG);
    assert((krb5_outer_context->gss_flags & GSS_C_SEQUENCE_FLAG) == 0);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}


int
main(int argc, char *argv[])
{
    gss_name_t target_name;
    OM_uint32 min_stat;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s targetname\n", argv[0]);
        return 1;
    }
    target_name = import_name(argv[1]);

    assert(t_gss_handshake_create_init(target_name) == 0);
    printf("t_gss_handshake_create_init... ok\n");

    assert(t_gss_handshake_create_accept(target_name) == 0);
    printf("t_gss_handshake_create_accept.. ok\n");

    assert(t_gss_handshake_create_both(target_name) == 0);
    printf("t_gss_handshake_create_both... ok\n");

    assert(t_krb5_init_set_req_flags(target_name) == 0);
    printf("t_krb5_init_set_req_flags... ok\n");

    assert(t_krb5_init_override_set_req_flags(target_name) == 0);
    printf("t_krb5_init_override_set_req_flags... ok\n");

    (void)gss_release_name(&min_stat, &target_name);
    return 0;
}
