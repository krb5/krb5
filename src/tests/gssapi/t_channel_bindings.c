/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/tests/gssapi/t_channel_bindings.c - test channel binding */
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
 * This test program verifies that the new chanel binding extensions work as
 * specified in:
 *
 * https://tools.ietf.org/html/draft-ietf-kitten-channel-bound-flag-03
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
t_gss_channel_bindings_check(gss_name_t target_name,
                             OM_uint32 req_flags,
                             OM_uint32 init_ret_flags_understood,
                             OM_uint32 accept_ret_flags_understood,
                             gss_channel_bindings_t init_cb,
                             gss_channel_bindings_t accept_cb,
                             OM_uint32 e_init_status,
                             OM_uint32 e_accept_status,
                             OM_uint32 m_init_ret_flags,
                             OM_uint32 e_init_ret_flags,
                             OM_uint32 m_accept_ret_flags,
                             OM_uint32 e_accept_ret_flags)
{
    /* Check that both init/accept_sec_context() accept empty sec contexts */
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    OM_uint32 init_ret_flags = 0;
    OM_uint32 accept_ret_flags = 0;
    OM_uint32 init_maj_stat = GSS_S_CONTINUE_NEEDED;
    OM_uint32 init_min_stat = 0;
    OM_uint32 accept_maj_stat = GSS_S_CONTINUE_NEEDED;
    OM_uint32 accept_min_stat = 0;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_buffer_desc accept_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("gss_acquire_cred()", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &init_context);
    check_gsserr("gss_create_sec_context(init)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &accept_context);
    check_gsserr("gss_create_sec_context(accept)", maj_stat, min_stat);

    maj_stat = gss_set_context_flags(&min_stat, init_context, req_flags,
                                     init_ret_flags_understood);
    check_gsserr("gss_set_context_flags(init)", maj_stat, min_stat);

    maj_stat = gss_set_context_flags(&min_stat, accept_context, req_flags,
                                     accept_ret_flags_understood);
    check_gsserr("gss_set_context_flags(accept)", maj_stat, min_stat);

    init_token.length = 0;
    init_token.value = NULL;
    accept_token.length = 0;
    accept_token.value = NULL;

    do {
        init_maj_stat = gss_init_sec_context(&init_min_stat,
                                             GSS_C_NO_CREDENTIAL,
                                             &init_context, target_name, mech,
                                             0, 0, init_cb, &accept_token,
                                             NULL, &init_token,
                                             &init_ret_flags, NULL);

        if (accept_maj_stat != GSS_S_CONTINUE_NEEDED)
            break;

        accept_maj_stat = gss_accept_sec_context(&accept_min_stat,
                                                 &accept_context,
                                                 cred, &init_token,
                                                 accept_cb, NULL, NULL,
                                                 &accept_token,
                                                 &accept_ret_flags, NULL,
                                                 NULL);

        if (init_maj_stat != GSS_S_CONTINUE_NEEDED)
            break;
    } while (1);

    if (e_init_status == GSS_S_COMPLETE && init_maj_stat != e_init_status) {
        check_gsserr("gss_init_sec_context()", init_maj_stat,
                     init_min_stat);
    }

    if (init_maj_stat != e_init_status)
        return 1;

    if (e_accept_status == GSS_S_COMPLETE &&
        accept_maj_stat != e_accept_status) {
        check_gsserr("gss_accept_sec_context()", accept_maj_stat,
                     accept_min_stat);
    }

    if (accept_maj_stat != e_accept_status)
        return 2;

    if ((init_ret_flags & m_init_ret_flags) != e_init_ret_flags)
        return 3;

    if ((accept_ret_flags & m_accept_ret_flags) != e_accept_ret_flags)
        return 4;

    (void)gss_release_cred(&min_stat, &cred);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_release_buffer(&min_stat, &accept_token);

    (void)gss_delete_sec_context(&min_stat, &accept_context, NULL);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}


int
main(int argc, char *argv[])
{
    gss_name_t target_name;
    OM_uint32 min_stat;
    gss_channel_bindings_t cb;
    gss_channel_bindings_t cb_fail;
    gss_channel_bindings_t cb_none;
    OM_uint32 f_mutual;
    OM_uint32 f_cb;
    OM_uint32 f_both;
    int call_val = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s targetname\n", argv[0]);
        return 1;
    }
    target_name = import_name(argv[1]);

    cb = calloc(sizeof(struct gss_channel_bindings_struct), 1);
    cb_fail = calloc(sizeof(struct gss_channel_bindings_struct), 1);
    cb_none = GSS_C_NO_CHANNEL_BINDINGS;
    assert(cb != NULL);
    assert(cb_fail != NULL);

    cb->initiator_addrtype = GSS_C_AF_NULLADDR;
    cb->initiator_address.length = 0;
    cb->acceptor_addrtype = GSS_C_AF_NULLADDR;
    cb->acceptor_address.length = 0;
    cb->application_data.length = 4;
    cb->application_data.value = "test";

    cb_fail->initiator_addrtype = GSS_C_AF_NULLADDR;
    cb_fail->initiator_address.length = 0;
    cb_fail->acceptor_addrtype = GSS_C_AF_NULLADDR;
    cb_fail->acceptor_address.length = 0;
    cb_fail->application_data.length = 4;
    cb_fail->application_data.value = "fail";

    f_mutual = GSS_C_MUTUAL_FLAG;
    f_cb = GSS_C_CHANNEL_BOUND_FLAG;
    f_both = f_mutual | f_cb;

    /* https://tools.ietf.org/html/draft-ietf-kitten-channel-bound-flag-03 */

    /* Section 3 - first circle */
    /*
     * Note that the number of trips is undefined. Thus, setting the mutual
     * flag ensures a full round trip before the context is established,
     * causing init to fail with accept.
     */
    call_val = t_gss_channel_bindings_check(
        target_name,
        f_both,
        0,
        0,
        cb,
        cb_fail,
        GSS_S_FAILURE,
        GSS_S_BAD_BINDINGS,
        f_cb,
        0,
        f_cb,
        0);
    assert(call_val == 0);

    /* Section 3 - second circle */
    call_val = t_gss_channel_bindings_check(
        target_name,
        f_both,
        0,
        0,
        cb_none,
        cb,
        GSS_S_FAILURE,
        GSS_S_BAD_BINDINGS,
        f_cb,
        0,
        f_cb,
        0);
    assert(call_val == 0);

    call_val = t_gss_channel_bindings_check(
        target_name,
        f_both,
        0,
        0,
        cb,
        cb,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        f_cb,
        0,
        f_cb,
        f_cb);
    assert(call_val == 0);

    /* Section 3 - third circle */
    call_val = t_gss_channel_bindings_check(
        target_name,
        f_both,
        0,
        0,
        cb,
        cb_none,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        f_cb,
        0,
        f_cb,
        0);
    assert(call_val == 0);

    /* Section 3 - fourth circle */
    call_val = t_gss_channel_bindings_check(
        target_name,
        f_both,
        f_cb,
        f_cb,
        cb,
        cb_none,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        f_cb,
        0,
        f_cb,
        0);
    assert(call_val == 0);

    call_val = t_gss_channel_bindings_check(
        target_name,
        f_both,
        f_cb,
        f_cb,
        cb_none,
        cb_none,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        f_cb,
        0,
        f_cb,
        0);
    assert(call_val == 0);

    call_val = t_gss_channel_bindings_check(
        target_name,
        f_both,
        f_cb,
        f_cb,
        cb_none,
        cb,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        f_cb,
        0,
        f_cb,
        0);
    assert(call_val == 0);

    call_val = t_gss_channel_bindings_check(
        target_name,
        f_both,
        f_cb,
        f_cb,
        cb,
        cb,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        f_cb,
        0,
        f_cb,
        f_cb);
    assert(call_val == 0);

    (void)gss_release_name(&min_stat, &target_name);

    return 0;
}
