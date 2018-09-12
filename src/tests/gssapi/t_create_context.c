/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/tests/gssapi/t_create_context.c - test create_sec_context */
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
 * This test program verifies that the gss_create_sec_context() can create
 * empty contexts, that gss_set_context_flags() can interpret them, and that
 * gss_delete_sec_context() can correctly free the structures.
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
t_gss_create_context()
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_union_ctx_id_t union_check;
    gss_ctx_id_t *context_handle = NULL;

    maj_stat = gss_create_sec_context(&min_stat, NULL);
    assert(maj_stat != GSS_S_COMPLETE);

    maj_stat = gss_create_sec_context(&min_stat, &context);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);
    assert(context != GSS_C_NO_CONTEXT);

    union_check = (gss_union_ctx_id_t)context;
    assert(union_check != NULL);
    assert(union_check == union_check->loopback);
    assert(union_check->internal_ctx_id == NULL);
    assert(union_check->req_flags == 0);
    assert(union_check->ret_flags_understood == 0);

    free(union_check);

    maj_stat = gss_create_sec_context(&min_stat, context_handle);
    assert(maj_stat != GSS_S_COMPLETE);

    context_handle = malloc(sizeof(gss_ctx_id_t));
    if (context_handle == NULL) {
        fprintf(stderr, "MALLOC failed. OOM.\n");
        return 1;
    }

    maj_stat = gss_create_sec_context(&min_stat, context_handle);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);

    assert(*context_handle != NULL);

    union_check = (gss_union_ctx_id_t)*context_handle;
    assert(union_check != NULL);
    assert(union_check == union_check->loopback);
    assert(union_check->internal_ctx_id == NULL);
    assert(union_check->req_flags == 0);
    assert(union_check->ret_flags_understood == 0);

    free(union_check);
    free(context_handle);

    return 0;
}

static int
t_gss_set_context_flags()
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_union_ctx_id_t union_check;

    maj_stat = gss_set_context_flags(&min_stat, context, 1, 2);
    assert(maj_stat != GSS_S_COMPLETE);

    maj_stat = gss_create_sec_context(&min_stat, &context);
    check_gsserr("t_gss_set_context_flags(1)", maj_stat, min_stat);

    maj_stat = gss_set_context_flags(&min_stat, context, 1, 2);
    check_gsserr("t_gss_set_context_flags(2)", maj_stat, min_stat);

    union_check = (gss_union_ctx_id_t)context;
    assert(union_check != NULL);
    assert(union_check == union_check->loopback);
    assert(union_check->internal_ctx_id == NULL);
    assert(union_check->req_flags == 1);
    assert(union_check->ret_flags_understood == 2);

    maj_stat = gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
    check_gsserr("t_gss_set_context_flags(3)", maj_stat, min_stat);

    context = NULL;
    maj_stat = gss_set_context_flags(&min_stat, context, 1, 2);
    assert(maj_stat != GSS_S_COMPLETE);

    return 0;
}

static int
t_gss_create_delete_integration()
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc out_buf;

    maj_stat = gss_create_sec_context(&min_stat, &context);
    check_gsserr("t_gss_create_delete_integration()", maj_stat, min_stat);

    assert(context != GSS_C_NO_CONTEXT);

    maj_stat = gss_delete_sec_context(&min_stat, &context, &out_buf);
    check_gsserr("t_gss_create_delete_integration()", maj_stat, min_stat);

    assert(out_buf.length == 0);

    return 0;
}


int
main(int argc, char *argv[])
{
    assert(t_gss_create_context() == 0);
    printf("t_gss_create_context()... ok\n");

    assert(t_gss_set_context_flags() == 0);
    printf("t_gss_set_context_flags()... ok\n");

    assert(t_gss_create_delete_integration() == 0);
    printf("t_gss_create_delete_integration()... ok\n");

    return 0;
}
