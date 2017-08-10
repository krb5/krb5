/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/lib/gssapi/krb5/set_context_flags.c - set ctx flags */
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

#include "k5-int.h"
#include "gssapiP_krb5.h"

#include <stdlib.h>

OM_uint32 KRB5_CALLCONV
krb5_gss_set_context_flags(OM_uint32 *minor_status, gss_ctx_id_t context,
                           uint64_t req_flags, uint64_t ret_flags_understood)
{
    krb5_gss_ctx_id_t ctx;

    if (context == GSS_C_NO_CONTEXT)
        return GSS_S_FAILURE | GSS_S_NO_CONTEXT;

    if (minor_status != NULL)
        *minor_status = 0;

    ctx = (krb5_gss_ctx_id_t)context;
    if (ctx->magic != KG_CONTEXT)
        return GSS_S_FAILURE | GSS_S_NO_CONTEXT;

    ctx->req_flags = req_flags;
    ctx->ret_flags_understood = ret_flags_understood;

    return GSS_S_COMPLETE;
}
