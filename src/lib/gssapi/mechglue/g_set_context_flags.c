/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/lib/gssapi/mechglue/g_set_context_flags.c - set ctx flags */
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


#include "mglueP.h"

/*
 * Defined:
 * https://tools.ietf.org/html/draft-ietf-kitten-channel-bound-flag-03
 *
 * Section 2.2
 *
 * See src/lib/gssapi/generic/gssapi_ext.h for type definitions.
 */
OM_uint32 KRB5_CALLCONV
gss_set_context_flags(OM_uint32 *minor_status, gss_ctx_id_t context,
                      uint64_t req_flags, uint64_t ret_flags_understood)
{
    gss_union_ctx_id_t ctx = (gss_union_ctx_id_t)context;

    if (minor_status != NULL)
        *minor_status = 0;
    if (minor_status == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    if (context == GSS_C_NO_CONTEXT)
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;

    if (GSSINT_CHK_LOOP(ctx))
        return GSS_S_NO_CONTEXT;

    ctx->req_flags = req_flags;
    ctx->ret_flags_understood = ret_flags_understood;
    return GSS_S_COMPLETE;
}
