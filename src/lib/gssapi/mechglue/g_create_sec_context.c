/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/lib/gssapi/mechglue/g_create_sec_context.c - create empty union ctx */
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>
#include <time.h>

/*
 * Defined:
 * https://tools.ietf.org/html/draft-ietf-kitten-channel-bound-flag-01
 *
 * Section 2.1
 *
 * See src/lib/gssapi/generic/gssapi_ext.h for type definitions.
 */
OM_uint32 KRB5_CALLCONV
gss_create_sec_context(OM_uint32 *minor_status, gss_ctx_id_t *context)
{
    gss_union_ctx_id_t union_ctx;

    if (context == NULL)
        return GSS_S_FAILURE;

    union_ctx = calloc(1, sizeof(gss_union_ctx_id_desc));
    if (union_ctx == NULL) {
        if (minor_status != NULL)
            *minor_status = ENOMEM;
        return GSS_S_UNAVAILABLE;
    }

    union_ctx->loopback = union_ctx;

    *context = (gss_ctx_id_t)union_ctx;

    if (minor_status != NULL)
        *minor_status = 0;

    return GSS_S_COMPLETE;
}
