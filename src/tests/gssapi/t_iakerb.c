/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/gssapi/t_iakerb.c - IAKERB tests */
/*
 * Copyright (C) 2024 by the Massachusetts Institute of Technology.
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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "common.h"

static uint8_t
realm_query[] = {
    /* ASN.1 wrapper for IAKERB mech */
    0x60, 0x10,
    0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x02, 0x05,
    /* IAKERB_PROXY token type */
    0x05, 0x01,
    /* IAKERB-HEADER with empty target-realm */
    0x30, 0x04,
    0xA1, 0x02, 0x0C, 0x00
};

static uint8_t
realm_response[] = {
    /* ASN.1 wrapper for IAKERB mech */
    0x60, 0x1B,
    0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x02, 0x05,
    /* IAKERB_PROXY token type */
    0x05, 0x01,
    /* IAKERB-HEADER with configured realm */
    0x30, 0x0F,
    0xA1, 0x0D, 0x0C, 0x0B,
    'K', 'R', 'B', 'T', 'E', 'S', 'T', '.', 'C', 'O', 'M'
};

int
main(void)
{
    OM_uint32 major, minor;
    gss_cred_id_t cred;
    gss_buffer_desc in, out;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;

    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, 0, &mechset_iakerb,
                             GSS_C_ACCEPT, &cred, NULL, NULL);
    check_gsserr("gss_acquire_cred", major, minor);

    in.value = realm_query;
    in.length = sizeof(realm_query);
    major = gss_accept_sec_context(&minor, &ctx, cred, &in,
                                   GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL, &out,
                                   NULL, NULL, NULL);
    check_gsserr("gss_accept_sec_context", major, minor);
    assert(out.length == sizeof(realm_response));
    assert(memcmp(out.value, realm_response, out.length) == 0);

    gss_release_buffer(&minor, &out);
    gss_delete_sec_context(&minor, &ctx, NULL);
    gss_release_cred(&minor, &cred);
    return 0;
}
