/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/fuzzing/fuzz_gssapi.c */
/*
 * Copyright (C) 2024 by Arjun. All rights reserved.
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
 * Fuzzing harness implementation for krb5int_parse_enctype_list and
 * gss_oid_to_str, gss_str_to_oid.
 */

#include "autoconf.h"
#include <k5-int.h>
#include <gssapi/gssapi_krb5.h>

#define kMinInputLength 2
#define kMaxInputLength 1024

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void
enctype_list(char *data_in)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_enctype *ienc, zero = 0;

    ret = krb5_init_context(&context);
    if (ret)
        return;

    ret = krb5int_parse_enctype_list(context, "", data_in, &zero, &ienc);
    if (!ret)
        free(ienc);

    krb5_free_context(context);
}

static void
gss_oid(const uint8_t *data, size_t size)
{
    OM_uint32 minor;
    gss_buffer_desc buf;
    gss_OID_desc oid_desc;
    gss_OID oid;

    oid_desc.elements = (void *)data;
    oid_desc.length = size;

    gss_oid_to_str(&minor, &oid_desc, &buf);
    gss_release_buffer(&minor, &buf);

    buf.value = (void *)data;
    buf.length = size;

    gss_str_to_oid(&minor, &buf, &oid);
    gss_release_oid(&minor, &oid);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    krb5_error_code ret;
    char *data_in;

    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    data_in = k5memdup0(data, size, &ret);
    if (ret)
        return 0;

    enctype_list(data_in);
    gss_oid(data, size);

    free(data_in);

    return 0;
}
