/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/fuzzing/fuzz_ccache.c - fuzzing harness for the FILE ccache parser */
/*
 * Copyright (C) 2026 by Arthur Chan. All rights reserved.
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
 * This harness fuzzes the FILE credential cache parser in
 * lib/krb5/ccache/cc_file.c.  The fuzz input is written verbatim to a
 * temporary file, which is then resolved as a "FILE:" ccache and read back;
 * then the cache's default principal is fetched and its credentials are
 * iterated to drive the parser (version, header, principal and credential
 * unmarshalling).
 */

#include <k5-int.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define kMinInputLength 2
#define kMaxInputLength 4096

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* krb5_init_context is expensive, so create the context once and reuse it. */
static krb5_context
get_context(void)
{
    static krb5_context context = NULL;
    static int initialized = 0;

    if (!initialized) {
        initialized = 1;
        if (krb5_init_context(&context) != 0)
            context = NULL;
    }
    return context;
}

/* Iterate over every credential in the cache to exercise the parser. */
static void
iterate_creds(krb5_context context, krb5_ccache ccache)
{
    krb5_error_code ret;
    krb5_cc_cursor cursor;
    krb5_creds cred;

    ret = krb5_cc_start_seq_get(context, ccache, &cursor);
    if (ret)
        return;

    while (krb5_cc_next_cred(context, ccache, &cursor, &cred) == 0)
        krb5_free_cred_contents(context, &cred);

    krb5_cc_end_seq_get(context, ccache, &cursor);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_ccache ccache;
    krb5_principal princ;
    char tmpl[] = "/tmp/fuzz_ccache.XXXXXX";
    char name[64];
    int fd;

    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    context = get_context();
    if (context == NULL)
        return 0;

    /* Write the fuzz input to a temporary file. */
    fd = mkstemp(tmpl);
    if (fd < 0)
        return 0;
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    snprintf(name, sizeof(name), "FILE:%s", tmpl);

    ret = krb5_cc_resolve(context, name, &ccache);
    if (ret) {
        unlink(tmpl);
        return 0;
    }

    /* Fetch the default principal, then walk the credentials. */
    ret = krb5_cc_get_principal(context, ccache, &princ);
    if (!ret)
        krb5_free_principal(context, princ);

    iterate_creds(context, ccache);

    krb5_cc_close(context, ccache);
    unlink(tmpl);

    return 0;
}
