/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/fuzzing/fuzz_keytab.c - fuzzing harness for the FILE keytab parser */
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
 * This harness fuzzes the FILE keytab parser in lib/krb5/keytab/kt_file.c.
 * The fuzz input is written verbatim to a temporary file, which is then
 * resolved as a "FILE:" keytab and read back; then each entry is iterated to
 * drive the parsing code (version header, and per-entry principal, key and
 * metadata unmarshalling).
 */

#include <k5-int.h>

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

/* Iterate over every entry in the keytab to exercise the parser. */
static void
iterate_entries(krb5_context context, krb5_keytab keytab)
{
    krb5_error_code ret;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;

    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret)
        return;

    while (krb5_kt_next_entry(context, keytab, &entry, &cursor) == 0)
        krb5_free_keytab_entry_contents(context, &entry);

    krb5_kt_end_seq_get(context, keytab, &cursor);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_keytab keytab;
    char tmpl[] = "/tmp/fuzz_keytab.XXXXXX";
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

    ret = krb5_kt_resolve(context, name, &keytab);
    if (ret) {
        unlink(tmpl);
        return 0;
    }

    iterate_entries(context, keytab);

    krb5_kt_close(context, keytab);
    unlink(tmpl);

    return 0;
}
