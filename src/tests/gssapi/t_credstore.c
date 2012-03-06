/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2011 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

static void
print_gss_status(int type, OM_uint32 code)
{
    OM_uint32 major, minor;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx = 0;

    do {
        major = gss_display_status(&minor, code, type,
                                   GSS_C_NULL_OID, &msg_ctx, &msg);
        if (major == 0) {
            fprintf(stdout, "%s. ", (char *)msg.value);
            major = gss_release_buffer(&minor, &msg);
        }
    } while (msg_ctx);
}

static void
print_status(char *msg, OM_uint32 major, OM_uint32 minor)
{
    fprintf(stdout, "%s: ", msg);
    print_gss_status(GSS_C_GSS_CODE, major);
    print_gss_status(GSS_C_MECH_CODE, minor);
    fprintf(stdout, "\n");
}

static void
usage(const char *name)
{
    fprintf(stderr,
            "Usage: %s <principal> [--cred_store {<key> <value>} ...]\n",
            name);
}

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_key_value_set_desc store;
    gss_buffer_desc buf;
    gss_name_t service = GSS_C_NO_NAME;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    int i, e;

    if (argc < 2 || ((argc - 3) % 2)) {
        usage(argv[0]);
        exit(1);
    }

    store.count = (argc - 3) / 2;
    store.elements = calloc(store.count,
                            sizeof(struct gss_key_value_element_struct));
    if (!store.elements) {
        fprintf(stderr, "OOM\n");
        exit(1);
    }

    if (argc > 2) {
        if (strcmp(argv[2], "--cred_store") != 0) {
            usage(argv[0]);
            exit(1);
        }

        for (i = 3, e = 0; i < argc; i += 2, e++) {
            store.elements[e].key = argv[i];
            store.elements[e].value = argv[i + 1];
            continue;
        }
    }

    /* First acquire default creds and try to store them in the cred store. */

    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                             GSS_C_INITIATE, &cred, NULL, NULL);
    if (major) {
        print_status("gss_acquire_cred(default user creds) failed",
                     major, minor);
        goto out;
    }

    major = gss_store_cred_into(&minor, cred, GSS_C_INITIATE,
                                GSS_C_NO_OID, 1, 0, &store, NULL, NULL);
    if (major) {
        print_status("gss_store_cred_in_store(default user creds) failed",
                     major, minor);
        goto out;
    }

    gss_release_cred(&minor, &cred);

    /* Then try to acquire creds from store. */

    buf.value = argv[1];
    buf.length = strlen(argv[1]);

    major = gss_import_name(&minor, &buf,
                            (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                            &service);
    if (major) {
        print_status("gss_import_name(principal) failed", major, minor);
        goto out;
    }

    major = gss_acquire_cred_from(&minor, service,
                                  0, GSS_C_NO_OID_SET, GSS_C_BOTH,
                                  &store, &cred, NULL, NULL);
    if (major) {
        print_status("gss_acquire_cred_from_store(principal) failed",
                     major, minor);
        goto out;
    }

    fprintf(stdout, "Cred Store Success\n");

    major = 0;

out:
    gss_release_name(&minor, &service);
    gss_release_cred(&minor, &cred);
    free(store.elements);
    return major;
}
