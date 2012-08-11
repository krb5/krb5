/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/gssapi/t_export_name.c - Test program for gss_export_name behavior */
/*
 * Copyright 2012 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * Test program for gss_export_name, intended to be run from a Python test
 * script.  Imports a name, canonicalizes it to a mech, exports it,
 * re-imports/exports it to compare results, and then prints the hex form of
 * the exported name followed by a newline.
 *
 * Usage: ./t_export_name [-k|-s] user:username|krb5:princ|host:service@host
 *
 * The name is imported as a username, krb5 principal, or hostbased name.
 * By default or with -k, the name is canonicalized to the krb5 mech; -s
 * indicates SPNEGO instead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi/gssapi_krb5.h>

static gss_OID_desc spnego_mech = { 6, "\053\006\001\005\005\002" };

static void
display_status_1(const char *m, OM_uint32 code, int type)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    msg_ctx = 0;
    while (1) {
        maj_stat = gss_display_status(&min_stat, code,
                                      type, GSS_C_NULL_OID,
                                      &msg_ctx, &msg);
        fprintf(stderr, "%s: %s\n", m, (char *)msg.value);
        (void) gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }
}

static void
gsserr(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
    display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
    display_status_1(msg, min_stat, GSS_C_MECH_CODE);
    exit(1);
}

static void
print_hex(FILE *fp, gss_buffer_t buf)
{
    size_t i;
    const unsigned char *bytes = buf->value;

    for (i = 0; i < buf->length; i++)
        printf("%02X", bytes[i]);
    printf("\n");
}

static void
usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s [-k|-s] user:username|krb5:princ|gss:service@host\n",
            progname);
    exit(1);
}

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_OID mech = (gss_OID)gss_mech_krb5, nametype;
    gss_name_t name, mechname, impname;
    gss_buffer_desc buf, buf2;
    const char *name_arg, *progname = argv[0];
    char opt;

    while (argc > 1 && argv[1][0] == '-') {
        opt = argv[1][1];
        argc--, argv++;
        if (opt == 'k')
            mech = (gss_OID)gss_mech_krb5;
        else if (opt == 's')
            mech = &spnego_mech;
        else
            usage(progname);
    }
    if (argc != 2)
        usage(progname);
    name_arg = argv[1];

    /* Import the name. */
    if (strncmp(name_arg, "user:", 5) == 0) {
        nametype = GSS_C_NT_USER_NAME;
        name_arg += 5;
    } else if (strncmp(name_arg, "krb5:", 5) == 0) {
        nametype = (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME;
        name_arg += 5;
    } else if (strncmp(name_arg, "host:", 5) == 0) {
        nametype = GSS_C_NT_HOSTBASED_SERVICE;
        name_arg += 5;
    } else {
        usage(progname);
    }
    buf.value = (char *)name_arg;
    buf.length = strlen(name_arg);
    major = gss_import_name(&minor, &buf, nametype, &name);
    if (GSS_ERROR(major))
        gsserr("gss_import_name", major, minor);

    /* Canonicalize and export the name. */
    major = gss_canonicalize_name(&minor, name, mech, &mechname);
    if (GSS_ERROR(major))
        gsserr("gss_canonicalize_name", major, minor);
    major = gss_export_name(&minor, mechname, &buf);
    if (GSS_ERROR(major))
        gsserr("gss_export_name", major, minor);

    /* Import and re-export the name, and compare the results. */
    major = gss_import_name(&minor, &buf, GSS_C_NT_EXPORT_NAME, &impname);
    if (GSS_ERROR(major))
        gsserr("gss_export_name", major, minor);
    major = gss_export_name(&minor, impname, &buf2);
    if (GSS_ERROR(major))
        gsserr("gss_export_name", major, minor);
    if (buf.length != buf2.length ||
        memcmp(buf.value, buf2.value, buf.length) != 0) {
        fprintf(stderr, "Mismatched results:\n");
        print_hex(stderr, &buf);
        print_hex(stderr, &buf2);
        return 1;
    }

    print_hex(stdout, &buf);

    (void)gss_release_name(&minor, &name);
    (void)gss_release_name(&minor, &mechname);
    (void)gss_release_buffer(&minor, &buf);
    (void)gss_release_buffer(&minor, &buf2);
    return 0;
}
