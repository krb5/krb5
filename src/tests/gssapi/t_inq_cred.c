/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/gssapi/t_inq_cred.c - Test program for gss_inquire_cred behavior */
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
 * Test program for gss_inquire_cred, intended to be run from a Python test
 * script.  Acquires credentials, inquires them, and prints the resulting name
 * and lifetime.
 *
 * Usage: ./t_inq_cred [-k|-s] [-a|-b|-i] [initiatorprinc|gss:service@host]
 *
 * By default no mechanism is specified when acquiring credentials; -k
 * indicates the krb5 mech and -s indicates SPNEGO.  By default or with -i,
 * initiator credentials are acquired; -a indicates acceptor credentials and -b
 * indicates credentials of both types.  The credential is acquired with no
 * name by default; a krb5 principal name or host-based name (prefixed with
 * "gss:") may be supplied as an argument.
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
usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s [-k|-s] [-a|-b|-i] [princ|gss:service@host]\n",
            progname);
    exit(1);
}

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major, lifetime;
    gss_cred_usage_t cred_usage = GSS_C_INITIATE;
    gss_OID mech = GSS_C_NO_OID;
    gss_OID_set_desc mechs;
    gss_OID_set mechset = GSS_C_NO_OID_SET;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_name_t name = GSS_C_NO_NAME;
    gss_buffer_desc buf;
    const char *name_arg = NULL, *progname = argv[0];
    char opt;

    while (argc > 1 && argv[1][0] == '-') {
        opt = argv[1][1];
        argc--, argv++;
        if (opt == 'a')
            cred_usage = GSS_C_ACCEPT;
        else if (opt == 'b')
            cred_usage = GSS_C_BOTH;
        else if (opt == 'i')
            cred_usage = GSS_C_INITIATE;
        else if (opt == 'k')
            mech = (gss_OID)gss_mech_krb5;
        else if (opt == 's')
            mech = &spnego_mech;
        else
            usage(progname);
    }
    if (argc > 2)
        usage(progname);
    if (argc > 1)
        name_arg = argv[1];

    /* Import the name, if given. */
    if (name_arg != NULL && strncmp(name_arg, "gss:", 4) == 0) {
        /* Import as host-based service. */
        buf.value = (char *)name_arg + 4;
        buf.length = strlen((char *)buf.value);
        major = gss_import_name(&minor, &buf, GSS_C_NT_HOSTBASED_SERVICE,
                                &name);
        if (GSS_ERROR(major))
            gsserr("gss_import_name", major, minor);
    } else if (name_arg != NULL) {
        /* Import as krb5 principal name. */
        buf.value = (char *)name_arg;
        buf.length = strlen((char *)buf.value);
        major = gss_import_name(&minor, &buf,
                                (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &name);
        if (GSS_ERROR(major))
            gsserr("gss_import_name", major, minor);
    }

    if (mech != GSS_C_NO_OID) {
        mechs.elements = mech;
        mechs.count = 1;
        mechset = &mechs;
    }

    /* Acquire a credential. */
    major = gss_acquire_cred(&minor, name, GSS_C_INDEFINITE, mechset,
                             cred_usage, &cred, NULL, NULL);
    if (GSS_ERROR(major))
        gsserr("gss_acquire_cred", major, minor);

    /* Inquire about the credential. */
    (void)gss_release_name(&minor, &name);
    major = gss_inquire_cred(&minor, cred, &name, &lifetime, NULL, NULL);
    if (GSS_ERROR(major))
        gsserr("gss_inquire_cred", major, minor);

    /* Get a display form of the name. */
    buf.value = NULL;
    buf.length = 0;
    major = gss_display_name(&minor, name, &buf, NULL);
    if (GSS_ERROR(major))
        gsserr("gss_display_name", major, minor);

    printf("name: %.*s\n", (int)buf.length, (char *)buf.value);
    printf("lifetime: %d\n", (int)lifetime);

    (void)gss_release_cred(&minor, &cred);
    (void)gss_release_name(&minor, &name);
    (void)gss_release_buffer(&minor, &buf);
    return 0;
}
