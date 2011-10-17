/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2011 by the Massachusetts Institute of Technology.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi/gssapi_krb5.h>

/*
 * Test program for acceptor names, intended to be run from a Python test
 * script.  Performs a one-token gss_init_sec_context/gss_accept_sec_context
 * exchange with the default initiator name, a specified principal name as
 * target name, and a specified host-based name as acceptor name (or
 * GSS_C_NO_NAME if no acceptor name is given).  If the exchange is successful,
 * queries the context for the acceptor name and prints it.  If any call is
 * unsuccessful, displays an error message.  Exits with status 0 if all
 * operations are successful, or 1 if not.
 *
 * Usage: ./t_accname targetname [acceptorname]
 */

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
display_status(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
    display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
    display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t acceptor_cred;
    gss_buffer_desc buf;
    gss_name_t target_name, acceptor_name = GSS_C_NO_NAME, real_acceptor_name;
    gss_buffer_desc token, tmp, namebuf;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s targetname [acceptorname]\n", argv[0]);
        return 1;
    }

    /* Import the target name as a krb5 principal name. */
    buf.value = argv[1];
    buf.length = strlen((char *)buf.value);
    major = gss_import_name(&minor, &buf, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                            &target_name);
    if (GSS_ERROR(major)) {
        display_status("gss_import_name(target_name)", major, minor);
        return 1;
    }

    /* Import the acceptor name as a host-based name. */
    if (argc >= 3) {
        buf.value = argv[2];
        buf.length = strlen((char *)buf.value);
        major = gss_import_name(&minor, &buf,
                                (gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
                                &acceptor_name);
        if (GSS_ERROR(major)) {
            display_status("gss_import_name(acceptor_name)", major, minor);
            return 1;
        }
    }

    /* Get acceptor cred. */
    major = gss_acquire_cred(&minor, acceptor_name, GSS_C_INDEFINITE,
                             GSS_C_NO_OID_SET, GSS_C_ACCEPT,
                             &acceptor_cred, NULL, NULL);
    if (GSS_ERROR(major)) {
        display_status("gss_acquire_cred", major, minor);
        return 1;
    }

    /* Create krb5 initiator context and get the first token. */
    token.value = NULL;
    token.length = 0;
    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL,
                                 &initiator_context, target_name,
                                 (gss_OID)gss_mech_krb5,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, NULL, &token, NULL, NULL);
    if (GSS_ERROR(major)) {
        display_status("gss_init_sec_context", major, minor);
        return 1;
    }

    /* Pass the token to gss_accept_sec_context. */
    tmp.value = NULL;
    tmp.length = 0;
    major = gss_accept_sec_context(&minor, &acceptor_context, acceptor_cred,
                                   &token, GSS_C_NO_CHANNEL_BINDINGS,
                                   NULL, NULL, &tmp, NULL, NULL, NULL);
    if (major != GSS_S_COMPLETE) {
        display_status("gss_accept_sec_context", major, minor);
        return 1;
    }

    major = gss_inquire_context(&minor, acceptor_context, NULL,
                                &real_acceptor_name, NULL, NULL, NULL, NULL,
                                NULL);
    if (GSS_ERROR(major)) {
        display_status("gss_inquire_context", major, minor);
        return 1;
    }

    namebuf.value = NULL;
    namebuf.length = 0;
    major = gss_display_name(&minor, real_acceptor_name, &namebuf, NULL);
    if (GSS_ERROR(major)) {
        display_status("gss_display_name", major, minor);
        return 1;
    }

    printf("%.*s\n", (int)namebuf.length, (char *)namebuf.value);

    (void)gss_release_name(&minor, &target_name);
    (void)gss_release_name(&minor, &acceptor_name);
    (void)gss_release_cred(&minor, &acceptor_cred);
    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_buffer(&minor, &token);
    (void)gss_release_buffer(&minor, &tmp);
    return 0;
}
