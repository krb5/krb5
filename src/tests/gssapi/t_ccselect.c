/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/gssapi/t_ccselect.c - Test program for GSSAPI cred selection */
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
 * Test program for client credential selection, intended to be run from a
 * Python test script.  Performs a one-token
 * gss_init_sec_context/gss_accept_sec_context exchange, optionally with a
 * specified principal as the initiator name, a specified principal name as
 * target name, the default acceptor cred.  If the exchange is successful,
 * prints the initiator name as seen by the acceptor.  If any call is
 * unsuccessful, displays an error message.  Exits with status 0 if all
 * operations are successful, or 1 if not.
 *
 * Usage: ./t_ccselect [targetprinc|gss:service@host] [initiatorprinc|-]
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
gsserr(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
    display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
    display_status_1(msg, min_stat, GSS_C_MECH_CODE);
    exit(1);
}

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t initiator_cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc buf;
    gss_name_t target_name, initiator_name = GSS_C_NO_NAME;
    gss_name_t real_initiator_name;
    gss_buffer_desc token, tmp, namebuf;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s targetprinc [initiatorprinc|-]\n", argv[0]);
        return 1;
    }

    /* Import the target name. */
    if (strncmp(argv[1], "gss:", 4) == 0) {
        /* Import as host-based service. */
        buf.value = argv[1] + 4;
        buf.length = strlen((char *)buf.value);
        major = gss_import_name(&minor, &buf,
                                (gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
                                &target_name);
    } else {
        /* Import as krb5 principal name. */
        buf.value = argv[1];
        buf.length = strlen((char *)buf.value);
        major = gss_import_name(&minor, &buf,
                                (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                                &target_name);
    }
    if (GSS_ERROR(major))
        gsserr("gss_import_name(target_name)", major, minor);

    /* Import the initiator name as a krb5 principal and get creds, maybe. */
    if (argc >= 3) {
        if (strcmp(argv[2], "-") != 0) {
            buf.value = argv[2];
            buf.length = strlen((char *)buf.value);
            major = gss_import_name(&minor, &buf,
                                    (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                                    &initiator_name);
            if (GSS_ERROR(major))
                gsserr("gss_import_name(initiator_name)", major, minor);
        }

        /* Get acceptor cred. */
        major = gss_acquire_cred(&minor, initiator_name, GSS_C_INDEFINITE,
                                 GSS_C_NO_OID_SET, GSS_C_INITIATE,
                                 &initiator_cred, NULL, NULL);
        if (GSS_ERROR(major))
            gsserr("gss_acquire_cred", major, minor);
    }


    /* Create krb5 initiator context and get the first token. */
    token.value = NULL;
    token.length = 0;
    major = gss_init_sec_context(&minor, initiator_cred, &initiator_context,
                                 target_name, (gss_OID)gss_mech_krb5,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, NULL, &token, NULL, NULL);
    if (GSS_ERROR(major))
        gsserr("gss_init_sec_context", major, minor);

    /* Pass the token to gss_accept_sec_context. */
    tmp.value = NULL;
    tmp.length = 0;
    major = gss_accept_sec_context(&minor, &acceptor_context,
                                   GSS_C_NO_CREDENTIAL, &token,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &real_initiator_name, NULL, &tmp,
                                   NULL, NULL, NULL);
    if (major != GSS_S_COMPLETE)
        gsserr("gss_accept_sec_context", major, minor);

    namebuf.value = NULL;
    namebuf.length = 0;
    major = gss_display_name(&minor, real_initiator_name, &namebuf, NULL);
    if (GSS_ERROR(major))
        gsserr("gss_display_name(initiator)", major, minor);
    printf("%.*s\n", (int)namebuf.length, (char *)namebuf.value);

    (void)gss_release_name(&minor, &target_name);
    (void)gss_release_name(&minor, &initiator_name);
    (void)gss_release_name(&minor, &real_initiator_name);
    (void)gss_release_cred(&minor, &initiator_cred);
    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_buffer(&minor, &token);
    (void)gss_release_buffer(&minor, &tmp);
    (void)gss_release_buffer(&minor, &namebuf);
    return 0;
}
