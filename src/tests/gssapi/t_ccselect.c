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

#include "common.h"

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

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t initiator_cred = GSS_C_NO_CREDENTIAL;
    gss_name_t target_name, initiator_name = GSS_C_NO_NAME;
    gss_name_t real_initiator_name;
    gss_buffer_desc token, tmp, namebuf;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s targetname [initiatorname|-]\n", argv[0]);
        return 1;
    }

    target_name = import_name(argv[1]);

    if (argc >= 3) {
        /* Get initiator cred. */
        if (strcmp(argv[2], "-") != 0)
            initiator_name = import_name(argv[2]);
        major = gss_acquire_cred(&minor, initiator_name, GSS_C_INDEFINITE,
                                 GSS_C_NO_OID_SET, GSS_C_INITIATE,
                                 &initiator_cred, NULL, NULL);
        check_gsserr("gss_acquire_cred", major, minor);
    }


    /* Create krb5 initiator context and get the first token. */
    token.value = NULL;
    token.length = 0;
    major = gss_init_sec_context(&minor, initiator_cred, &initiator_context,
                                 target_name, (gss_OID)gss_mech_krb5,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, NULL, &token, NULL, NULL);
    check_gsserr("gss_init_sec_context", major, minor);

    /* Pass the token to gss_accept_sec_context. */
    tmp.value = NULL;
    tmp.length = 0;
    major = gss_accept_sec_context(&minor, &acceptor_context,
                                   GSS_C_NO_CREDENTIAL, &token,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &real_initiator_name, NULL, &tmp,
                                   NULL, NULL, NULL);
    check_gsserr("gss_accept_sec_context", major, minor);

    namebuf.value = NULL;
    namebuf.length = 0;
    major = gss_display_name(&minor, real_initiator_name, &namebuf, NULL);
    check_gsserr("gss_display_name(initiator)", major, minor);
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
