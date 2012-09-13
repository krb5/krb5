/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2010  by the Massachusetts Institute of Technology.
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

/*
 * Test program for SPNEGO and gss_set_neg_mechs
 *
 * Example usage:
 *
 * kinit testuser
 * ./t_spnego host/test.host@REALM testhost.keytab
 */

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t verifier_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER, tmp = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_name_t target_name, source_name = GSS_C_NO_NAME;
    OM_uint32 time_rec;
    gss_OID mech = GSS_C_NO_OID;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s target_name [keytab]\n", argv[0]);
        exit(1);
    }

    target_name = import_name(argv[1]);

    if (argc >= 3) {
        major = krb5_gss_register_acceptor_identity(argv[2]);
        check_gsserr("krb5_gss_register_acceptor_identity", major, 0);
    }

    /* Get default acceptor cred. */
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             &mechset_spnego, GSS_C_ACCEPT,
                             &verifier_cred_handle, &actual_mechs, NULL);
    check_gsserr("gss_acquire_cred", major, minor);

    /* Restrict the acceptor to krb5, to exercise the neg_mechs logic. */
    major = gss_set_neg_mechs(&minor, verifier_cred_handle, &mechset_krb5);
    check_gsserr("gss_set_neg_mechs", major, minor);

    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL,
                                 &initiator_context, target_name, &mech_spnego,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, NULL, &token, NULL,
                                 &time_rec);
    check_gsserr("gss_init_sec_context", major, minor);
    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);

    major = gss_accept_sec_context(&minor, &acceptor_context,
                                   verifier_cred_handle, &token,
                                   GSS_C_NO_CHANNEL_BINDINGS, &source_name,
                                   &mech, &tmp, NULL, &time_rec, NULL);
    check_gsserr("gss_accept_sec_context", major, minor);

    display_canon_name("Source name", source_name, &mech_krb5);
    display_oid("Source mech", mech);

    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_name(&minor, &source_name);
    (void)gss_release_name(&minor, &target_name);
    (void)gss_release_buffer(&minor, &token);
    (void)gss_release_buffer(&minor, &tmp);
    (void)gss_release_cred(&minor, &verifier_cred_handle);
    (void)gss_release_oid_set(&minor, &actual_mechs);
    return 0;
}
