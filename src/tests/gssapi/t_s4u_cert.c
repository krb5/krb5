/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2009  by the Massachusetts Institute of Technology.
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
 * Test program for protocol transition (S4U2Self) with certificate
 *
 * Usage eg:
 * (set default keytab)
 * kinit -f 'host/test.win.mit.edu@WIN.MIT.EDU'
 * ./t_s4u_cert usertest@WIN.MIT.EDU p:usertest@WIN.MIT.EDU
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

static int use_spnego = 0;

static void
init_accept_sec_context(gss_cred_id_t claimant_cred_handle,
                        gss_cred_id_t verifier_cred_handle)
{
    OM_uint32 major, minor, flags;
    gss_name_t source_name = GSS_C_NO_NAME, target_name = GSS_C_NO_NAME;
    gss_ctx_id_t initiator_context, acceptor_context;
    gss_OID mech = GSS_C_NO_OID;

    major = gss_inquire_cred(&minor, verifier_cred_handle, &target_name, NULL,
                             NULL, NULL);
    check_gsserr("gss_inquire_cred", major, minor);

    display_canon_name("Target name", target_name, &mech_krb5);

    mech = use_spnego ? &mech_spnego : &mech_krb5;
    display_oid("Target mech", mech);

    flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    establish_contexts(mech, claimant_cred_handle, verifier_cred_handle,
                       target_name, flags, &initiator_context,
                       &acceptor_context, &source_name, &mech, NULL);

    display_canon_name("Source name", source_name, &mech_krb5);
    display_oid("Source mech", mech);
    enumerate_attributes(source_name, 1);

    (void)gss_release_name(&minor, &source_name);
    (void)gss_release_name(&minor, &target_name);
    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
}

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t impersonator_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t user_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc cert_data = GSS_C_EMPTY_BUFFER;
    gss_name_t user = GSS_C_NO_NAME;
    gss_OID_set mechs;

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s [--spnego] [cert_data] [user]\n", argv[0]);
        exit(1);
    }

    if (strcmp(argv[1], "--spnego") == 0) {
        use_spnego++;
        argc--;
        argv++;
    }

    if (strcmp(argv[1], "-")) {
        cert_data.length = strlen(argv[1]);
        cert_data.value = argv[1];
    }

    if (argc > 2)
        user = import_name(argv[2]);

    /* Get default cred. Initiate cred should be sufficient to impersonate */
    mechs = use_spnego ? &mechset_spnego : &mechset_krb5;
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE, mechs,
                             GSS_C_INITIATE, &impersonator_cred_handle, NULL,
                             NULL);
    check_gsserr("gss_acquire_cred", major, minor);

    printf("Protocol transition tests follow\n");
    printf("-----------------------------------\n\n");

    /* Get S4U2Self cred. */
    major = gss_acquire_cred_impersonate_cert(&minor,
                                              impersonator_cred_handle,
                                              user, &cert_data,
                                              GSS_C_INDEFINITE,
                                              mechs, GSS_C_INITIATE,
                                              &user_cred_handle, NULL,
                                              NULL);
    check_gsserr("gss_acquire_cred_impersonate_cert", major, minor);

    (void)gss_release_cred(&minor, &impersonator_cred_handle);
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE, mechs,
                             GSS_C_ACCEPT, &impersonator_cred_handle, NULL,
                             NULL);
    check_gsserr("gss_acquire_cred", major, minor);

    init_accept_sec_context(user_cred_handle, impersonator_cred_handle);
    printf("\n");

    (void)gss_release_name(&minor, &user);
    (void)gss_release_cred(&minor, &impersonator_cred_handle);
    (void)gss_release_cred(&minor, &user_cred_handle);
    return 0;
}
