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
#include <assert.h>

#include "common.h"

static gss_OID_desc mech_krb5_wrong = {
    9, "\052\206\110\202\367\022\001\002\002"
};
gss_OID_set_desc mechset_krb5_wrong = { 1, &mech_krb5_wrong };

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
    OM_uint32 minor, major, flags;
    gss_cred_id_t verifier_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t initiator_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc itok = GSS_C_EMPTY_BUFFER, atok = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t initiator_context, acceptor_context;
    gss_name_t target_name, source_name = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;
    gss_OID_desc pref_oids[2];
    gss_OID_set_desc pref_mechs;
    const unsigned char *atok_oid;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s target_name [keytab]\n", argv[0]);
        exit(1);
    }

    target_name = import_name(argv[1]);

    if (argc >= 3) {
        major = krb5_gss_register_acceptor_identity(argv[2]);
        check_gsserr("krb5_gss_register_acceptor_identity", major, 0);
    }

    /* Get default initiator cred. */
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             &mechset_spnego, GSS_C_INITIATE,
                             &initiator_cred_handle, NULL, NULL);
    check_gsserr("gss_acquire_cred(initiator)", major, minor);

    /* Make the initiator prefer IAKERB and offer krb5 as an alternative. */
    pref_oids[0] = mech_iakerb;
    pref_oids[1] = mech_krb5;
    pref_mechs.count = 2;
    pref_mechs.elements = pref_oids;
    major = gss_set_neg_mechs(&minor, initiator_cred_handle, &pref_mechs);
    check_gsserr("gss_set_neg_mechs(initiator)", major, minor);

    /* Get default acceptor cred. */
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             &mechset_spnego, GSS_C_ACCEPT,
                             &verifier_cred_handle, &actual_mechs, NULL);
    check_gsserr("gss_acquire_cred(acceptor)", major, minor);

    /* Restrict the acceptor to krb5 (which will force a reselection). */
    major = gss_set_neg_mechs(&minor, verifier_cred_handle, &mechset_krb5);
    check_gsserr("gss_set_neg_mechs(acceptor)", major, minor);

    flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    establish_contexts(&mech_spnego, initiator_cred_handle,
                       verifier_cred_handle, target_name, flags,
                       &initiator_context, &acceptor_context, &source_name,
                       &mech, NULL);

    display_canon_name("Source name", source_name, &mech_krb5);
    display_oid("Source mech", mech);

    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_name(&minor, &source_name);
    (void)gss_release_cred(&minor, &initiator_cred_handle);
    (void)gss_release_cred(&minor, &verifier_cred_handle);
    (void)gss_release_oid_set(&minor, &actual_mechs);

    /*
     * Test that the SPNEGO acceptor code properly reflects back the erroneous
     * Microsoft mech OID in the supportedMech field of the NegTokenResp
     * message.  Our initiator code doesn't care (it treats all variants of the
     * krb5 mech as equivalent when comparing the supportedMech response to its
     * first-choice mech), so we have to look directly at the DER encoding of
     * the response token.  If we don't request mutual authentication, the
     * SPNEGO reply will contain no underlying mech token, so the encoding of
     * the correct NegotiationToken response is completely predictable:
     *
     *   A1 14 (choice 1, length 20, meaning negTokenResp)
     *     30 12 (sequence, length 18)
     *       A0 03 (context tag 0, length 3)
     *         0A 01 00 (enumerated value 0, meaning accept-completed)
     *       A1 0B (context tag 1, length 11)
     *         06 09 (object identifier, length 9)
     *            2A 86 48 82 F7 12 01 02 02 (the erroneous krb5 OID)
     *
     * So we can just compare the length to 22 and the nine bytes at offset 13
     * to the expected OID.
     */
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             &mechset_spnego, GSS_C_INITIATE,
                             &initiator_cred_handle, NULL, NULL);
    check_gsserr("gss_acquire_cred(2)", major, minor);
    major = gss_set_neg_mechs(&minor, initiator_cred_handle,
                              &mechset_krb5_wrong);
    check_gsserr("gss_set_neg_mechs(2)", major, minor);
    major = gss_init_sec_context(&minor, initiator_cred_handle,
                                 &initiator_context, target_name, &mech_spnego,
                                 flags, GSS_C_INDEFINITE,
                                 GSS_C_NO_CHANNEL_BINDINGS, &atok, NULL, &itok,
                                 NULL, NULL);
    check_gsserr("gss_init_sec_context", major, minor);
    assert(major == GSS_S_CONTINUE_NEEDED);
    major = gss_accept_sec_context(&minor, &acceptor_context,
                                   GSS_C_NO_CREDENTIAL, &itok,
                                   GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                   NULL, &atok, NULL, NULL, NULL);
    assert(atok.length == 22);
    atok_oid = (unsigned char *)atok.value + 13;
    assert(memcmp(atok_oid, mech_krb5_wrong.elements, 9) == 0);
    check_gsserr("gss_accept_sec_context", major, minor);

    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_cred(&minor, &initiator_cred_handle);
    (void)gss_release_name(&minor, &target_name);
    (void)gss_release_buffer(&minor, &itok);
    (void)gss_release_buffer(&minor, &atok);
    return 0;
}
