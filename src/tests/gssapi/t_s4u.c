/* -*- mode: c; indent-tabs-mode: nil -*- */
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi/gssapi_krb5.h>

/*
 * Test program for protocol transition (S4U2Self) and constrained delegation
 * (S4U2Proxy)
 *
 * Note: because of name canonicalization, the following tips may help
 * when configuring with Active Directory:
 *
 * - Create a computer account FOO$
 * - Set the UPN to host/foo.domain (no suffix); this is necessary to
 *   be able to send an AS-REQ as this principal, otherwise you would
 *   need to use the canonical name (FOO$), which will cause principal
 *   comparison errors in gss_accept_sec_context().
 * - Add a SPN of host/foo.domain
 * - Add host/foo.domain to the keytab (possibly easiest to do this with ktadd)
 *
 * For S4U2Proxy to work the TGT must be forwardable too.
 *
 * Usage eg:
 *
 * kinit -f host/mithost.win.mit.edu@WIN.MIT.EDU
 * t_s4u delegtest@WIN.MIT.EDU HOST@WIN-EQ7E4AA2WR8.win.mit.edu krb5.keytab
 */

static gss_OID_desc spnego_mech = { 6, "\053\006\001\005\005\002" };

static void displayStatus_1(m, code, type)
     char *m;
     OM_uint32 code;
     int type;
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

static void displayStatus(msg, maj_stat, min_stat)
     char *msg;
     OM_uint32 maj_stat;
     OM_uint32 min_stat;
{
     displayStatus_1(msg, maj_stat, GSS_C_GSS_CODE);
     displayStatus_1(msg, min_stat, GSS_C_MECH_CODE);
}

static OM_uint32
displayCanonName(OM_uint32 *minor, gss_name_t name, char *tag)
{
    gss_name_t canon;
    OM_uint32 major;
    gss_buffer_desc buf;

    major = gss_canonicalize_name(minor, name, (gss_OID)gss_mech_krb5, &canon);
    if (GSS_ERROR(major)) {
        displayStatus("gss_canonicalize_name", major, minor);
        return major;
    }

    major = gss_display_name(minor, canon, &buf, NULL);
    if (GSS_ERROR(major)) {
        displayStatus("gss_display_name", major, minor);
        gss_release_name(minor, &canon);
        return major;
    }

    printf("%s:\t%s\n", tag, (char *)buf.value);

    gss_release_buffer(minor, &buf);
    gss_release_name(minor, &canon);

    return GSS_S_COMPLETE;
}

static OM_uint32
initAcceptSecContext(OM_uint32 *minor,
                     gss_cred_id_t claimant_cred_handle,
                     gss_cred_id_t verifier_cred_handle,
                     gss_cred_id_t *deleg_cred_handle)
{
    OM_uint32 major;
    gss_buffer_desc token, tmp;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_name_t source_name = GSS_C_NO_NAME;
    gss_name_t target_name = GSS_C_NO_NAME;
    OM_uint32 time_rec;

    token.value = NULL;
    token.length = 0;

    tmp.value = NULL;
    tmp.length = 0;

    *deleg_cred_handle = GSS_C_NO_CREDENTIAL;

    major = gss_inquire_cred(minor, verifier_cred_handle,
                             &target_name, NULL, NULL, NULL);
    if (GSS_ERROR(major)) {
        displayStatus("gss_inquire_cred", major, minor);
        return major;
    }

    displayCanonName(minor, target_name, "Target name");

    major = gss_init_sec_context(minor,
                                 claimant_cred_handle,
                                 &initiator_context,
                                 target_name,
#if 1
                                 (gss_OID)&spnego_mech,
#else
                                 (gss_OID)&gss_mech_krb5,
#endif
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE,
                                 GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER,
                                 NULL,
                                 &token,
                                 NULL,
                                 &time_rec);

    if (target_name != GSS_C_NO_NAME)
        (void) gss_release_name(minor, &target_name);

    if (GSS_ERROR(major)) {
        displayStatus("gss_init_sec_context", major, minor);
        return major;
    }

    (void) gss_delete_sec_context(minor, &initiator_context, NULL);

    major = gss_accept_sec_context(minor,
                                   &acceptor_context,
                                   verifier_cred_handle,
                                   &token,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &source_name,
                                   NULL,
                                   &tmp,
                                   NULL,
                                   &time_rec,
                                   deleg_cred_handle);

    if (GSS_ERROR(major))
        displayStatus("gss_accept_sec_context", major, minor);
    else
        displayCanonName(minor, source_name, "Source name");

    (void) gss_release_name(minor, &source_name);
    (void) gss_delete_sec_context(minor, &acceptor_context, NULL);
    (void) gss_release_buffer(minor, &token);
    (void) gss_release_buffer(minor, &tmp);

    return major;
}

static OM_uint32
constrainedDelegate(OM_uint32 *minor,
                    gss_OID_set desired_mechs,
                    gss_name_t target,
                    gss_cred_id_t delegated_cred_handle,
                    gss_cred_id_t verifier_cred_handle)
{
    OM_uint32 major, tmp;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_name_t cred_name = GSS_C_NO_NAME;
    OM_uint32 time_rec, lifetime;
    gss_cred_usage_t usage;
    gss_buffer_desc token;

    printf("Constrained delegation tests follow\n");
    printf("-----------------------------------\n\n");

    if (gss_inquire_cred(minor, verifier_cred_handle, &cred_name,
                         &lifetime, &usage, NULL) == GSS_S_COMPLETE) {
        displayCanonName(minor, cred_name, "Proxy name");
        gss_release_name(minor, &cred_name);
    }
    displayCanonName(minor, target, "Target name");
    if (gss_inquire_cred(minor, delegated_cred_handle, &cred_name,
                         &lifetime, &usage, NULL) == GSS_S_COMPLETE) {
        displayCanonName(minor, cred_name, "Source name");
        gss_release_name(minor, &cred_name);
    }

    printf("\n");

    major = gss_init_sec_context(minor,
                                 delegated_cred_handle,
                                 &initiator_context,
                                 target,
#if 0
                                 (gss_OID)&spnego_mech,
#else
                                 (gss_OID)gss_mech_krb5,
#endif
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE,
                                 GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER,
                                 NULL,
                                 &token,
                                 NULL,
                                 &time_rec);
    if (GSS_ERROR(major))
        displayStatus("gss_init_sec_context", major, minor);

    (void) gss_release_buffer(&tmp, &token);
    (void) gss_delete_sec_context(&tmp, &initiator_context, NULL);

    return major;
}

int main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t impersonator_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t user_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_name_t user = GSS_C_NO_NAME, target = GSS_C_NO_NAME;
    gss_OID_set_desc mechs;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc buf;

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s [user] [proxy-target] [keytab]\n", argv[0]);
        fprintf(stderr, "       proxy-target and keytab are optional\n");
        exit(1);
    }

    buf.value = argv[1];
    buf.length = strlen((char *)buf.value);

    major = gss_import_name(&minor, &buf,
                            (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                            &user);
    if (GSS_ERROR(major)) {
        displayStatus("gss_import_name(user)", major, minor);
        goto out;
    }

    if (argc > 2 && strcmp(argv[2], "-")) {
        buf.value = argv[2];
        buf.length = strlen((char *)buf.value);

        major = gss_import_name(&minor, &buf,
                                (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                                &target);
        if (GSS_ERROR(major)) {
            displayStatus("gss_import_name(target)", major, minor);
            goto out;
        }
    } else {
        target = GSS_C_NO_NAME;
    }

    if (argc > 3) {
        major = krb5_gss_register_acceptor_identity(argv[3]);
        if (GSS_ERROR(major)) {
            displayStatus("krb5_gss_register_acceptor_identity", major, minor);
            goto out;
        }
    }

    mechs.elements = (gss_OID)gss_mech_krb5;
    mechs.count = 1;

    /* get default cred */
    major = gss_acquire_cred(&minor,
                             GSS_C_NO_NAME,
                             GSS_C_INDEFINITE,
                             &mechs,
                             GSS_C_BOTH,
                             &impersonator_cred_handle,
                             &actual_mechs,
                             NULL);
    if (GSS_ERROR(major)) {
        displayStatus("gss_acquire_cred", major, minor);
        goto out;
    }

    (void) gss_release_oid_set(&minor, &actual_mechs);

    printf("Protocol transition tests follow\n");
    printf("-----------------------------------\n\n");

    /* get S4U2Self cred */
    major = gss_acquire_cred_impersonate_name(&minor,
                                              impersonator_cred_handle,
                                              user,
                                              GSS_C_INDEFINITE,
                                              &mechs,
                                              GSS_C_INITIATE,
                                              &user_cred_handle,
                                              &actual_mechs,
                                              NULL);
    if (GSS_ERROR(major)) {
        displayStatus("gss_acquire_cred_impersonate_name", major, minor);
        goto out;
    }

    major = initAcceptSecContext(&minor,
                                 user_cred_handle,
                                 impersonator_cred_handle,
                                 &delegated_cred_handle);
    if (GSS_ERROR(major))
        goto out;

    printf("\n");

    if (target != GSS_C_NO_NAME &&
        delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
        major = constrainedDelegate(&minor, &mechs, target,
                                    delegated_cred_handle,
                                    impersonator_cred_handle);
    } else if (target != GSS_C_NO_NAME) {
        fprintf(stderr, "Warning: no delegated credentials handle returned\n\n");
        fprintf(stderr, "Verify:\n\n");
        fprintf(stderr, " - The TGT for the impersonating service is forwardable\n");
        fprintf(stderr, " - The T2A4D flag set on the impersonating service's UAC\n");
        fprintf(stderr, " - The user is not marked sensitive and cannot be delegated\n");
        fprintf(stderr, "\n");
    }

out:
    (void) gss_release_name(&minor, &user);
    (void) gss_release_name(&minor, &target);
    (void) gss_release_cred(&minor, &delegated_cred_handle);
    (void) gss_release_cred(&minor, &impersonator_cred_handle);
    (void) gss_release_cred(&minor, &user_cred_handle);
    (void) gss_release_oid_set(&minor, &actual_mechs);

    return GSS_ERROR(major) ? 1 : 0;
}

