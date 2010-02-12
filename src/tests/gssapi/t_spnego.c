/* -*- mode: c; indent-tabs-mode: nil -*- */
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

#include <gssapi/gssapi_krb5.h>

/*
 * Test program for SPNEGO and gss_set_neg_mechs
 *
 * Example usage:
 *
 * kinit testuser
 * ./t_spnego host/test.host@REALM testhost.keytab
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
    OM_uint32 major, tmp_minor;
    gss_buffer_desc buf;

    major = gss_canonicalize_name(minor, name,
                                  (gss_OID)gss_mech_krb5, &canon);
    if (GSS_ERROR(major)) {
        displayStatus("gss_canonicalize_name", major, *minor);
        return major;
    }

    major = gss_display_name(minor, canon, &buf, NULL);
    if (GSS_ERROR(major)) {
        displayStatus("gss_display_name", major, *minor);
        gss_release_name(&tmp_minor, &canon);
        return major;
    }

    printf("%s:\t%s\n", tag, (char *)buf.value);

    gss_release_buffer(&tmp_minor, &buf);
    gss_release_name(&tmp_minor, &canon);

    return GSS_S_COMPLETE;
}

static OM_uint32
displayOID(OM_uint32 *minor, gss_OID oid, char *tag)
{
    OM_uint32 major, tmp_minor;
    gss_buffer_desc buf;

    major = gss_oid_to_str(minor, oid, &buf);
    if (GSS_ERROR(major)) {
        displayStatus("gss_oid_to_str", major, *minor);
        return major;
    }

    printf("%s:\t%s\n", tag, (char *)buf.value);

    gss_release_buffer(&tmp_minor, &buf);

    return GSS_S_COMPLETE;
}

static OM_uint32
initAcceptSecContext(OM_uint32 *minor,
		     gss_name_t target_name,
                     gss_cred_id_t verifier_cred_handle)
{
    OM_uint32 major;
    gss_buffer_desc token, tmp;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_name_t source_name = GSS_C_NO_NAME;
    OM_uint32 time_rec;
    gss_OID mech = GSS_C_NO_OID;

    token.value = NULL;
    token.length = 0;

    tmp.value = NULL;
    tmp.length = 0;

    major = gss_init_sec_context(minor,
                                 GSS_C_NO_CREDENTIAL,
                                 &initiator_context,
                                 target_name,
                                 &spnego_mech,
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
        displayStatus("gss_init_sec_context", major, *minor);
        return major;
    }

    (void) gss_delete_sec_context(minor, &initiator_context, NULL);

    major = gss_accept_sec_context(minor,
                                   &acceptor_context,
                                   verifier_cred_handle,
                                   &token,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &source_name,
                                   &mech,
                                   &tmp,
                                   NULL,
                                   &time_rec,
                                   NULL);

    if (GSS_ERROR(major))
        displayStatus("gss_accept_sec_context", major, *minor);
    else {
        displayCanonName(minor, source_name, "Source name");
        displayOID(minor, mech, "Source mech");
    }

    (void) gss_release_name(minor, &source_name);
    (void) gss_delete_sec_context(minor, &acceptor_context, NULL);
    (void) gss_release_buffer(minor, &token);
    (void) gss_release_buffer(minor, &tmp);
    (void) gss_release_oid(minor, &mech);

    return major;
}

int main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t verifier_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_OID_set_desc mechs;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc buf;
    gss_name_t target_name;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s target_name [keytab]\n", argv[0]);
        exit(1);
    }

    buf.value = argv[1];
    buf.length = strlen((char *)buf.value);
    major = gss_import_name(&minor, &buf,
                            (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                            &target_name);
    if (GSS_ERROR(major)) {
        displayStatus("gss_import_name(target_name)", major, minor);
        goto out;
    }

    if (argc > 2) {
        major = krb5_gss_register_acceptor_identity(argv[2]);
        if (GSS_ERROR(major)) {
            displayStatus("krb5_gss_register_acceptor_identity",
                          major, minor);
            goto out;
        }
    }

    mechs.elements = &spnego_mech;
    mechs.count = 1;

    /* get default acceptor cred */
    major = gss_acquire_cred(&minor,
                             GSS_C_NO_NAME,
                             GSS_C_INDEFINITE,
                             &mechs,
                             GSS_C_ACCEPT,
                             &verifier_cred_handle,
                             &actual_mechs,
                             NULL);
    if (GSS_ERROR(major)) {
        displayStatus("gss_acquire_cred", major, minor);
        goto out;
    }

    /* Restrict the acceptor to krb5, to exercise the neg_mechs logic. */
    mechs.elements = (gss_OID)gss_mech_krb5;
    mechs.count = 1;
    major = gss_set_neg_mechs(&minor, verifier_cred_handle, &mechs);
    if (GSS_ERROR(major)) {
        displayStatus("gss_set_neg_mechs", major, minor);
        goto out;
    }

    major = initAcceptSecContext(&minor, target_name, verifier_cred_handle);
    if (GSS_ERROR(major))
        goto out;

    printf("\n");

out:
    (void) gss_release_cred(&minor, &verifier_cred_handle);
    (void) gss_release_oid_set(&minor, &actual_mechs);
    (void) gss_release_name(&minor, &target_name);

    return GSS_ERROR(major) ? 1 : 0;
}
