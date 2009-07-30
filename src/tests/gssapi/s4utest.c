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
 *    $ kinit -f host/mithost.win.mit.edu@WIN.MIT.EDU
 *    $ s4utest delegtest@WIN.MIT.EDU HOST@WIN-EQ7E4AA2WR8.win.mit.edu krb5.keytab
 */

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
        return major;
    }

    printf("%s:\t%s\n", tag, (char *)buf.value);

    gss_release_buffer(minor, &buf);

    return GSS_S_COMPLETE;
}


int main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    gss_cred_id_t verifier_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_name_t principal = GSS_C_NO_NAME, target = GSS_C_NO_NAME;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_cred_id_t delegated_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc buf;
    gss_OID mech_type;
    OM_uint32 ret_flags, time_ret;

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s [user] [proxy-target] [keytab]\n", argv[0]);
        fprintf(stderr, "       proxy-target and keytab are optional\n");
        exit(1);
    }

    buf.value = argv[1];
    buf.length = strlen((char *)buf.value);

    major = gss_import_name(&minor, &buf, (gss_OID)GSS_KRB5_NT_ENTERPRISE_NAME, &principal);
    if (GSS_ERROR(major)) {
        displayStatus("gss_import_name(user)", major, minor);
        goto out;
    }

    if (argc > 2 && strcmp(argv[2], "-")) {
        buf.value = argv[2];
        buf.length = strlen((char *)buf.value);

        major = gss_import_name(&minor, &buf, (gss_OID)GSS_C_NT_HOSTBASED_SERVICE, &target);
        if (GSS_ERROR(major)) {
            displayStatus("gss_import_name(target)", major, minor);
            goto out;
        }

        major = gss_krb5_add_sec_context_delegatee(&minor, &context_handle, target);
        if (GSS_ERROR(major)) {
            displayStatus("gss_krb5_add_sec_context_delegatee", major, minor);
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

   buf.value = NULL;

    major = gss_krb5_create_sec_context_for_principal(&minor,
        &context_handle,
        verifier_cred_handle,
        principal,
        GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
        0,
        &src_name,
        &mech_type,
        &ret_flags,
        &time_ret,
        &delegated_cred_handle);
    if (GSS_ERROR(major)) {
        displayStatus("gss_krb5_create_sec_context_for_principal", major, minor);
        goto out;
    }

    displayCanonName(&minor, src_name, "User name");
    if (target != GSS_C_NO_NAME)
        displayCanonName(&minor, target, "Target name");

    if (delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
        gss_name_t cred_name = GSS_C_NO_NAME;
        OM_uint32 lifetime;
        gss_cred_usage_t usage;

        buf.value = NULL;

        if (gss_inquire_cred(&minor, delegated_cred_handle, &cred_name,
                             &lifetime, &usage, NULL) == GSS_S_COMPLETE)
            displayCanonName(&minor, cred_name, "Cred name");
        gss_release_name(&minor, &cred_name);

        printf("\n");

        gss_delete_sec_context(&minor, &context_handle, NULL);
        context_handle = NULL;

        major = gss_init_sec_context(&minor,
                                     delegated_cred_handle,
                                     &context_handle,
                                     target,
                                     (gss_OID)gss_mech_krb5,
                                     GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                     0,
                                     GSS_C_NO_CHANNEL_BINDINGS,
                                     GSS_C_NO_BUFFER,
                                     &mech_type,
                                     &buf,
                                     &ret_flags,
                                     &time_ret);
        if (GSS_ERROR(major)) {
            displayStatus("gss_init_sec_context(delegated_cred_handle)", major, minor);
        }
        printf("gss_init_sec_context with delegated credentials succeeded\n");
        gss_release_buffer(&minor, &buf);
    } else if (target != GSS_C_NO_NAME) {
        fprintf(stderr, "Warning: no delegated credentials handle returned\n");
    }


out:
    gss_release_name(&minor, &principal);
    gss_release_name(&minor, &target);
    gss_release_name(&minor, &src_name);
    gss_delete_sec_context(&minor, &context_handle, NULL);
    gss_release_cred(&minor, &delegated_cred_handle);

    return GSS_ERROR(major) ? 1 : 0;
}

