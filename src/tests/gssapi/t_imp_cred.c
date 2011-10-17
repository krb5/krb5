/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/gssapi/t_imp_cred.c - krb5_gss_import_cred test harness */
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

/*
 * Test program for krb5_gss_import_cred, intended to be run from a Python test
 * script.  Creates an initiator credential for the default ccache and an
 * acceptor principal for the default keytab (possibly using a specified keytab
 * principal), and performs a one-token context exchange using a specified
 * target principal.  If the exchange is successful, queries the context for
 * the acceptor name and prints it.  If any call is unsuccessful, displays an
 * error message.  Exits with status 0 if all operations are successful, or 1
 * if not.
 *
 * Usage: ./t_imp_cred target-princ [keytab-princ]
 */

#include "k5-platform.h"
#include <krb5.h>
#include <gssapi/gssapi_krb5.h>

static void
display_status(const char *m, OM_uint32 code, int type)
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
exit_gsserr(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
    display_status(msg, maj_stat, GSS_C_GSS_CODE);
    display_status(msg, min_stat, GSS_C_MECH_CODE);
    exit(1);
}

static void
exit_kerr(krb5_context context, const char *msg, krb5_error_code code)
{
    const char *errmsg;

    errmsg = krb5_get_error_message(context, code);
    printf("%s: %s\n", msg, errmsg);
    krb5_free_error_message(context, errmsg);
    exit(1);
}

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t initiator_cred, acceptor_cred;
    gss_buffer_desc buf, token, tmp;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_name_t target_name;
    krb5_context context;
    krb5_ccache cc;
    krb5_keytab kt;
    krb5_principal princ = NULL;
    krb5_error_code ret;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s targetprinc [acceptorprinc]\n", argv[0]);
        return 1;
    }

    /* Import the target name as a krb5 principal name. */
    buf.value = argv[1];
    buf.length = strlen((char *)buf.value);
    major = gss_import_name(&minor, &buf, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                            &target_name);
    if (GSS_ERROR(major)) {
        display_status("gss_import_name", major, minor);
        return 1;
    }

    /* Acquire the krb5 objects we need. */
    ret = krb5_init_context(&context);
    if (ret)
        exit_kerr(NULL, "krb5_init_context", ret);
    ret = krb5_cc_default(context, &cc);
    if (ret)
        exit_kerr(context, "krb5_cc_default", ret);
    ret = krb5_kt_default(context, &kt);
    if (ret)
        exit_kerr(context, "krb5_kt_default", ret);
    if (argc >= 3) {
        ret = krb5_parse_name(context, argv[2], &princ);
        if (ret)
            exit_kerr(context, "krb5_parse_name", ret);
    }

    /* Get initiator cred. */
    major = gss_krb5_import_cred(&minor, cc, NULL, NULL, &initiator_cred);
    if (GSS_ERROR(major))
        exit_gsserr("gss_krb5_import_cred (initiator)", major, minor);

    /* Get acceptor cred. */
    major = gss_krb5_import_cred(&minor, NULL, princ, kt, &acceptor_cred);
    if (GSS_ERROR(major))
        exit_gsserr("gss_krb5_import_cred (acceptor)", major, minor);

    /* Create krb5 initiator context and get the first token. */
    token.value = NULL;
    token.length = 0;
    major = gss_init_sec_context(&minor, initiator_cred,
                                 &initiator_context, target_name,
                                 (gss_OID)gss_mech_krb5,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, NULL, &token, NULL, NULL);
    if (GSS_ERROR(major))
        exit_gsserr("gss_init_sec_context", major, minor);

    /* Pass the token to gss_accept_sec_context. */
    tmp.value = NULL;
    tmp.length = 0;
    major = gss_accept_sec_context(&minor, &acceptor_context, acceptor_cred,
                                   &token, GSS_C_NO_CHANNEL_BINDINGS,
                                   NULL, NULL, &tmp, NULL, NULL, NULL);
    if (major != GSS_S_COMPLETE)
        exit_gsserr("gss_accept_sec_context", major, minor);

    krb5_cc_close(context, cc);
    krb5_kt_close(context, kt);
    krb5_free_principal(context, princ);
    krb5_free_context(context);
    (void)gss_release_name(&minor, &target_name);
    (void)gss_release_cred(&minor, &initiator_cred);
    (void)gss_release_cred(&minor, &acceptor_cred);
    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_buffer(&minor, &token);
    (void)gss_release_buffer(&minor, &tmp);
    return 0;
}
