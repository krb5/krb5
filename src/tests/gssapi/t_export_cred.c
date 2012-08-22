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
#include <ctype.h>

#include <gssapi/gssapi_krb5.h>

static gss_OID_desc mech_krb5 = { 9, "\052\206\110\206\367\022\001\002\002" };
static gss_OID_desc mech_spnego = { 6, "\053\006\001\005\005\002" };
static gss_OID_set_desc mechset_krb5 = { 1, &mech_krb5 };
static gss_OID_set_desc mechset_spnego = { 1, &mech_spnego };

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

/* If maj_stat indicates an error, display an error message (containing msg)
 * and exit. */
static void
check_gsserr(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
    if (GSS_ERROR(maj_stat)) {
        display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
        display_status_1(msg, min_stat, GSS_C_MECH_CODE);
        exit(1);
    }
}

/* Display an error message and exit. */
static void
errout(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

/* Import a GSSAPI name based on a string of the form 'u:username',
 * 'p:principalname', or 'h:host@service' (or just 'h:service'). */
static gss_name_t
import_name(const char *str)
{
    OM_uint32 major, minor;
    gss_name_t name;
    gss_buffer_desc buf;
    gss_OID nametype = NULL;

    if (*str == 'u')
        nametype = GSS_C_NT_USER_NAME;
    else if (*str == 'p')
        nametype = (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME;
    else if (*str == 'h')
        nametype = GSS_C_NT_HOSTBASED_SERVICE;
    if (nametype == NULL || str[1] != ':')
        errout("names must begin with u: or p: or h:");
    buf.value = (char *)str + 2;
    buf.length = strlen(str) - 2;
    major = gss_import_name(&minor, &buf, nametype, &name);
    check_gsserr("gss_import_name", major, minor);
    return name;
}

/* Display a usage error message and exit. */
static void
usage(void)
{
    fprintf(stderr, "Usage: t_export_cred [-k|-s] [-i initiatorname] "
            "[-a acceptorname] targetname\n");
    exit(1);
}

/* Export *cred to a token, then release *cred and replace it by re-importing
 * the token. */
static void
export_import_cred(gss_cred_id_t *cred)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    major = gss_export_cred(&minor, *cred, &buf);
    check_gsserr("gss_export_cred", major, minor);
    (void)gss_release_cred(&minor, cred);
    major = gss_import_cred(&minor, &buf, cred);
    check_gsserr("gss_import_cred", major, minor);
    (void)gss_release_buffer(&minor, &buf);
}

int
main(int argc, char *argv[])
{
    OM_uint32 major, minor, flags;
    gss_name_t initiator_name = GSS_C_NO_NAME, acceptor_name = GSS_C_NO_NAME;
    gss_name_t target_name;
    gss_cred_id_t initiator_cred, acceptor_cred, delegated_cred;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_OID mech = GSS_C_NO_OID;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc token, tmp;
    char optchar;

    /* Parse arguments. */
    argv++;
    while (*argv != NULL && **argv == '-') {
        optchar = (*argv)[1];
        argv++;
        if (optchar == 'i') {
            if (*argv == NULL)
                usage();
            initiator_name = import_name(*argv++);
        } else if (optchar == 'a') {
            if (*argv == NULL)
                usage();
            acceptor_name = import_name(*argv++);
        } else if (optchar == 'k') {
            mech = &mech_krb5;
            mechs = &mechset_krb5;
        } else if (optchar == 's') {
            mech = &mech_spnego;
            mechs = &mechset_spnego;
        } else {
            usage();
        }
    }
    if (*argv == NULL || *(argv + 1) != NULL)
        usage();
    target_name = import_name(argv[0]);

    /* Get initiator cred and export/import it. */
    major = gss_acquire_cred(&minor, initiator_name, GSS_C_INDEFINITE, mechs,
                             GSS_C_INITIATE, &initiator_cred, NULL, NULL);
    check_gsserr("gss_acquire_cred(initiator)", major, minor);
    export_import_cred(&initiator_cred);

    /* Get acceptor cred and export/import it. */
    major = gss_acquire_cred(&minor, acceptor_name, GSS_C_INDEFINITE, mechs,
                             GSS_C_ACCEPT, &acceptor_cred, NULL, NULL);
    check_gsserr("gss_acquire_cred(acceptor)", major, minor);
    export_import_cred(&acceptor_cred);

    /* Initiate and accept a security context (one-token exchange only),
     * delegating credentials. */
    flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG |
        GSS_C_INTEG_FLAG | GSS_C_DELEG_FLAG;
    major = gss_init_sec_context(&minor, initiator_cred, &initiator_context,
                                 target_name, mech, flags, GSS_C_INDEFINITE,
                                 GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                 NULL, &token, NULL, NULL);
    check_gsserr("gss_init_sec_context", major, minor);

    major = gss_accept_sec_context(&minor, &acceptor_context, acceptor_cred,
                                   &token, GSS_C_NO_CHANNEL_BINDINGS,
                                   NULL, NULL, &tmp, NULL, NULL,
                                   &delegated_cred);
    check_gsserr("gss_accept_sec_context", major, minor);

    /* Import, release, export, and store delegated creds */
    export_import_cred(&delegated_cred);
    major = gss_store_cred(&minor, delegated_cred, GSS_C_INITIATE,
                           GSS_C_NULL_OID, 1, 1, NULL, NULL);
    check_gsserr("gss_store_cred", major, minor);

    (void)gss_release_name(&minor, &initiator_name);
    (void)gss_release_name(&minor, &acceptor_name);
    (void)gss_release_name(&minor, &target_name);
    (void)gss_release_cred(&minor, &initiator_cred);
    (void)gss_release_cred(&minor, &acceptor_cred);
    (void)gss_release_cred(&minor, &delegated_cred);
    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_buffer(&minor, &token);
    (void)gss_release_buffer(&minor, &tmp);
    return 0;
}
