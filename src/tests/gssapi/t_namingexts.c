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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

static int use_spnego = 0;

static void
test_export_import_name(gss_name_t name)
{
    OM_uint32 major, minor;
    gss_buffer_desc exported_name = GSS_C_EMPTY_BUFFER;
    gss_name_t imported_name = GSS_C_NO_NAME;
    unsigned int i;

    major = gss_export_name_composite(&minor, name, &exported_name);
    check_gsserr("gss_export_name_composite", major, minor);

    printf("Exported name:\n");
    for (i = 0; i < exported_name.length; i++) {
        if ((i % 32) == 0)
            printf("\n");
        printf("%02x", ((char *)exported_name.value)[i] & 0xFF);
    }
    printf("\n");

    major = gss_import_name(&minor, &exported_name, GSS_C_NT_EXPORT_NAME,
                            &imported_name);
    check_gsserr("gss_import_name", major, minor);
    (void)gss_release_buffer(&minor, &exported_name);

    printf("\n");
    display_canon_name("Re-imported name", imported_name, &mech_krb5);
    printf("Re-imported attributes:\n\n");
    enumerate_attributes(imported_name, 0);

    (void)gss_release_name(&minor, &imported_name);
}

static void
test_greet_authz_data(gss_name_t name)
{
    OM_uint32 major, minor;
    gss_buffer_desc attr;
    gss_buffer_desc value;

    attr.value = "urn:greet:greeting";
    attr.length = strlen((char *)attr.value);

    major = gss_delete_name_attribute(&minor, name, &attr);
    if (major == GSS_S_UNAVAILABLE) {
        fprintf(stderr, "Warning: greet_client plugin not installed\n");
        exit(1);
    }
    check_gsserr("gss_delete_name_attribute", major, minor);

    value.value = "Hello, acceptor world!";
    value.length = strlen((char *)value.value);
    major = gss_set_name_attribute(&minor, name, 1, &attr, &value);
    if (major == GSS_S_UNAVAILABLE)
        return;
    check_gsserr("gss_set_name_attribute", major, minor);
}

static void
test_map_name_to_any(gss_name_t name)
{
    OM_uint32 major, minor;
    gss_buffer_desc type_id;
    krb5_pac pac;
    krb5_context context = NULL;
    krb5_error_code ret;
    size_t len, i;
    krb5_ui_4 *types;

    type_id.value = "mspac";
    type_id.length = strlen((char *)type_id.value);

    major = gss_map_name_to_any(&minor, name, 1, &type_id, (gss_any_t *)&pac);
    if (major == GSS_S_UNAVAILABLE)
        return;
    check_gsserr("gss_map_name_to_any", major, minor);

    ret = krb5_init_context(&context);
    check_k5err(context, "krb5_init_context", ret);

    if (krb5_pac_get_types(context, pac, &len, &types) == 0) {
        printf("PAC buffer types:");
        for (i = 0; i < len; i++)
            printf(" %d", types[i]);
        printf("\n");
        free(types);
    }

    (void)gss_release_any_name_mapping(&minor, name, &type_id,
                                       (gss_any_t *)&pac);
}

static void
init_accept_sec_context(gss_cred_id_t verifier_cred_handle)
{
    OM_uint32 major, minor;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER, tmp = GSS_C_EMPTY_BUFFER;
    gss_name_t source_name = GSS_C_NO_NAME, target_name = GSS_C_NO_NAME;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_OID mech = use_spnego ? &mech_spnego : &mech_krb5;
    OM_uint32 time_rec;

    major = gss_inquire_cred(&minor, verifier_cred_handle, &target_name, NULL,
                             NULL, NULL);
    check_gsserr("gss_inquire_cred", major, minor);

    display_canon_name("Target name", target_name, &mech_krb5);

    major = gss_init_sec_context(&minor, verifier_cred_handle,
                                 &initiator_context, target_name, mech,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, NULL, &token, NULL,
                                 &time_rec);
    check_gsserr("gss_init_sec_context", major, minor);

    (void)gss_release_name(&minor, &target_name);
    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);

    major = gss_accept_sec_context(&minor, &acceptor_context,
                                   verifier_cred_handle, &token,
                                   GSS_C_NO_CHANNEL_BINDINGS, &source_name,
                                   NULL, &tmp, NULL, &time_rec, NULL);
    check_gsserr("gss_accept_sec_context", major, minor);

    display_canon_name("Source name", source_name, &mech_krb5);
    enumerate_attributes(source_name, 1);
    test_export_import_name(source_name);
    test_map_name_to_any(source_name);

    (void)gss_release_name(&minor, &source_name);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_buffer(&minor, &token);
    (void)gss_release_buffer(&minor, &tmp);
}

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t cred_handle = GSS_C_NO_CREDENTIAL;
    gss_OID_set mechs, actual_mechs = GSS_C_NO_OID_SET;
    gss_name_t tmp_name, name;

    if (argc > 1 && strcmp(argv[1], "--spnego") == 0) {
        use_spnego++;
        argc--;
        argv++;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [--spnego] principal [keytab]\n", argv[0]);
        exit(1);
    }

    tmp_name = import_name(argv[1]);
    major = gss_canonicalize_name(&minor, tmp_name, &mech_krb5, &name);
    check_gsserr("gss_canonicalze_name", major, minor);
    (void)gss_release_name(&minor, &tmp_name);

    test_greet_authz_data(name);

    if (argc >= 3) {
        major = krb5_gss_register_acceptor_identity(argv[2]);
        check_gsserr("krb5_gss_register_acceptor_identity", major, minor);
    }

    mechs = use_spnego ? &mechset_spnego : &mechset_krb5;

    /* get default cred */
    major = gss_acquire_cred(&minor, name, GSS_C_INDEFINITE, mechs, GSS_C_BOTH,
                             &cred_handle, &actual_mechs, NULL);
    check_gsserr("gss_acquire_cred", major, minor);

    (void)gss_release_oid_set(&minor, &actual_mechs);

    init_accept_sec_context(cred_handle);

    printf("\n");

    (void)gss_release_cred(&minor, &cred_handle);
    (void)gss_release_oid_set(&minor, &actual_mechs);
    (void)gss_release_name(&minor, &name);
    return 0;
}
