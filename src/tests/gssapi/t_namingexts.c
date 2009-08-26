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
#include <gssapi/gssapi_generic.h>

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
        return major;
    }

    printf("%s:\t%s\n", tag, (char *)buf.value);

    gss_release_buffer(minor, &buf);

    return GSS_S_COMPLETE;
}

static void
dumpAttribute(OM_uint32 *minor,
              gss_name_t name,
              gss_buffer_t attribute)
{
    OM_uint32 major, tmp;
    gss_buffer_desc value;
    gss_buffer_desc display_value;
    int authenticated = 0;
    int complete = 0;
    int more = -1;
    unsigned int i;

    while (more != 0) {
        value.value = NULL;
        display_value.value = NULL;

        major = gss_get_name_attribute(minor,
                                       name,
                                       attribute,
                                       &authenticated,
                                       &complete,
                                       &value,
                                       &display_value,
                                       &more);
        if (GSS_ERROR(major)) {
            displayStatus("gss_get_name_attribute", major, minor);
            break;
        }

        printf("\nAttribute %.*s %s %s %.*s\n",
               (int)attribute->length, (char *)attribute->value,
               authenticated ? "Authenticated" : "",
                complete ? "Complete" : "",
               (int)display_value.length, (char *)display_value.value);

        for (i = 0; i < value.length; i++) {
            if ((i % 32) == 0)
                printf("\n");
            printf("%02x", ((char *)value.value)[i] & 0xFF);
        }

        printf("\n");

        gss_release_buffer(&tmp, &value);
        gss_release_buffer(&tmp, &display_value);
    }
}

static OM_uint32
enumerateAttributes(OM_uint32 *minor,
                    gss_name_t name)
{
    OM_uint32 major, tmp;
    int name_is_MN;
    gss_OID mech = GSS_C_NO_OID;
    gss_buffer_set_t authenticated = GSS_C_NO_BUFFER_SET;
    gss_buffer_set_t asserted = GSS_C_NO_BUFFER_SET;
    gss_buffer_set_t complete = GSS_C_NO_BUFFER_SET;
    unsigned int i;

    major = gss_inquire_name(minor,
                             name,
                             &name_is_MN,
                             &mech,
                             &authenticated,
                             &asserted,
                             &complete);
    if (GSS_ERROR(major)) {
        displayStatus("gss_inquire_name", major, minor);
        goto cleanup;
    }

    if (authenticated != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < authenticated->count; i++)
            dumpAttribute(minor, name, &authenticated->elements[i]);
    }
    if (asserted != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < asserted->count; i++)
            dumpAttribute(minor, name, &asserted->elements[i]);
    }
    if (complete != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < complete->count; i++)
            dumpAttribute(minor, name, &complete->elements[i]);
    }

cleanup:
    gss_release_oid(&tmp, &mech);
    gss_release_buffer_set(&tmp, &authenticated);
    gss_release_buffer_set(&tmp, &asserted);
    gss_release_buffer_set(&tmp, &complete);

    return major;
}

static OM_uint32
testExportImportName(OM_uint32 *minor,
                     gss_name_t name)
{
    OM_uint32 major, tmp;
    gss_buffer_desc exported_name;
    gss_name_t imported_name = GSS_C_NO_NAME;
    unsigned int i;

    exported_name.value = NULL;

    major = gss_export_name_composite(minor,
                                      name,
                                      &exported_name);
    if (GSS_ERROR(major)) {
        displayStatus("gss_export_name_composite", major, *minor);
        return major;
    }

    printf("Exported name:\n");

    for (i = 0; i < exported_name.length; i++) {
        if ((i % 32) == 0)
            printf("\n");
        printf("%02x", ((char *)exported_name.value)[i] & 0xFF);
    }

    printf("\n");

    major = gss_import_name(minor, &exported_name, gss_nt_exported_name,
                            &imported_name);
    if (GSS_ERROR(major)) {
        displayStatus("gss_import_name", major, *minor);
        gss_release_buffer(&tmp, &exported_name);
        return major;
    }

    gss_release_buffer(&tmp, &exported_name);

#if 0
    major = enumerateAttributes(minor, imported_name);
#endif

    gss_release_name(&tmp, &imported_name);

    return major;
}

static OM_uint32
testGreetAuthzData(OM_uint32 *minor,
                   gss_name_t target_name)
{
    OM_uint32 major;
    gss_buffer_desc attr;
    gss_buffer_desc value;

    attr.value = "greet:greeting";
    attr.length = strlen((char *)attr.value);

    value.value = "Hello, acceptor world!";
    value.length = strlen((char *)value.value);

    major = gss_set_name_attribute(minor,
                                   target_name,
                                   1,
                                   &attr,
                                   &value);
    if (GSS_ERROR(major)) {
        if (major != GSS_S_UNAVAILABLE)
            displayStatus("gss_set_name_attribute", major, minor);
        return major;
    }

    return GSS_S_COMPLETE;
}

static OM_uint32
initAcceptSecContext(OM_uint32 *minor,
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

    testGreetAuthzData(minor, target_name);
    displayCanonName(minor, target_name, "Target name");

    major = gss_init_sec_context(minor,
                                 verifier_cred_handle,
                                 &initiator_context,
                                 target_name,
                                 (gss_OID)&spnego_mech,
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
    else {
        displayCanonName(minor, source_name, "Source name");
        enumerateAttributes(minor, source_name);
        testExportImportName(minor, source_name);
    }

    (void) gss_delete_sec_context(minor, &acceptor_context, NULL);
    (void) gss_release_buffer(minor, &token);
    (void) gss_release_buffer(minor, &tmp);

    return major;
}

int main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_cred_id_t cred_handle = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_OID_set_desc mechs;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;

    if (argc > 1) {
        major = krb5_gss_register_acceptor_identity(argv[1]);
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
                             &cred_handle,
                             &actual_mechs,
                             NULL);
    if (GSS_ERROR(major)) {
        displayStatus("gss_acquire_cred", major, minor);
        goto out;
    }

    (void) gss_release_oid_set(&minor, &actual_mechs);

    major = initAcceptSecContext(&minor,
                                 cred_handle,
                                 &delegated_cred_handle);
    if (GSS_ERROR(major))
        goto out;

    printf("\n");

out:
    (void) gss_release_cred(&minor, &delegated_cred_handle);
    (void) gss_release_cred(&minor, &cred_handle);
    (void) gss_release_oid_set(&minor, &actual_mechs);

    return GSS_ERROR(major) ? 1 : 0;
}

