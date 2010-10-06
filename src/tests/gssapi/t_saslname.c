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

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

static void
displayStatus_1(char *m, OM_uint32 code, int type)
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
displayStatus(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
     displayStatus_1(msg, maj_stat, GSS_C_GSS_CODE);
     displayStatus_1(msg, min_stat, GSS_C_MECH_CODE);
}

static
OM_uint32 dumpMechAttrs(OM_uint32 *minor, gss_OID mech)
{
    OM_uint32 major, tmpMinor;
    gss_OID_set mech_attrs = GSS_C_NO_OID_SET;
    gss_OID_set known_attrs = GSS_C_NO_OID_SET;
    size_t i;

    major = gss_inquire_attrs_for_mech(minor, mech, &mech_attrs, &known_attrs);
    if (GSS_ERROR(major)) {
        displayStatus("gss_inquire_attrs_for_mech", major, *minor);
        return major;
    }

    printf("Mech attrs:  ");

    for (i = 0; i < mech_attrs->count; i++) {
        gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc short_desc = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc long_desc = GSS_C_EMPTY_BUFFER;

        major = gss_display_mech_attr(minor, &mech_attrs->elements[i],
                                      &name, &short_desc, &long_desc);
        if (GSS_ERROR(major)) {
            displayStatus("gss_display_mech_attr", major, *minor);
            continue;
        }
        printf("%.*s ", (int)name.length, (char *)name.value);
        gss_release_buffer(minor, &name);
        gss_release_buffer(minor, &short_desc);
        gss_release_buffer(minor, &long_desc);
    }
    printf("\n");

    printf("Known attrs: ");

    for (i = 0; i < known_attrs->count; i++) {
        gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc short_desc = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc long_desc = GSS_C_EMPTY_BUFFER;

        major = gss_display_mech_attr(minor, &known_attrs->elements[i],
                                      &name, &short_desc, &long_desc);
        if (GSS_ERROR(major)) {
            displayStatus("gss_display_mech_attr", major, *minor);
            continue;
        }
        printf("%.*s ", (int)name.length, (char *)name.value);
        gss_release_buffer(minor, &name);
        gss_release_buffer(minor, &short_desc);
        gss_release_buffer(minor, &long_desc);
    }
    printf("\n");

    gss_release_oid_set(&tmpMinor, &mech_attrs);
    gss_release_oid_set(&tmpMinor, &known_attrs);

    return GSS_S_COMPLETE;
}

int main(int argc, char *argv[])
{
    gss_OID_set mechs;
    OM_uint32 major, minor;
    size_t i;

    major = gss_indicate_mechs(&minor, &mechs);
    if (GSS_ERROR(major)) {
        displayStatus("gss_indicate_mechs", major, minor);
        return major;
    }

    for (i = 0; i < mechs->count; i++) {
        gss_buffer_desc oidstr = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc sasl_mech_name = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc mech_name = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc mech_description = GSS_C_EMPTY_BUFFER;
        gss_OID oid = GSS_C_NO_OID;

        major = gss_oid_to_str(&minor, &mechs->elements[i], &oidstr);
        if (GSS_ERROR(major))
            continue;

        major = gss_inquire_saslname_for_mech(&minor, &mechs->elements[i],
                                              &sasl_mech_name, &mech_name,
                                              &mech_description);
        if (GSS_ERROR(major)) {
            gss_release_buffer(&minor, &oidstr);
            continue;
        }

        printf("-------------------------------------------------------------"
               "-----------------\n");
        printf("OID        : %.*s\n", (int)oidstr.length,
               (char *)oidstr.value);
        printf("SASL mech  : %.*s\n", (int)sasl_mech_name.length,
               (char *)sasl_mech_name.value);
        printf("Mech name  : %.*s\n", (int)mech_name.length,
               (char *)mech_name.value);
        printf("Mech desc  : %.*s\n", (int)mech_description.length,
               (char *)mech_description.value);
        dumpMechAttrs(&minor, &mechs->elements[i]);
        printf("-------------------------------------------------------------"
               "-----------------\n");

        if (GSS_ERROR(gss_inquire_mech_for_saslname(&minor, &sasl_mech_name,
                                                    &oid))) {
            displayStatus("gss_inquire_mech_for_saslname", major, minor);
        } else if (oid == GSS_C_NO_OID ||
            (oid->length != mechs->elements[i].length &&
             memcmp(oid->elements, mechs->elements[i].elements,
                    oid->length) != 0)) {
            gss_release_buffer(&minor, &oidstr);
            (void) gss_oid_to_str(&minor, oid, &oidstr);
            fprintf(stderr, "Got different OID %.*s for mechanism %.*s\n",
                    (int)oidstr.length, (char *)oidstr.value,
                    (int)sasl_mech_name.length, (char *)sasl_mech_name.value);
        }
        gss_release_buffer(&minor, &oidstr);
        gss_release_buffer(&minor, &sasl_mech_name);
        gss_release_buffer(&minor, &mech_name);
        gss_release_buffer(&minor, &mech_description);
    }

    gss_release_oid_set(&minor, &mechs);

    return GSS_ERROR(major) ? 1 : 0;
}
