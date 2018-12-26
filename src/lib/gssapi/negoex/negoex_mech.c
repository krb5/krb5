/*
 * Copyright (C) 2011-2018 PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "gssapiP_negoex.h"

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_attrs_for_mech(OM_uint32 *minor,
                                  gss_const_OID mech,
                                  gss_OID_set *mech_attrs,
                                  gss_OID_set *known_mech_attrs)
{
    OM_uint32 major, tmpMinor;

    /* known_mech_attrs is handled by mechglue */
    *minor = 0;

    if (mech_attrs == NULL)
        return GSS_S_COMPLETE;

    major = gss_create_empty_oid_set(minor, mech_attrs);
    if (GSS_ERROR(major))
        goto cleanup;

#define MA_SUPPORTED(ma)    do {                                 \
        major = gss_add_oid_set_member(minor,                    \
                                       (gss_OID)ma, mech_attrs); \
        if (GSS_ERROR(major))                                    \
                goto cleanup;                                    \
    } while (0)

    MA_SUPPORTED(GSS_C_MA_MECH_NEGOEX);
    MA_SUPPORTED(GSS_C_MA_NOT_INDICATED);
    MA_SUPPORTED(GSS_C_MA_SPNEGO_ONLY);

cleanup:
    if (GSS_ERROR(major))
        gss_release_oid_set(&tmpMinor, mech_attrs);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_display_status(OM_uint32 *minor,
                          OM_uint32 status_value,
                          int status_type,
                          gss_OID mech_type,
                          OM_uint32 *message_context,
                          gss_buffer_t status_string)
{
    OM_uint32 major;

    *message_context = 0;

    status_string->length = 0;
    status_string->value = NULL;

    if (status_type != GSS_C_MECH_CODE || *message_context != 0 ||
        (mech_type != GSS_C_NO_OID &&
         !gss_oid_equal(mech_type, GSS_NEGOEX_MECHANISM))) {
        *minor = 0;
        return GSS_S_BAD_STATUS;
    }

    if (negoex_in_call_p()) {
         if (g_make_string_buffer(error_message(status_value), status_string)) {
            major = GSS_S_COMPLETE;
            *minor = 0;
        } else {
            *minor = ENOMEM;
            major = GSS_S_FAILURE;
        }
    } else {
        major = negoex_enter_call(minor);
        if (GSS_ERROR(major))
            goto cleanup;

        major = gss_display_status(minor, status_value, status_type,
                                   mech_type, message_context, status_string);
        if (GSS_ERROR(major))
            goto cleanup;

        major = negoex_leave_call(minor);
        if (GSS_ERROR(major))
            goto cleanup;
    }

cleanup:
    major = GSS_S_COMPLETE;
    *minor = 0;

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_names_for_mech(OM_uint32 *minor,
                                  gss_OID mech,
                                  gss_OID_set *name_types)
{
    OM_uint32 major, tmpMinor;

    if (mech != GSS_C_NULL_OID &&
        !gss_oid_equal(GSS_NEGOEX_MECHANISM, mech)) {
        *minor = 0;
        return GSS_S_UNAVAILABLE;
    }

    major = gss_create_empty_oid_set(minor, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_add_oid_set_member(minor, GSS_C_NT_USER_NAME, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_add_oid_set_member(minor, GSS_C_NT_MACHINE_UID_NAME, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_add_oid_set_member(minor, GSS_C_NT_STRING_UID_NAME, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_add_oid_set_member(minor, GSS_C_NT_HOSTBASED_SERVICE, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    if (GSS_ERROR(major))
        gss_release_oid_set(&tmpMinor, name_types);

    return major;
}
