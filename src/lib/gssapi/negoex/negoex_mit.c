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
#include "mglueP.h"

static struct gss_config negoex_mechanism = {
    {10, (void *)"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e"},
    NULL,
    negoex_gss_acquire_cred,
    negoex_gss_release_cred,
    negoex_gss_init_sec_context,
#ifndef LEAN_CLIENT
    negoex_gss_accept_sec_context,
#else
    NULL,
#endif
    NULL,
    negoex_gss_delete_sec_context,
    negoex_gss_context_time,
    negoex_gss_get_mic,
    negoex_gss_verify_mic,
    negoex_gss_wrap,
    negoex_gss_unwrap,
    negoex_gss_display_status,
    NULL,
    negoex_gss_compare_name,
    negoex_gss_display_name,
    negoex_gss_import_name,
    negoex_gss_release_name,
    negoex_gss_inquire_cred,
    NULL,
#ifndef LEAN_CLIENT
    negoex_gss_export_sec_context,
    negoex_gss_import_sec_context,
#else
    NULL,
    NULL,
#endif
    NULL,
    negoex_gss_inquire_names_for_mech,
    negoex_gss_inquire_context,
    NULL,
    negoex_gss_wrap_size_limit,
    NULL,
    NULL,
    NULL,
    negoex_gss_duplicate_name,
    NULL,
    negoex_gss_inquire_sec_context_by_oid,
    negoex_gss_inquire_cred_by_oid,
    negoex_gss_set_sec_context_option,
    negoex_gss_set_cred_option,
    NULL,
    NULL,
    NULL,
    negoex_gss_wrap_iov,
    negoex_gss_unwrap_iov,
    negoex_gss_wrap_iov_length,
    negoex_gss_complete_auth_token,
    negoex_gss_acquire_cred_impersonate_name,
    NULL,
    negoex_gss_display_name_ext,
    negoex_gss_inquire_name,
    negoex_gss_get_name_attribute,
    negoex_gss_set_name_attribute,
    negoex_gss_delete_name_attribute,
    negoex_gss_export_name_composite,
    negoex_gss_map_name_to_any,
    negoex_gss_release_any_name_mapping,
    negoex_gss_pseudo_random,
    negoex_gss_set_neg_mechs,
    NULL,                            /* negoex_gss_inquire_saslname_for_mech, */
    NULL,                            /* negoex_gss_inquire_mech_for_saslname, */
    negoex_gss_inquire_attrs_for_mech,
    negoex_gss_acquire_cred_from,
    NULL,                           /* gss_store_cred_into */
    negoex_gss_acquire_cred_with_password,
    negoex_gss_export_cred,
    negoex_gss_import_cred,
    NULL,                           /* gssspi_import_sec_context_by_mech */
    NULL,                           /* gssspi_import_name_by_mech */
    NULL,                           /* gssspi_import_cred_by_mech */
    negoex_gss_get_mic_iov,
    negoex_gss_verify_mic_iov,
    negoex_gss_get_mic_iov_length
};

gss_OID GSS_NEGOEX_MECHANISM = (gss_OID)&negoex_mechanism.mech_type;

#ifdef _GSS_STATIC_LINK
static int gss_negoexmechglue_init(void)
{
    struct gss_mech_config mech_negoex;

    initialize_nego_error_table();

    memset(&mech_negoex, 0, sizeof(mech_negoex));
    mech_negoex.mech = &negoex_mechanism;
    mech_negoex.mechNameStr = "negoex";
    mech_negoex.mech_type = GSS_C_NO_OID;

    return gssint_register_mechinfo(&mech_negoex);
}
#else
gss_mechanism KRB5_CALLCONV
gss_mech_initialize(void)
{
    return &negoex_mechanism;
}

MAKE_INIT_FUNCTION(gss_krb5int_lib_init);
MAKE_FINI_FUNCTION(gss_krb5int_lib_fini);
int gss_krb5int_lib_init(void);
#endif /* _GSS_STATIC_LINK */

int gss_negoexint_lib_init(void)
{
    int err;

    err = k5_key_register(K5_KEY_GSS_NEGOEX_CALL_DEPTH, NULL);
    if (err)
        return err;

#ifdef _GSS_STATIC_LINK
    return gss_negoexmechglue_init();
#else
    return 0;
#endif
}

void gss_negoexint_lib_fini(void)
{
}

OM_uint32
negoex_enter_call(OM_uint32 *minor)
{
    uintptr_t depth;
    int ret;

    depth = (uintptr_t)k5_getspecific(K5_KEY_GSS_NEGOEX_CALL_DEPTH);
    depth++;

    ret = k5_setspecific(K5_KEY_GSS_NEGOEX_CALL_DEPTH, (void *)depth);
    if (ret) {
        *minor = ret;
        return GSS_S_FAILURE;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
negoex_leave_call(OM_uint32 *minor)
{
    uintptr_t depth;
    int ret;

    depth = (uintptr_t)k5_getspecific(K5_KEY_GSS_NEGOEX_CALL_DEPTH);
    assert(depth > 0);
    depth--;

    ret = k5_setspecific(K5_KEY_GSS_NEGOEX_CALL_DEPTH, (void *)depth);
    if (ret) {
        *minor = ret;
        return GSS_S_FAILURE;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

int
negoex_in_call_p(void)
{
    uintptr_t depth;

    depth = (uintptr_t)k5_getspecific(K5_KEY_GSS_NEGOEX_CALL_DEPTH);

    return !!depth;
}
