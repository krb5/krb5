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
negoex_gss_context_time(OM_uint32 *minor,
                        gss_ctx_id_t context_handle,
                        OM_uint32 *time_rec)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_context_time(minor, negoex_active_context(ctx), time_rec);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_get_mic(OM_uint32 *minor,
                   gss_ctx_id_t context_handle,
                   gss_qop_t qop_req,
                   gss_buffer_t message_buffer,
                   gss_buffer_t message_token)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_get_mic(minor, negoex_active_context(ctx),
                       qop_req, message_buffer, message_token);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_verify_mic(OM_uint32 *minor,
                      gss_ctx_id_t context_handle,
                      gss_buffer_t message_buffer,
                      gss_buffer_t message_token,
                      gss_qop_t *qop_state)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_verify_mic(minor, negoex_active_context(ctx),
                          message_buffer, message_token,qop_state);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_wrap(OM_uint32 *minor,
                gss_ctx_id_t context_handle,
                int conf_req_flag,
                gss_qop_t qop_req,
                gss_buffer_t input_message_buffer,
                int *conf_state,
                gss_buffer_t output_message_buffer)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_wrap(minor, negoex_active_context(ctx),
                    conf_req_flag, qop_req,
                    input_message_buffer, conf_state,
                    output_message_buffer);

}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_unwrap(OM_uint32 *minor,
                  gss_ctx_id_t context_handle,
                  gss_buffer_t input_message_buffer,
                  gss_buffer_t output_message_buffer,
                  int *conf_state,
                  gss_qop_t *qop_state)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_unwrap(minor, negoex_active_context(ctx),
                      input_message_buffer, output_message_buffer,
                      conf_state, qop_state);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_compare_name(OM_uint32 *minor,
                        gss_name_t name1,
                        gss_name_t name2,
                        int *name_equal)
{
    return gss_compare_name(minor, name1, name2, name_equal);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_display_name(OM_uint32 *minor,
                        gss_name_t name,
                        gss_buffer_t output_name_buffer,
                        gss_OID *output_name_type)
{
    return gss_display_name(minor, name, output_name_buffer,
                            output_name_type);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_import_name(OM_uint32 *minor,
                       gss_buffer_t import_name_buffer,
                       gss_OID input_name_type,
                       gss_name_t *output_name)
{
    return gss_import_name(minor, import_name_buffer,
                           input_name_type, output_name);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_release_name(OM_uint32 *minor,
                        gss_name_t *name)
{
    return gss_release_name(minor, name);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_export_sec_context(OM_uint32 *minor,
                              gss_ctx_id_t *context_handle,
                              gss_buffer_t interprocess_token)
{
    OM_uint32 major;
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)*context_handle;
    negoex_auth_mech_t mech;

    mech = negoex_active_mech(ctx);
    if (mech == NULL)
        return GSS_S_NO_CONTEXT;

    major = gss_export_sec_context(minor, &mech->Context, interprocess_token);
    if (GSS_ERROR(major))
        return major;

    mech->Context = NULL;

    negoex_release_context(ctx);
    *context_handle = GSS_C_NO_CONTEXT;

    return major;
}

static OM_uint32
negoex_alloc_context_for_mech(OM_uint32 *minor,
                              gss_ctx_id_t *mech_ctx,
                              negoex_ctx_id_t *pCtx)
{
    OM_uint32 major;
    negoex_ctx_id_t ctx = NULL;
    gss_OID mech_type = GSS_C_NO_OID;

    assert(*pCtx == NULL);

    major = negoex_alloc_context(minor, &ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_inquire_context(minor, *mech_ctx, NULL, NULL, &ctx->Lifetime,
                                &mech_type, &ctx->GssFlags, NULL, NULL);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_add_auth_mech(minor, ctx, mech_type);
    if (GSS_ERROR(major))
        goto cleanup;

    negoex_active_mech(ctx)->Context = *mech_ctx;
    *mech_ctx = GSS_C_NO_CONTEXT;

    *pCtx = ctx;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major))
        negoex_release_context(ctx);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_import_sec_context(OM_uint32 *minor,
                              gss_buffer_t interprocess_token,
                              gss_ctx_id_t *context_handle)
{
    OM_uint32 major, tmpMinor;
    negoex_ctx_id_t ctx = NULL;
    gss_ctx_id_t mech_ctx = GSS_C_NO_CONTEXT;

    major = gss_import_sec_context(minor, interprocess_token, &mech_ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_alloc_context_for_mech(minor, &mech_ctx, &ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    *context_handle = (gss_ctx_id_t)ctx;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major)) {
        gss_delete_sec_context(&tmpMinor, &mech_ctx, NULL);
        negoex_release_context(ctx);
    }

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_context(OM_uint32 *minor,
                           gss_ctx_id_t context_handle,
                           gss_name_t *src_name,
                           gss_name_t *target_name,
                           OM_uint32 *lifetime_rec,
                           gss_OID *mech_type,
                           OM_uint32 *ctx_flags,
                           int *locally_initiated,
                           int *is_open)
{
    OM_uint32 major;
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;
    gss_ctx_id_t mechContext;

    if (src_name != NULL)
        *src_name = GSS_C_NO_NAME;
    if (target_name != NULL)
        *target_name = GSS_C_NO_NAME;
    if (lifetime_rec != NULL)
        *lifetime_rec = 0;
    if (mech_type != NULL)
        *mech_type = GSS_NEGOEX_MECHANISM;
    if (ctx_flags != NULL)
        *ctx_flags = 0;
    if (locally_initiated != NULL)
        *locally_initiated = (ctx->Flags & NEGOEX_CTX_FLAG_INITIATOR) != 0;
    if (is_open != NULL)
        *is_open = (ctx->Flags & NEGOEX_CTX_FLAG_MECH_COMPLETE) != 0;

    mechContext = negoex_active_context(ctx);
    if (mechContext == GSS_C_NO_CONTEXT)
        return GSS_S_COMPLETE;

    major = gss_inquire_context(minor, mechContext,
                                src_name, target_name, lifetime_rec,
                                mech_type, ctx_flags, locally_initiated,
                                is_open);
    if ((ctx->Flags & NEGOEX_CTX_FLAG_MECH_COMPLETE) == 0) {
        if (mech_type != NULL)
            *mech_type = GSS_NEGOEX_MECHANISM;

        if (ctx_flags != NULL) {
            *ctx_flags &= ~(GSS_C_PROT_READY_FLAG);
            *ctx_flags &= ~(GSS_C_TRANS_FLAG);
        }
    }

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_wrap_size_limit(OM_uint32 *minor,
                           gss_ctx_id_t context_handle,
                           int conf_req_flag,
                           gss_qop_t qop_req,
                           OM_uint32 req_output_size,
                           OM_uint32 *max_input_size)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_wrap_size_limit(minor, negoex_active_context(ctx),
                               conf_req_flag, qop_req,
                               req_output_size, max_input_size);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_duplicate_name(OM_uint32 *minor,
                          const gss_name_t input_name,
                          gss_name_t *dest_name)
{
    return gss_duplicate_name(minor, input_name, dest_name);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_sec_context_by_oid(OM_uint32 *minor,
                                      const gss_ctx_id_t context_handle,
                                      const gss_OID desired_object,
                                      gss_buffer_set_t *data_set)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_inquire_sec_context_by_oid(minor,
                                          negoex_active_context(ctx),
                                          desired_object, data_set);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_set_sec_context_option(OM_uint32 *minor,
                                  gss_ctx_id_t *pCtx,
                                  const gss_OID desired_object,
                                  const gss_buffer_t value)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)*pCtx;
    gss_ctx_id_t mech_ctx = GSS_C_NO_CONTEXT;
    OM_uint32 major, tmpMinor;

    if (ctx != NULL)
        mech_ctx = negoex_active_context(ctx);

    major = gss_set_sec_context_option(minor, &mech_ctx,
                                       desired_object, value);
    if (GSS_ERROR(major))
        return major;

    if (ctx == NULL) {
        major = negoex_alloc_context_for_mech(minor, &mech_ctx, &ctx);
        if (GSS_ERROR(major)) {
            gss_delete_sec_context(&tmpMinor, &mech_ctx, NULL);
            return major;
        }

        *pCtx = (gss_ctx_id_t)ctx;
    }

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_wrap_iov(OM_uint32 *minor,
                    gss_ctx_id_t context_handle,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    int *conf_state,
                    gss_iov_buffer_desc *iov,
                    int iov_count)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_wrap_iov(minor, negoex_active_context(ctx),
                        conf_req_flag, qop_req, conf_state,
                        iov, iov_count);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_unwrap_iov(OM_uint32 *minor,
                      gss_ctx_id_t context_handle,
                      int *conf_state,
                      gss_qop_t *qop_state,
                      gss_iov_buffer_desc *iov,
                      int iov_count)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_unwrap_iov(minor, negoex_active_context(ctx),
                          conf_state, qop_state, iov, iov_count);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_wrap_iov_length(OM_uint32 *minor,
                           gss_ctx_id_t context_handle,
                           int conf_req_flag,
                           gss_qop_t qop_req,
                           int *conf_state,
                           gss_iov_buffer_desc *iov,
                           int iov_count)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_wrap_iov_length(minor,
                               negoex_active_context(ctx),
                               conf_req_flag,
                               qop_req,
                               conf_state,
                               iov,
                               iov_count);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_complete_auth_token(OM_uint32 *minor,
                               const gss_ctx_id_t context_handle,
                               gss_buffer_t input_message_buffer)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_complete_auth_token(minor, negoex_active_context(ctx),
                                   input_message_buffer);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_display_name_ext(OM_uint32 *minor,
                            gss_name_t name,
                            gss_OID display_as_name_type,
                            gss_buffer_t display_name)
{
    return gss_display_name_ext(minor, name, display_as_name_type,
                               display_name);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_name(OM_uint32 *minor,
                        gss_name_t name,
                        int *name_is_MN,
                        gss_OID *MN_mech,
                        gss_buffer_set_t *attrs)
{
    return gss_inquire_name(minor, name, name_is_MN, MN_mech, attrs);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_get_name_attribute(OM_uint32 *minor,
                              gss_name_t name,
                              gss_buffer_t attr,
                              int *authenticated,
                              int *complete,
                              gss_buffer_t value,
                              gss_buffer_t display_value,
                              int *more)
{
    return gss_get_name_attribute(minor, name, attr, authenticated, complete,
                                  value, display_value, more);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_set_name_attribute(OM_uint32 *minor,
                              gss_name_t name,
                              int complete,
                              gss_buffer_t attr,
                              gss_buffer_t value)
{
    return gss_set_name_attribute(minor, name, complete, attr, value);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_delete_name_attribute(OM_uint32 *minor,
                                 gss_name_t name,
                                 gss_buffer_t attr)
{
    return gss_delete_name_attribute(minor, name, attr);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_export_name_composite(OM_uint32 *minor,
                                 gss_name_t input_name,
                                 gss_buffer_t exported_name)
{
    return gss_export_name_composite(minor, input_name, exported_name);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_map_name_to_any(OM_uint32 *minor,
                           gss_name_t name,
                           int authenticated,
                           gss_buffer_t type_id,
                           gss_any_t *output)
{
    return gss_map_name_to_any(minor, name, authenticated, type_id, output);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_release_any_name_mapping(OM_uint32 *minor,
                                    gss_name_t name,
                                    gss_buffer_t type_id,
                                    gss_any_t *input)
{
    return gss_release_any_name_mapping(minor, name, type_id, input);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_pseudo_random(OM_uint32 *minor,
                         gss_ctx_id_t context_handle,
                         int prf_key,
                         const gss_buffer_t prf_in,
                         ssize_t desired_output_len,
                         gss_buffer_t prf_out)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_pseudo_random(minor, negoex_active_context(ctx),
                             prf_key, prf_in, desired_output_len, prf_out);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_get_mic_iov(OM_uint32 *minor, gss_ctx_id_t context_handle,
                       gss_qop_t qop_req, gss_iov_buffer_desc *iov,
                       int iov_count)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_get_mic_iov(minor, negoex_active_context(ctx), qop_req, iov,
                           iov_count);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_verify_mic_iov(OM_uint32 *minor, gss_ctx_id_t context_handle,
                          gss_qop_t *qop_state, gss_iov_buffer_desc *iov,
                          int iov_count)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_verify_mic_iov(minor, negoex_active_context(ctx), qop_state, iov,
                              iov_count);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_get_mic_iov_length(OM_uint32 *minor,
                              gss_ctx_id_t context_handle, gss_qop_t qop_req,
                              gss_iov_buffer_desc *iov, int iov_count)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)context_handle;

    return gss_get_mic_iov_length(minor, negoex_active_context(ctx), qop_req, iov,
                                  iov_count);
}

