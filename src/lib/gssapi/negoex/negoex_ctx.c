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

/*
 * The initial context token emitted by the initiator is a INITIATOR_NEGO
 * message followed by zero or more INITIATOR_META_DATA tokens, and zero
 * or one AP_REQUEST tokens.
 *
 * Upon receiving this, the acceptor computes the list of mutually supported
 * authentication mechanisms and performs the metadata exchange. The output
 * token is ACCEPTOR_NEGO followed by zero or more ACCEPTOR_META_DATA tokens,
 * and zero or one CHALLENGE tokens.
 *
 * Once the metadata exchange is complete and a mechanism is selected, the
 * selected mechanism's context token exchange continues with AP_REQUEST and
 * CHALLENGE messages.
 *
 * Once the context token exchange is complete, VERIFY messages are sent to
 * authenticate the entire exchange.
 */

static OM_uint32
negoex_sm_ap_request(OM_uint32 *minor,
                     negoex_cred_id_t cred,
                     negoex_ctx_id_t ctx,
                     gss_name_t target,
                     gss_OID mech_type,
                     OM_uint32 req_flags,
                     OM_uint32 time_req,
                     gss_channel_bindings_t input_chan_bindings,
                     PMESSAGE_HEADER *pInMessages,
                     ULONG cInMessages,
                     PMESSAGE_HEADER **ppOutMessages,
                     ULONG *pcOutMessages);

negoex_auth_mech_t
negoex_active_mech(negoex_ctx_id_t ctx)
{
    return ctx ? ctx->AuthMechs : NULL;
}

gss_ctx_id_t
negoex_active_context(negoex_ctx_id_t ctx)
{
    negoex_auth_mech_t mech = negoex_active_mech(ctx);
    return mech ? mech->Context : GSS_C_NO_CONTEXT;
}

static PUCHAR
negoex_active_auth_scheme(negoex_ctx_id_t ctx)
{
    negoex_auth_mech_t mech = negoex_active_mech(ctx);
    return mech ? mech->AuthScheme : NULL;
}

static OM_uint32
negoex_locate_mech(OM_uint32 *minor,
                   negoex_ctx_id_t ctx,
                   AUTH_SCHEME authScheme,
                   int active,
                   negoex_auth_mech_t *pMech)
{
    negoex_auth_mech_t mech;

    if (pMech != NULL)
        *pMech = NULL;

    if (authScheme != NULL)
        mech = negoex_locate_auth_scheme(ctx, authScheme);
    else
        mech = ctx->AuthMechs;

    if (mech == NULL) {
        *minor = NEGOEX_NO_AVAILABLE_MECHS;
        return GSS_S_FAILURE;
    }

    if (active && mech != ctx->AuthMechs) {
        *minor = NEGOEX_AUTH_SCHEME_MISMATCH;
        return GSS_S_NO_CONTEXT;
    }

    if (pMech != NULL)
        *pMech = mech;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
negoex_locate_active_mech(OM_uint32 *minor,
                          negoex_ctx_id_t ctx,
                          negoex_auth_mech_t *pMech)
{
    return negoex_locate_mech(minor, ctx, NULL, TRUE, pMech);
}

static void
zero_and_release_buffer_set(gss_buffer_set_t *pBuffers)
{
    OM_uint32 tmpMinor;
    gss_buffer_set_t buffers = *pBuffers;
    ULONG i;

    if (buffers != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < buffers->count; i++)
            negoex_zero_buffer(&buffers->elements[i]);

        gss_release_buffer_set(&tmpMinor, &buffers);
    }

    *pBuffers = GSS_C_NO_BUFFER_SET;
}

static OM_uint32
buffer_set_to_key(OM_uint32 *minor,
                  gss_buffer_set_t buffers,
                  krb5_keyblock *key)
{
    OM_uint32 major;

    /*
     * Returned keys must be formatted similarly to GSS_C_INQ_SSPI_SESSION_KEY,
     * where the first element contains the key and the second element contains
     * and OID wherein the last element is the RFC 3961 encryption type.
     */
    if (buffers->count != 2) {
        *minor = NEGOEX_NO_VERIFY_KEY;
        return GSS_S_FAILURE;
    }

    key->contents = negoex_alloc(&major, minor, buffers->elements[0].length);
    if (GSS_ERROR(major))
        return major;

    key->enctype = ((PUCHAR)buffers->elements[1].value)
                                    [buffers->elements[1].length - 1];

    memcpy(key->contents, buffers->elements[0].value,
           buffers->elements[0].length);
    key->length = buffers->elements[0].length;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
negoex_get_session_keys(OM_uint32 *minor,
                        negoex_ctx_id_t ctx,
                        negoex_auth_mech_t mech)
{
    OM_uint32 major;
    gss_buffer_set_t buffers = GSS_C_NO_BUFFER_SET;

    major = gss_inquire_sec_context_by_oid(minor, mech->Context,
                                           GSS_C_INQ_NEGOEX_KEY,
                                           &buffers);
    if (major == GSS_S_COMPLETE) {
        major = buffer_set_to_key(minor, buffers, &mech->Key);
        if (GSS_ERROR(major))
            goto cleanup;

        zero_and_release_buffer_set(&buffers);
    }

    major = gss_inquire_sec_context_by_oid(minor, mech->Context,
                                           GSS_C_INQ_NEGOEX_VERIFY_KEY,
                                           &buffers);
    if (major == GSS_S_COMPLETE) {
        major = buffer_set_to_key(minor, buffers, &mech->VerifyKey);
        if (GSS_ERROR(major))
            goto cleanup;

        zero_and_release_buffer_set(&buffers);
    }

cleanup:
    zero_and_release_buffer_set(&buffers);

    return GSS_S_COMPLETE;
}

/*
 * Emit INITIATOR_NEGO message.
 */
static OM_uint32
negoex_sm_init_nego(OM_uint32 *minor,
                    negoex_cred_id_t cred,
                    negoex_ctx_id_t ctx,
                    gss_name_t target,
                    gss_OID mech_type,
                    OM_uint32 req_flags,
                    OM_uint32 time_req,
                    gss_channel_bindings_t input_chan_bindings,
                    PMESSAGE_HEADER *pInMessages,
                    ULONG cInMessages,
                    PMESSAGE_HEADER **ppOutMessages,
                    ULONG *pcOutMessages)
{
    PNEGO_MESSAGE initNegoMessage = NULL;
    OM_uint32 major;
    ULONG cbAuthSchemes;
    USHORT cAuthSchemes;
    PAUTH_SCHEME_VECTOR pAuthSchemes;

    assert(ctx->State == NEGOEX_STATE_INITIAL);

    ctx->GssFlags = req_flags;
    ctx->Lifetime = time_req;

    /* On the first call, there should be absolutely no input tokens. */
    if (cInMessages != 0) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = NEGOEX_INVALID_MESSAGE_TYPE;
        goto cleanup;
    }

    major = negoex_random(minor, ctx->ConversationId, CONVERSATION_ID_LENGTH);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_negotiate_mechs(minor, cred, ctx, GSS_C_INITIATE, NULL, NULL);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_pack_auth_schemes(minor, ctx, NULL,
                                     &cAuthSchemes, &cbAuthSchemes);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_alloc_message(minor, ctx, MESSAGE_TYPE_INITIATOR_NEGO,
                                 NEGO_MESSAGE_HEADER_LENGTH,
                                 NEGO_MESSAGE_HEADER_LENGTH + cbAuthSchemes,
                                 (PMESSAGE_HEADER *)&initNegoMessage);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_random(minor, initNegoMessage->Random, 32);
    if (GSS_ERROR(major))
        goto cleanup;

    initNegoMessage->ProtocolVersion = 0;

    pAuthSchemes = &initNegoMessage->AuthSchemes;
    pAuthSchemes->AuthSchemeArrayOffset =
        initNegoMessage->Header.cbHeaderLength;
    pAuthSchemes->AuthSchemeCount = cAuthSchemes;

    major = negoex_pack_auth_schemes(minor, ctx,
                                     (PUCHAR)initNegoMessage +
                                        pAuthSchemes->AuthSchemeArrayOffset,
                                     &cAuthSchemes, &cbAuthSchemes);
    if (GSS_ERROR(major))
        goto cleanup;

    negoex_trace_auth_schemes("Proposed",
                              (PUCHAR)initNegoMessage, pAuthSchemes);

    major = negoex_add_message(minor, &initNegoMessage->Header,
                               ppOutMessages, pcOutMessages);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_CONTINUE_NEEDED;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major))
        negoex_free(initNegoMessage);

    return major;
}

/*
 * Check for any unrecognised critical extensions. Critical extensions
 * have their high bit set.
 */
static OM_uint32
negoex_validate_extensions(OM_uint32 *minor,
                           PNEGO_MESSAGE negoMessage)
{
    PEXTENSION extension;
    ULONG i;

    extension = (PEXTENSION)((PUCHAR)negoMessage + /* unaligned */
                             negoMessage->Extensions.ExtensionArrayOffset);

    for (i = 0; i < negoMessage->Extensions.ExtensionCount; i++) {
        if (extension->ExtensionType & EXTENSION_FLAG_CRITICAL) {
            *minor = NEGOEX_UNSUPPORTED_CRITICAL_EXTENSION;
            return GSS_S_UNAVAILABLE;
        }

        extension++;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

/*
 * Emit ACCEPTOR_NEGO message.
 */
static OM_uint32
negoex_sm_accept_nego(OM_uint32 *minor,
                      negoex_cred_id_t cred,
                      negoex_ctx_id_t ctx,
                      gss_name_t target,
                      gss_OID mech_type,
                      OM_uint32 req_flags,
                      OM_uint32 time_req,
                      gss_channel_bindings_t input_chan_bindings,
                      PMESSAGE_HEADER *pInMessages,
                      ULONG cInMessages,
                      PMESSAGE_HEADER **ppOutMessages,
                      ULONG *pcOutMessages)
{
    PNEGO_MESSAGE initNegoMessage = NULL;
    PNEGO_MESSAGE acceptNegoMessage = NULL;
    OM_uint32 major;
    USHORT cAuthSchemes;
    ULONG cbAuthSchemes;
    PAUTH_SCHEME_VECTOR pAuthSchemes;

    assert(ctx->State == NEGOEX_STATE_NEGOTIATE);

    initNegoMessage = (PNEGO_MESSAGE)negoex_locate_message(pInMessages, cInMessages,
                                                           MESSAGE_TYPE_INITIATOR_NEGO);
    if (initNegoMessage == NULL) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = NEGOEX_MISSING_NEGO_MESSAGE;
        goto cleanup;
    }

    negoex_trace_auth_schemes("Proposed",
                              (PUCHAR)initNegoMessage, &initNegoMessage->AuthSchemes);

    major = negoex_validate_extensions(minor, initNegoMessage);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_negotiate_mechs(minor, cred, ctx, GSS_C_ACCEPT,
                                   initNegoMessage, &initNegoMessage->AuthSchemes);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_pack_auth_schemes(minor, ctx, NULL,
                                     &cAuthSchemes, &cbAuthSchemes);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_alloc_message(minor, ctx, MESSAGE_TYPE_ACCEPTOR_NEGO,
                                 NEGO_MESSAGE_HEADER_LENGTH,
                                 NEGO_MESSAGE_HEADER_LENGTH + cbAuthSchemes,
                                 (PMESSAGE_HEADER *)&acceptNegoMessage);
    if (GSS_ERROR(major))
        goto cleanup;

    major = negoex_random(minor, acceptNegoMessage->Random, 32);
    if (GSS_ERROR(major))
        goto cleanup;

    acceptNegoMessage->ProtocolVersion = 0;

    pAuthSchemes = &acceptNegoMessage->AuthSchemes;
    pAuthSchemes->AuthSchemeArrayOffset =
        acceptNegoMessage->Header.cbHeaderLength;
    pAuthSchemes->AuthSchemeCount = cAuthSchemes;

    major = negoex_pack_auth_schemes(minor, ctx,
                                     (PUCHAR)acceptNegoMessage +
                                        pAuthSchemes->AuthSchemeArrayOffset,
                                     &cAuthSchemes, &cbAuthSchemes);
    if (GSS_ERROR(major))
        goto cleanup;

    negoex_trace_auth_schemes("Available",
                              (PUCHAR)acceptNegoMessage, pAuthSchemes);

    major = negoex_add_message(minor, &acceptNegoMessage->Header,
                               ppOutMessages, pcOutMessages);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_CONTINUE_NEEDED;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major))
        negoex_free(acceptNegoMessage);

    return major;
}

/*
 * Process ACCEPTOR_NEGO message.
 */
static OM_uint32
negoex_sm_init_nego2(OM_uint32 *minor,
                     negoex_cred_id_t cred,
                     negoex_ctx_id_t ctx,
                     gss_name_t target,
                     gss_OID mech_type,
                     OM_uint32 req_flags,
                     OM_uint32 time_req,
                     gss_channel_bindings_t input_chan_bindings,
                     PMESSAGE_HEADER *pInMessages,
                     ULONG cInMessages,
                     PMESSAGE_HEADER **ppOutMessages,
                     ULONG *pcOutMessages)
{
    PNEGO_MESSAGE acceptNegoMessage = NULL;
    PAUTH_SCHEME_VECTOR pAuthSchemes;
    OM_uint32 major;

    assert(ctx->State == NEGOEX_STATE_NEGOTIATE);

    acceptNegoMessage = (PNEGO_MESSAGE)
        negoex_locate_message(pInMessages, cInMessages,
                              MESSAGE_TYPE_ACCEPTOR_NEGO);
    if (acceptNegoMessage == NULL) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = NEGOEX_MISSING_NEGO_MESSAGE;
        goto cleanup;
    }

    pAuthSchemes = &acceptNegoMessage->AuthSchemes;

    negoex_trace_auth_schemes("Available",
                              (PUCHAR)acceptNegoMessage, pAuthSchemes);

    major = negoex_validate_extensions(minor, acceptNegoMessage);
    if (GSS_ERROR(major))
        goto cleanup;

    /* The initiator selects the security mechanism here */
    major = negoex_common_auth_schemes(minor, ctx,
                                       (AUTH_SCHEME *)((PUCHAR)acceptNegoMessage +
                                            pAuthSchemes->AuthSchemeArrayOffset),
                                       pAuthSchemes->AuthSchemeCount);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_CONTINUE_NEEDED;
    *minor = 0;

cleanup:
    return major;
}

/*
 * Get metadata for negotiated mechanisms.
 */
static OM_uint32
negoex_sm_query_meta_data(OM_uint32 *minor,
                          negoex_cred_id_t cred,
                          negoex_ctx_id_t ctx,
                          gss_name_t target,
                          gss_OID mech_type,
                          OM_uint32 req_flags,
                          OM_uint32 time_req,
                          gss_channel_bindings_t input_chan_bindings,
                          PMESSAGE_HEADER *pInMessages,
                          ULONG cInMessages,
                          PMESSAGE_HEADER **ppOutMessages,
                          ULONG *pcOutMessages)
{
    OM_uint32 major, tmpMinor;
    negoex_auth_mech_t p;
    MESSAGE_TYPE type;

    if (ctx->Flags & NEGOEX_CTX_FLAG_INITIATOR) {
        assert(ctx->State == NEGOEX_STATE_INITIAL);
        type = MESSAGE_TYPE_INITIATOR_META_DATA;
    } else {
        assert(ctx->State == NEGOEX_STATE_NEGOTIATE);
        type = MESSAGE_TYPE_ACCEPTOR_META_DATA;
    }

    for (p = ctx->AuthMechs; p != NULL; p = p->Next) {
        gss_buffer_desc metaData = GSS_C_EMPTY_BUFFER;

        major = gss_query_meta_data(minor,
                                    p->Oid,
                                    cred ? cred->Credential : GSS_C_NO_CREDENTIAL,
                                    &p->Context,
                                    target,
                                    req_flags,
                                    &metaData);
        if (GSS_ERROR(major)) {
            /* GSS_Query_meta_data failure removes mechanism from list */
            negoex_delete_auth_mech(ctx, &p);
            major = GSS_S_COMPLETE;
            if (p == NULL)
                break;
            continue;
        }

        if (metaData.value == NULL)
            continue;

        major = negoex_add_exchange_message(minor,
                                            ctx,
                                            type,
                                            p->AuthScheme,
                                            &metaData,
                                            ppOutMessages,
                                            pcOutMessages);
        if (GSS_ERROR(major)) {
            gss_release_buffer(&tmpMinor, &metaData);
            break;
        }
        gss_release_buffer(&tmpMinor, &metaData);
    }

    if (major == GSS_S_COMPLETE) {
        if ((ctx->Flags & NEGOEX_CTX_FLAG_INITIATOR) == 0)
            ctx->State = NEGOEX_STATE_AUTHENTICATE;

        major = GSS_S_CONTINUE_NEEDED;
    }

    return major;
}

static void
negoex_get_byte_vector(PMESSAGE_HEADER message,
                       PBYTE_VECTOR byteVector,
                       gss_buffer_t buffer)
{
    buffer->length = byteVector->ByteArrayLength;
    buffer->value = (PUCHAR)message + byteVector->ByteArrayOffset;
}

/*
 * Process metadata for negotiated mechanisms.
 */
static OM_uint32
negoex_sm_exchange_meta_data(OM_uint32 *minor,
                             negoex_cred_id_t cred,
                             negoex_ctx_id_t ctx,
                             gss_name_t target,
                             gss_OID mech_type,
                             OM_uint32 req_flags,
                             OM_uint32 time_req,
                             gss_channel_bindings_t input_chan_bindings,
                             PMESSAGE_HEADER *pInMessages,
                             ULONG cInMessages,
                             PMESSAGE_HEADER **ppOutMessages,
                             ULONG *pcOutMessages)
{
    OM_uint32 major;
    negoex_auth_mech_t mech;
    MESSAGE_TYPE type;
    ULONG i;

    assert(ctx->State == NEGOEX_STATE_NEGOTIATE);

    if (ctx->Flags & NEGOEX_CTX_FLAG_INITIATOR) {
        type = MESSAGE_TYPE_ACCEPTOR_META_DATA;
    } else {
        type = MESSAGE_TYPE_INITIATOR_META_DATA;
    }

    for (i = 0; i < cInMessages; i++) {
        PEXCHANGE_MESSAGE message;
        gss_buffer_desc metaData;

        if (pInMessages[i]->MessageType != type)
            continue;

        message = (PEXCHANGE_MESSAGE)pInMessages[i];

        mech = negoex_locate_auth_scheme(ctx, message->AuthScheme);
        if (mech == NULL)
            continue;

        negoex_get_byte_vector(&message->Header, &message->Exchange, &metaData);

        major = gss_exchange_meta_data(minor,
                                       mech->Oid,
                                       cred ? cred->Credential
                                            : GSS_C_NO_CREDENTIAL,
                                       &mech->Context,
                                       target,
                                       req_flags,
                                       &metaData);
        if (GSS_ERROR(major)) {
            /* GSS_Exchange_meta_data failure removes mechanism from list */
            negoex_delete_auth_mech(ctx, &mech);
            continue;
        }
    }

    major = negoex_locate_active_mech(minor, ctx, &mech);
    if (GSS_ERROR(major))
        return major;

    if (major == GSS_S_COMPLETE) {
        if (ctx->Flags & NEGOEX_CTX_FLAG_INITIATOR) {
            /*
             * Commit this context to the selected authentication mechanism.
             */
            negoex_select_auth_mech(ctx, mech);
            ctx->State = NEGOEX_STATE_AUTHENTICATE;
        }

        major = GSS_S_CONTINUE_NEEDED;
    }

    return major;
}

/*
 * Call gss_init_sec_context for selected mechanism.
 */
static OM_uint32
negoex_sm_ap_request(OM_uint32 *minor,
                     negoex_cred_id_t cred,
                     negoex_ctx_id_t ctx,
                     gss_name_t target,
                     gss_OID mech_type,
                     OM_uint32 req_flags,
                     OM_uint32 time_req,
                     gss_channel_bindings_t input_chan_bindings,
                     PMESSAGE_HEADER *pInMessages,
                     ULONG cInMessages,
                     PMESSAGE_HEADER **ppOutMessages,
                     ULONG *pcOutMessages)
{
    OM_uint32 major, tmpMajor, tmpMinor;
    negoex_auth_mech_t mech = NULL;
    gss_buffer_desc inputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc outputToken = GSS_C_EMPTY_BUFFER;
    PEXCHANGE_MESSAGE challenge;

    if (ctx->Flags & NEGOEX_CTX_FLAG_MECH_COMPLETE)
        return GSS_S_CONTINUE_NEEDED;

    /* Disable sending of optimistic token for testing */
    if (ctx->State < NEGOEX_STATE_AUTHENTICATE) {
        if (getenv("NEGOEX_NO_OPTIMISTIC_TOKEN"))
            return GSS_S_CONTINUE_NEEDED;

        ctx->Flags |= NEGOEX_CTX_FLAG_OPTIMISTIC;
    }

    challenge = (PEXCHANGE_MESSAGE)
        negoex_locate_message(pInMessages, cInMessages,
                              MESSAGE_TYPE_CHALLENGE);
    if (challenge != NULL) {
        negoex_get_byte_vector(&challenge->Header, &challenge->Exchange,
                               &inputToken);
    }

    major = negoex_locate_mech(minor, ctx,
                               challenge ? challenge->AuthScheme : NULL,
                               TRUE, &mech);
    if (GSS_ERROR(major))
        return major;

    if (challenge == NULL &&
        ctx->State == NEGOEX_STATE_AUTHENTICATE &&
        (ctx->Flags & NEGOEX_CTX_FLAG_OPTIMISTIC)) {
        /* Acceptor ignored optimistic token, restart authentication */
        gss_delete_sec_context(&tmpMinor, &mech->Context, NULL);
        ctx->Flags &= ~(NEGOEX_CTX_FLAG_OPTIMISTIC);
    }

    major = gss_init_sec_context(minor,
                                 cred ? cred->Credential : GSS_C_NO_CREDENTIAL,
                                 &mech->Context,
                                 target,
                                 mech->Oid,
                                 req_flags,
                                 time_req,
                                 input_chan_bindings,
                                 challenge ? &inputToken : GSS_C_NO_BUFFER,
                                 &ctx->ActualMech,
                                 &outputToken,
                                 &ctx->GssFlags,
                                 &ctx->Lifetime);

    if (outputToken.value != NULL) {
        tmpMajor = negoex_add_exchange_message(&tmpMinor,
                                               ctx,
                                               MESSAGE_TYPE_AP_REQUEST,
                                               mech->AuthScheme,
                                               &outputToken,
                                               ppOutMessages,
                                               pcOutMessages);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
        }
    }

    if (major == GSS_S_COMPLETE) {
        ctx->Flags |= NEGOEX_CTX_FLAG_MECH_COMPLETE;
        major = GSS_S_CONTINUE_NEEDED;
    }

    if (GSS_ERROR(major)) {
        if (ctx->State < NEGOEX_STATE_AUTHENTICATE) {
            /*
             * This was an optimistic or error token; pretend this never happened.
             */
            gss_delete_sec_context(&tmpMinor, &mech->Context, NULL);
            major = GSS_S_CONTINUE_NEEDED;
            *minor = 0;
        }
    } else {
        tmpMajor = negoex_get_session_keys(&tmpMinor, ctx, mech);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
        }
    }

    gss_release_buffer(&tmpMinor, &outputToken);

    return major;
}

/*
 * Call gss_accept_sec_context for selected mechanism. The state is
 * NEGOTIATE on entry, and advanced to AUTHENTICATE as soon as an
 * additional context token is emitted, or INITIATOR_VERIFY once the
 * selected mechanism context is complete.
 */
static OM_uint32
negoex_sm_challenge(OM_uint32 *minor,
                    negoex_cred_id_t cred,
                    negoex_ctx_id_t ctx,
                    gss_name_t target,
                    gss_OID mech_type,
                    OM_uint32 req_flags,
                    OM_uint32 time_req,
                    gss_channel_bindings_t input_chan_bindings,
                    PMESSAGE_HEADER *pInMessages,
                    ULONG cInMessages,
                    PMESSAGE_HEADER **ppOutMessages,
                    ULONG *pcOutMessages)
{
    OM_uint32 major, tmpMajor, tmpMinor;
    negoex_auth_mech_t mech;
    gss_buffer_desc inputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc outputToken = GSS_C_EMPTY_BUFFER;
    PEXCHANGE_MESSAGE apRequest;

    assert(ctx->State >= NEGOEX_STATE_NEGOTIATE &&
           ctx->State < NEGOEX_STATE_COMPLETE);

    if (ctx->Flags & NEGOEX_CTX_FLAG_MECH_COMPLETE)
        return GSS_S_CONTINUE_NEEDED;

    apRequest = (PEXCHANGE_MESSAGE)
        negoex_locate_message(pInMessages, cInMessages,
                              MESSAGE_TYPE_AP_REQUEST);
    if (apRequest != NULL) {
        /* Get the token from the initiator */
        negoex_get_byte_vector(&apRequest->Header, &apRequest->Exchange,
                               &inputToken);
    } else if (ctx->State == NEGOEX_STATE_NEGOTIATE) {
        /* Optimistic tokens are optional */
        *minor = 0;
        return GSS_S_CONTINUE_NEEDED;
    } else {
        *minor = NEGOEX_MISSING_AP_REQUEST_MESSAGE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    mech = negoex_locate_auth_scheme(ctx, apRequest->AuthScheme);
    if (mech == NULL) {
        *minor = NEGOEX_NO_AVAILABLE_MECHS;
        return GSS_S_FAILURE;
    }

    if ((ctx->Flags & NEGOEX_CTX_FLAG_MECH_SELECTED) &&
        mech != negoex_active_mech(ctx)) {
        *minor = NEGOEX_AUTH_SCHEME_MISMATCH;
        return GSS_S_BAD_MECH;
    }

    if (ctx->InitiatorName != GSS_C_NO_NAME)
        gss_release_name(&tmpMinor, &ctx->InitiatorName);
    if (ctx->ActualMech != GSS_C_NO_OID)
        gss_release_oid(&tmpMinor, &ctx->ActualMech);
    if (ctx->DelegCred != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&tmpMinor, &ctx->DelegCred);

    major = gss_accept_sec_context(minor,
                                   &mech->Context,
                                   cred ? cred->Credential : GSS_C_NO_CREDENTIAL,
                                   apRequest ? &inputToken : GSS_C_NO_BUFFER,
                                   input_chan_bindings,
                                   &ctx->InitiatorName,
                                   &ctx->ActualMech,
                                   &outputToken,
                                   &ctx->GssFlags,
                                   &ctx->Lifetime,
                                   &ctx->DelegCred);
    if (outputToken.value != NULL) {
        tmpMajor = negoex_add_exchange_message(&tmpMinor,
                                               ctx,
                                               MESSAGE_TYPE_CHALLENGE,
                                               mech->AuthScheme,
                                               &outputToken,
                                               ppOutMessages,
                                               pcOutMessages);
         if (GSS_ERROR(tmpMajor)) {
             major = tmpMajor;
             *minor = tmpMinor;
         }
    }

    if (major == GSS_S_COMPLETE) {
        ctx->Flags |= NEGOEX_CTX_FLAG_MECH_COMPLETE;
        major = GSS_S_CONTINUE_NEEDED;
    }

    if (GSS_ERROR(major)) {
        if (ctx->State < NEGOEX_STATE_AUTHENTICATE) {
            /*
             * This was an optimistic token; pretend this never happened.
             */
            major = GSS_S_CONTINUE_NEEDED;
            *minor = 0;
            gss_delete_sec_context(&tmpMinor, &mech->Context, NULL);
        }
    } else {
        if ((ctx->Flags & NEGOEX_CTX_FLAG_MECH_SELECTED) == 0) {
            /*
             * Commit this context to the selected authentication mechanism.
             */
            negoex_select_auth_mech(ctx, mech);
        }

        tmpMajor = negoex_get_session_keys(&tmpMinor, ctx, mech);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
        }
    }

    gss_release_buffer(&tmpMinor, &outputToken);

    return major;
}

static krb5_keyusage
negoex_verify_keyusage(negoex_ctx_id_t ctx,
                       int makeChecksum)
{
    int initChecksum;
    krb5_keyusage usage;

    initChecksum = ((ctx->Flags & NEGOEX_CTX_FLAG_INITIATOR) != 0);
    initChecksum ^= !makeChecksum;

    /* Of course, these are the wrong way around in the spec. */
    if (initChecksum)
        usage = NEGOEX_KEYUSAGE_ACCEPTOR_CHECKSUM;
    else
        usage = NEGOEX_KEYUSAGE_INITIATOR_CHECKSUM;

    return usage;
}

static OM_uint32
negoex_locate_checksum(OM_uint32 *minor,
                       negoex_ctx_id_t ctx,
                       PMESSAGE_HEADER *pInMessages,
                       ULONG cInMessages,
                       krb5_checksum *cksum,
                       negoex_auth_mech_t *pMech)
{
    OM_uint32 major;
    PVERIFY_MESSAGE verifyMessage;
    PCHECKSUM checksum;

    verifyMessage = (PVERIFY_MESSAGE)
        negoex_locate_message(pInMessages, cInMessages, MESSAGE_TYPE_VERIFY);
    if (verifyMessage == NULL) {
        *minor = NEGOEX_MISSING_VERIFY_MESSAGE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    major = negoex_locate_mech(minor, ctx,
                               verifyMessage->AuthScheme,
                               TRUE, pMech);
    if (GSS_ERROR(major))
        return major;

    checksum = &verifyMessage->Checksum;

    if (checksum->cbHeaderLength != CHECKSUM_HEADER_LENGTH) {
        *minor = NEGOEX_INVALID_MESSAGE_SIZE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (checksum->ChecksumScheme != CHECKSUM_SCHEME_RFC3961) {
        *minor = NEGOEX_UNKNOWN_CHECKSUM_SCHEME;
        return GSS_S_UNAVAILABLE;
    }

    cksum->checksum_type = checksum->ChecksumType;
    cksum->length        = checksum->ChecksumValue.ByteArrayLength;
    cksum->contents      = (PUCHAR)verifyMessage +
                           checksum->ChecksumValue.ByteArrayOffset;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
negoex_pack_checksum(OM_uint32 *minor,
                     negoex_ctx_id_t ctx,
                     krb5_checksum *cksum,
                     PMESSAGE_HEADER **ppOutMessages,
                     ULONG *pcOutMessages)
{
    OM_uint32 major;
    PVERIFY_MESSAGE verifyMessage;
    PCHECKSUM checksum;

    major = negoex_alloc_message(minor, ctx, MESSAGE_TYPE_VERIFY,
                                 VERIFY_MESSAGE_HEADER_LENGTH,
                                 VERIFY_MESSAGE_HEADER_LENGTH + cksum->length,
                                 (PMESSAGE_HEADER *)&verifyMessage);
    if (GSS_ERROR(major))
        return major;

    memcpy(verifyMessage->AuthScheme, negoex_active_auth_scheme(ctx),
           AUTH_SCHEME_LENGTH);

    checksum = &verifyMessage->Checksum;

    checksum->cbHeaderLength                = CHECKSUM_HEADER_LENGTH;
    checksum->ChecksumScheme                = CHECKSUM_SCHEME_RFC3961;
    checksum->ChecksumType                  = cksum->checksum_type;
    checksum->ChecksumValue.ByteArrayOffset = verifyMessage->Header.cbHeaderLength;
    checksum->ChecksumValue.ByteArrayLength = cksum->length;

    memcpy((PUCHAR)verifyMessage + checksum->ChecksumValue.ByteArrayOffset,
           cksum->contents, cksum->length);

    major = negoex_add_message(minor, &verifyMessage->Header,
                               ppOutMessages, pcOutMessages);

    return major;
}

static OM_uint32
negoex_append_pending_messages(OM_uint32 *minor,
                               PMESSAGE_HEADER *pMessages,
                               ULONG cMessages,
                               gss_buffer_t token)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc pending = GSS_C_EMPTY_BUFFER;

    major = negoex_make_token(minor, pMessages, cMessages, &pending);
    if (GSS_ERROR(major))
        return major;

    token->value = negoex_realloc(&major, minor,
                                  token->value,
                                  token->length + pending.length);
    if (GSS_ERROR(major)) {
        gss_release_buffer(&tmpMinor, &pending);
        return major;
    }

    memcpy((PUCHAR)token->value + token->length, pending.value, pending.length);
    token->length += pending.length;

    gss_release_buffer(&tmpMinor, &pending);

    return GSS_S_COMPLETE;
}


static OM_uint32
negoex_checksum(OM_uint32 *minor,
                negoex_ctx_id_t ctx,
                PMESSAGE_HEADER *pInMessages,
                ULONG cInMessages,
                PMESSAGE_HEADER **ppOutMessages,
                ULONG *pcOutMessages,
                int makeChecksum)
{
    OM_uint32 major, tmpMinor;
    krb5_error_code code;
    krb5_context context = NULL;
    krb5_cksumtype cksumtype;
    krb5_keyblock *key;
    krb5_keyusage usage = negoex_verify_keyusage(ctx, makeChecksum);
    krb5_data input;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    krb5_checksum cksum;
    negoex_auth_mech_t mech = NULL;
    ULONG messageCount;

    memset(&cksum, 0, sizeof(cksum));

    if (makeChecksum)
        major = negoex_locate_active_mech(minor, ctx, &mech);
    else
        major = negoex_locate_checksum(minor, ctx,
                                       pInMessages, cInMessages,
                                       &cksum, &mech);
    if (GSS_ERROR(major))
        goto cleanup;

    assert(mech != NULL);

    key = makeChecksum ? &mech->Key : &mech->VerifyKey;
    if (key->enctype == ENCTYPE_NULL || key->length == 0) {
        major = GSS_S_UNAVAILABLE;
        *minor = NEGOEX_NO_VERIFY_KEY;
        goto cleanup;
    }

    messageCount = ctx->MessageCount;
    assert(cInMessages <= messageCount);

    if (!makeChecksum)
        messageCount--; /* don't include checksum itself */

    major = negoex_make_token(minor, ctx->Messages, messageCount, &token);
    if (GSS_ERROR(major))
        return major;

    if (makeChecksum) {
        major = negoex_append_pending_messages(minor, *ppOutMessages,
                                               *pcOutMessages, &token);
        if (GSS_ERROR(major))
            return major;
    }

    input.length = token.length;
    input.data   = token.value;

    code = krb5_init_context(&context);
    if (code != 0) {
        major = GSS_S_FAILURE;
        *minor = code;
        goto cleanup;
    }

    if (makeChecksum) {
        code = krb5int_c_mandatory_cksumtype(context, key->enctype, &cksumtype);
        if (code == 0)
            code = krb5_c_make_checksum(context, cksumtype, key,
                                        usage, &input, &cksum);
    } else {
        krb5_boolean valid = FALSE;

        code = krb5_c_verify_checksum(context, key, usage, &input,
                                      &cksum, &valid);
        if (code == 0 && !valid) {
            major = GSS_S_BAD_SIG;
            *minor = NEGOEX_INVALID_CHECKSUM;
            goto cleanup;
        }
    }
    if (code != 0) {
        major = GSS_S_FAILURE;
        *minor = code;
        goto cleanup;
    }

    if (makeChecksum) {
        major = negoex_pack_checksum(minor, ctx, &cksum,
                                     ppOutMessages, pcOutMessages);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (makeChecksum)
        krb5_free_checksum_contents(context, &cksum);
    gss_release_buffer(&tmpMinor, &token);
    krb5_free_context(context);

    return major;
}

static OM_uint32
negoex_sm_verify(OM_uint32 *minor,
                 negoex_cred_id_t cred,
                 negoex_ctx_id_t ctx,
                 gss_name_t target,
                 gss_OID mech_type,
                 OM_uint32 req_flags,
                 OM_uint32 time_req,
                 gss_channel_bindings_t input_chan_bindings,
                 PMESSAGE_HEADER *pInMessages,
                 ULONG cInMessages,
                 PMESSAGE_HEADER **ppOutMessages,
                 ULONG *pcOutMessages)
{
    OM_uint32 major = GSS_S_COMPLETE;
    int didMakeChecksum = 0;

    /*
     * The specification says:
     *
     *  "When there is a shared key established, a VERIFY message is
     *   produced using the required checksum mechanism per RFC 3961
     *   and included in the output token."
     *
     * It says nothing about whether the context is actually complete
     * at this point. We need to handle the case where the acceptor
     * sends the checksum before the initiator.
     *
     * The state is managed as follows:
     *
     *  NEGOEX_STATE_VERIFY             Checksum has been generated
     *  NEGOEX_CTX_FLAG_MECH_COMPLETE   Mech context is established
     *  NEGOEX_CTX_FLAG_PEER_VERIFIED   Checksum has been verified
     *
     * GSS_S_COMPLETE is not returned to the caller until all three
     * independent variables satisfied.
     */
    if (ctx->State < NEGOEX_STATE_VERIFY) {
        /*
         * Attempt to generate a signature for the conversation thus
         * far. Not having a verify key is a soft error unless the
         * mechanism context is complete.
         */
        major = negoex_checksum(minor, ctx, pInMessages, cInMessages,
                                ppOutMessages, pcOutMessages, TRUE);
        if (major == GSS_S_COMPLETE) {
            didMakeChecksum = TRUE;
        } else if (*minor == (OM_uint32)NEGOEX_NO_VERIFY_KEY &&
            (ctx->Flags & NEGOEX_CTX_FLAG_MECH_COMPLETE) == 0) {
            /*
             * If we just made an optimistic AP_REQUEST, then here is where
             * we advance the state. This is to handle the case where we are
             * able to generate a signature from the first optimistic call.
             */
            if (ctx->State == NEGOEX_STATE_INITIAL) {
                assert(ctx->Flags & NEGOEX_CTX_FLAG_INITIATOR);
                ctx->State = NEGOEX_STATE_NEGOTIATE;
            }
#if 0
            /* Alert the peer that we don't have a key just yet */
            major = negoex_pulse(minor, ctx, ALERT_VERIFY_NO_KEY,
                                 ppOutMessages, pcOutMessages);
#else
            major = GSS_S_CONTINUE_NEEDED;
#endif
        }
    }

    if ((ctx->Flags & NEGOEX_CTX_FLAG_PEER_VERIFIED) == 0) {
        /*
         * Check whether the peer sent a checksum. This is optional
         * unless we are in the VERIFY state.
         */
        major = negoex_checksum(minor, ctx, pInMessages, cInMessages,
                                ppOutMessages, pcOutMessages, FALSE);
        if (major == GSS_S_COMPLETE) {
            ctx->Flags |= NEGOEX_CTX_FLAG_PEER_VERIFIED;
        } else if (ctx->State < NEGOEX_STATE_VERIFY &&
                   (*minor == (OM_uint32)NEGOEX_NO_VERIFY_KEY ||
                    *minor == (OM_uint32)NEGOEX_MISSING_VERIFY_MESSAGE)) {
            major = GSS_S_CONTINUE_NEEDED;
        }
    }

    if (GSS_ERROR(major))
        return major;

    if (didMakeChecksum && ctx->State == NEGOEX_STATE_AUTHENTICATE)
        ctx->State = NEGOEX_STATE_VERIFY;

    if (ctx->State == NEGOEX_STATE_VERIFY &&
        (ctx->Flags & NEGOEX_CTX_FLAG_MECH_COMPLETE) &&
        (ctx->Flags & NEGOEX_CTX_FLAG_PEER_VERIFIED)) {
        ctx->State = NEGOEX_STATE_COMPLETE;
        major = GSS_S_COMPLETE;
    } else {
        major = GSS_S_CONTINUE_NEEDED;
    }

    *minor = 0;
    return major;
}

static OM_uint32
negoex_sm_alert(OM_uint32 *minor,
                negoex_cred_id_t cred,
                negoex_ctx_id_t ctx,
                gss_name_t target,
                gss_OID mech_type,
                OM_uint32 req_flags,
                OM_uint32 time_req,
                gss_channel_bindings_t input_chan_bindings,
                PMESSAGE_HEADER *pInMessages,
                ULONG cInMessages,
                PMESSAGE_HEADER **ppOutMessages,
                ULONG *pcOutMessages)
{
    PALERT_MESSAGE alertMessage;
    PALERT pAlerts;
    ULONG i;
    OM_uint32 major = GSS_S_CONTINUE_NEEDED;

    alertMessage = (PALERT_MESSAGE)
        negoex_locate_message(pInMessages, cInMessages, MESSAGE_TYPE_ALERT);
    if (alertMessage != NULL) {
        if (alertMessage->ErrorCode != 0) {
            *minor = NEGOEX_UNKNOWN_ALERT_ERROR;
            major = GSS_S_FAILURE;
        }

        /* handle advisory alerts */
        pAlerts = (PALERT)((PUCHAR)alertMessage + alertMessage->Alerts.AlertArrayOffset); /* unaligned */

        for (i = 0; i < alertMessage->Alerts.AlertCount; i++) {
            switch (pAlerts[i].AlertType) {
            case ALERT_TYPE_PULSE: {
                PALERT_PULSE pPulse = /* unaligned */
                    (PALERT_PULSE)((PUCHAR)alertMessage +
                                   pAlerts[i].AlertValue.ByteArrayOffset);

                if (pAlerts[i].AlertValue.ByteArrayLength != pPulse->cbHeaderLength ||
                    pPulse->cbHeaderLength < ALERT_PULSE_LENGTH)
                    continue;

                if (pPulse->Reason == ALERT_VERIFY_NO_KEY)
                    ctx->Flags |= NEGOEX_CTX_FLAG_VERIFY_NO_KEY;
                break;
            }
            default:
                break;
            }
        }
    }

    return major;
}

struct negoex_sm_entry {
    enum negoex_state ValidStates;
    ULONG Flags;
    OM_uint32 (*ProcessMessages)(OM_uint32 *,
                                 negoex_cred_id_t,
                                 negoex_ctx_id_t,
                                 gss_name_t,
                                 gss_OID,
                                 OM_uint32,
                                 OM_uint32,
                                 gss_channel_bindings_t,
                                 PMESSAGE_HEADER *,
                                 ULONG,
                                 PMESSAGE_HEADER **,
                                 ULONG *);
};

static struct negoex_sm_entry
negoex_initiator_sm[] =
{
    {
        NEGOEX_STATE_ALL,
        0,
        negoex_sm_alert
    },
    {
        NEGOEX_STATE_INITIAL,
        0,
        negoex_sm_init_nego
    },
    {
        NEGOEX_STATE_INITIAL,
        0,
        negoex_sm_query_meta_data
    },
    {
        NEGOEX_STATE_NEGOTIATE,
        0,
        negoex_sm_init_nego2
    },
    {
        NEGOEX_STATE_NEGOTIATE,
        0,
        negoex_sm_exchange_meta_data
    },
    {
        NEGOEX_STATE_INITIAL | NEGOEX_STATE_AUTHENTICATE | NEGOEX_STATE_VERIFY,
        0,
        negoex_sm_ap_request
    },
    {
        NEGOEX_STATE_INITIAL | NEGOEX_STATE_AUTHENTICATE | NEGOEX_STATE_VERIFY,
        0,
        negoex_sm_verify
    },
};

static struct negoex_sm_entry
negoex_acceptor_sm[] =
{
    {
        NEGOEX_STATE_ALL,
        0,
        negoex_sm_alert
    },
    {
        NEGOEX_STATE_NEGOTIATE,
        0,
        negoex_sm_accept_nego
    },
    {
        NEGOEX_STATE_NEGOTIATE,
        0,
        negoex_sm_exchange_meta_data
    },
    {
        NEGOEX_STATE_NEGOTIATE | NEGOEX_STATE_AUTHENTICATE | NEGOEX_STATE_VERIFY,
        0,
        negoex_sm_challenge
    },
    {
        NEGOEX_STATE_NEGOTIATE,
        0,
        negoex_sm_query_meta_data
    },
    {
        NEGOEX_STATE_AUTHENTICATE | NEGOEX_STATE_VERIFY,
        0,
        negoex_sm_verify
    },
};

static OM_uint32
negoex_sm_step(OM_uint32 *minor,
               negoex_cred_id_t cred,
               negoex_ctx_id_t ctx,
               gss_name_t target,
               gss_OID mech_type,
               OM_uint32 req_flags,
               OM_uint32 time_req,
               gss_channel_bindings_t input_chan_bindings,
               gss_buffer_t input_token,
               gss_buffer_t output_token,
               struct negoex_sm_entry *pSmEntries,
               size_t cSmEntries)
{
    OM_uint32 major, tmpMajor, tmpMinor;
    PMESSAGE_HEADER *pOutMessages = NULL;
    ULONG cOutMessages = 0;
    ULONG i;
    ULONG oldMessageCount = ctx->MessageCount;

    output_token->length = 0;
    output_token->value = NULL;

    /* Unpack messages from input token */
    if (input_token != GSS_C_NO_BUFFER) {
        major = negoex_parse_token(minor, input_token,
                                   &ctx->Messages, &ctx->MessageCount);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    /* Verify conversation IDs and sequence numbers */
    for (i = oldMessageCount; i < ctx->MessageCount; i++) {
        PMESSAGE_HEADER message = ctx->Messages[i];

        negoex_trace_message(0, message);

        assert(message->Signature == MESSAGE_SIGNATURE);

        if (message->SequenceNum != ctx->SequenceNum) {
            major = GSS_S_GAP_TOKEN;
            *minor = NEGOEX_MESSAGE_OUT_OF_SEQUENCE;
            goto cleanup;
        }

        assert(message->cbHeaderLength <= message->cbMessageLength);

        if ((ctx->Flags & NEGOEX_CTX_FLAG_INITIATOR) == 0 &&
            ctx->State == NEGOEX_STATE_INITIAL) {
            /* For acceptor message, set conversation ID */
            memcpy(ctx->ConversationId, message->ConversationId,
                   CONVERSATION_ID_LENGTH);
            ctx->State = NEGOEX_STATE_NEGOTIATE;
        } else if (memcmp(message->ConversationId, ctx->ConversationId,
                   CONVERSATION_ID_LENGTH) != 0) {
            major = GSS_S_DEFECTIVE_TOKEN;
            *minor = NEGOEX_INVALID_CONVERSATION_ID;
            goto cleanup;
        }

        ctx->SequenceNum++;
    }

    /*
     * Run state machine whilst CONTINUE_NEEDED is returned. If there is
     * a state transition, then break out of the loop as soon as soon as
     * we have at least one message to send.
     */
    for (i = 0; i < cSmEntries; i++) {
        struct negoex_sm_entry *sm = &pSmEntries[i];
        ULONG oldState = ctx->State;

        if ((ctx->State & sm->ValidStates) == 0)
            continue;

        major = sm->ProcessMessages(minor,
                                    cred,
                                    ctx,
                                    target,
                                    mech_type,
                                    req_flags,
                                    time_req,
                                    input_chan_bindings,
                                    &ctx->Messages[oldMessageCount],
                                    ctx->MessageCount - oldMessageCount,
                                    &pOutMessages,
                                    &cOutMessages);
        if ((major & GSS_S_CONTINUE_NEEDED) == 0)
            break;

        if (ctx->State != oldState && cOutMessages)
            break;
    }

    assert(ctx->State == NEGOEX_STATE_COMPLETE || major != GSS_S_COMPLETE);

    /* Forward any error tokens from acceptor */
    if (GSS_ERROR(major) &&
        (ctx->Flags & NEGOEX_CTX_FLAG_INITIATOR))
        goto cleanup;

    for (i = 0; i < cOutMessages; i++)
        negoex_trace_message(1, pOutMessages[i]);

    /* Pack tokens into output token, without stomping on return value */
    tmpMajor = negoex_make_token(&tmpMinor, pOutMessages,
                                 cOutMessages, output_token);
    if (GSS_ERROR(tmpMajor))
        goto tmp_cleanup;

    /* Stash the tokens for signature verification */
    ctx->Messages =
        negoex_realloc(&tmpMajor, &tmpMinor, ctx->Messages,
                       (ctx->MessageCount + cOutMessages) * sizeof(PMESSAGE_HEADER));
    if (GSS_ERROR(tmpMajor))
        goto tmp_cleanup;

    memcpy(&ctx->Messages[ctx->MessageCount], pOutMessages,
           cOutMessages * sizeof(PMESSAGE_HEADER));
    ctx->MessageCount += cOutMessages;

    negoex_free(pOutMessages);
    pOutMessages = NULL;
    cOutMessages = 0;

tmp_cleanup:
    if (GSS_ERROR(tmpMajor)) {
        major = tmpMajor;
        *minor = tmpMinor;
        goto cleanup;
    }

cleanup:
    negoex_free_messages(pOutMessages, cOutMessages);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_init_sec_context(OM_uint32 *minor,
                            gss_cred_id_t claimant_cred_handle,
                            gss_ctx_id_t *context_handle,
                            gss_name_t target_name,
                            gss_OID mech_type,
                            OM_uint32 req_flags,
                            OM_uint32 time_req,
                            gss_channel_bindings_t input_chan_bindings,
                            gss_buffer_t input_token,
                            gss_OID *actual_mech_type,
                            gss_buffer_t output_token,
                            OM_uint32 *ret_flags,
                            OM_uint32 *time_rec)
{
    OM_uint32 major;
    negoex_ctx_id_t ctx = NULL;

    if (*context_handle == GSS_C_NO_CONTEXT) {
        if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
            major = GSS_S_DEFECTIVE_TOKEN;
            goto cleanup;
        }

        major = negoex_alloc_context(minor, &ctx);
        if (GSS_ERROR(major))
            goto cleanup;

        ctx->Flags |= NEGOEX_CTX_FLAG_INITIATOR;
    } else {
        ctx = (negoex_ctx_id_t)*context_handle;
    }

    major = negoex_sm_step(minor,
                           (negoex_cred_id_t)claimant_cred_handle,
                           ctx,
                           target_name,
                           mech_type,
                           req_flags,
                           time_req,
                           input_chan_bindings,
                           input_token,
                           output_token,
                           negoex_initiator_sm,
                           sizeof(negoex_initiator_sm) /
                                sizeof(negoex_initiator_sm[0]));
    if (GSS_ERROR(major))
        goto cleanup;

    if (actual_mech_type != NULL)
        *actual_mech_type = ctx->ActualMech;
    if (ret_flags != NULL)
        *ret_flags = ctx->GssFlags;
    if (time_rec != NULL)
        *time_rec = ctx->Lifetime;

cleanup:
    if (GSS_ERROR(major)) {
        negoex_release_context(ctx);
        *context_handle = GSS_C_NO_CONTEXT;
    } else {
        *context_handle = (gss_ctx_id_t)ctx;
    }

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_accept_sec_context(OM_uint32 *minor,
                              gss_ctx_id_t *context_handle,
                              gss_cred_id_t verifier_cred_handle,
                              gss_buffer_t input_token,
                              gss_channel_bindings_t input_chan_bindings,
                              gss_name_t *src_name,
                              gss_OID *mech_type,
                              gss_buffer_t output_token,
                              OM_uint32 *ret_flags,
                              OM_uint32 *time_rec,
                              gss_cred_id_t *delegated_cred_handle)
{
    OM_uint32 major;
    negoex_ctx_id_t ctx = NULL;

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        major = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    }

    if (*context_handle == GSS_C_NO_CONTEXT) {
        major = negoex_alloc_context(minor, &ctx);
        if (GSS_ERROR(major))
            goto cleanup;
    } else {
        ctx = (negoex_ctx_id_t)*context_handle;
    }

    major = negoex_sm_step(minor,
                           (negoex_cred_id_t)verifier_cred_handle,
                           ctx,
                           GSS_C_NO_NAME,
                           GSS_C_NO_OID,
                           0,
                           0,
                           input_chan_bindings,
                           input_token,
                           output_token,
                           negoex_acceptor_sm,
                           sizeof(negoex_acceptor_sm) /
                                sizeof(negoex_acceptor_sm[0]));
    if (GSS_ERROR(major))
        goto cleanup;

    if (mech_type != NULL)
        *mech_type = ctx->ActualMech;
    if (ret_flags != NULL)
        *ret_flags = ctx->GssFlags;
    if (time_rec != NULL)
        *time_rec = ctx->Lifetime;

cleanup:
    if (major == GSS_S_COMPLETE) {
        if (src_name != NULL) {
            *src_name = ctx->InitiatorName;
            ctx->InitiatorName = GSS_C_NO_NAME;
        }
        if (delegated_cred_handle != NULL) {
            *delegated_cred_handle = ctx->DelegCred;
            ctx->DelegCred = GSS_C_NO_CREDENTIAL;
        }
    }
    if (GSS_ERROR(major)) {
        negoex_release_context(ctx);
        *context_handle = GSS_C_NO_CONTEXT;
    } else {
        *context_handle = (gss_ctx_id_t)ctx;
    }

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_delete_sec_context(OM_uint32 *minor,
                              gss_ctx_id_t *context_handle,
                              gss_buffer_t output_token)
{
    negoex_ctx_id_t ctx = (negoex_ctx_id_t)*context_handle;

    if (ctx != NULL) {
        negoex_release_context(ctx);
        *context_handle = NULL;
    }

    if (output_token != GSS_C_NO_BUFFER) {
        output_token->length = 0;
        output_token->value = NULL;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}
