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

static void
negoex_release_auth_mech(negoex_auth_mech_t mech);

void *
negoex_alloc(OM_uint32 *major,
             OM_uint32 *minor,
             size_t length)
{
    void *ptr;

    ptr = gssalloc_malloc(length);
    if (ptr == NULL) {
        *major = GSS_S_FAILURE;
        *minor = ENOMEM;
    } else {
        *major =  GSS_S_COMPLETE;
        *minor = 0;
    }

    return ptr;
}

void *
negoex_calloc(OM_uint32 *major,
              OM_uint32 *minor,
              size_t count,
              size_t size)
{
    void *ptr;

    ptr = gssalloc_calloc(count, size);
    if (ptr == NULL) {
        *major = GSS_S_FAILURE;
        *minor = ENOMEM;
    } else {
        *major =  GSS_S_COMPLETE;
        *minor = 0;
    }

    return ptr;
}

void *
negoex_realloc(OM_uint32 *major,
               OM_uint32 *minor,
               void *ptr,
               size_t size)
{
    void *newPtr;

    newPtr = gssalloc_realloc(ptr, size);
    if (newPtr == NULL) {
        *major = GSS_S_FAILURE;
        *minor = ENOMEM;
    } else {
        *major =  GSS_S_COMPLETE;
        *minor = 0;
    }

    return newPtr;
}

void
negoex_free(void *ptr)
{
    gssalloc_free(ptr);
}

OM_uint32
negoex_random(OM_uint32 *minor,
              unsigned char *data,
              size_t length)
{
    krb5_data d;
    krb5_context context;
    krb5_error_code code;

    d.data = (char *)data;
    d.length = length;

    code = krb5_init_context(&context);
    if (code == 0) {
        code = krb5_c_random_make_octets(context, &d);

        krb5_free_context(context);
    }

    *minor = code;

    return code ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

OM_uint32
negoex_alloc_context(OM_uint32 *minor,
                     negoex_ctx_id_t *pCtx)
{
    OM_uint32 major;
    negoex_ctx_id_t ctx = NULL;

    *pCtx = NULL;

    ctx = negoex_calloc(&major, minor, 1, sizeof(*ctx));
    if (GSS_ERROR(major))
        goto cleanup;

    ctx->State = NEGOEX_STATE_INITIAL;

    *pCtx = ctx;
    ctx = NULL;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    negoex_release_context(ctx);

    return major;
}

void
negoex_release_context(negoex_ctx_id_t ctx)
{
    OM_uint32 minor;
    negoex_auth_mech_t p, next;

    if (ctx == NULL)
        return;

    negoex_free_messages(ctx->Messages, ctx->MessageCount);
    gss_release_name(&minor, &ctx->InitiatorName);
    gss_release_cred(&minor, &ctx->DelegCred);

    for (p = ctx->AuthMechs; p != NULL; p = next) {
        next = p->Next;
        negoex_release_auth_mech(p);
    }

    negoex_free(ctx);
}

static OM_uint32
negoex_validate_header(OM_uint32 *minor,
                       PMESSAGE_HEADER message)
{
    ULONG cbHeaderLength;

    if (message->Signature != MESSAGE_SIGNATURE) {
        *minor = NEGOEX_INVALID_MESSAGE_SIGNATURE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    switch (message->MessageType) {
    case MESSAGE_TYPE_INITIATOR_NEGO:
    case MESSAGE_TYPE_ACCEPTOR_NEGO:
        cbHeaderLength = NEGO_MESSAGE_HEADER_LENGTH;
        break;
    case MESSAGE_TYPE_INITIATOR_META_DATA:
    case MESSAGE_TYPE_ACCEPTOR_META_DATA:
    case MESSAGE_TYPE_CHALLENGE:
    case MESSAGE_TYPE_AP_REQUEST:
        cbHeaderLength = EXCHANGE_MESSAGE_HEADER_LENGTH;
        break;
    case MESSAGE_TYPE_VERIFY:
        cbHeaderLength = VERIFY_MESSAGE_HEADER_LENGTH;
        break;
    case MESSAGE_TYPE_ALERT:
        cbHeaderLength = ALERT_MESSAGE_HEADER_LENGTH;
        break;
    default:
        *minor = NEGOEX_INVALID_MESSAGE_TYPE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Windows includes padding bytes in header length */
    if (message->cbHeaderLength < cbHeaderLength ||
        message->cbMessageLength < message->cbHeaderLength) {
        *minor = NEGOEX_INVALID_MESSAGE_SIZE;
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

#define NEGOEX_CHECK_OFFSET(hdr, offset, length)         do { \
        if ((offset) + (length) > (hdr)->cbMessageLength) {   \
            *minor = NEGOEX_INVALID_MESSAGE_SIZE;             \
            return GSS_S_DEFECTIVE_TOKEN;                     \
        }                                                     \
    } while (0)

#define NEGOEX_UNPACK_VECTOR(hdr, field, prefix, size)   do { \
        negoex_swap_ULONG(&(field)->prefix##ArrayOffset);     \
        negoex_swap_USHORT(&(field)->prefix##Count);          \
        NEGOEX_CHECK_OFFSET(hdr, (field)->prefix##ArrayOffset, (field)->prefix##Count * (size)); \
    } while (0)

#define NEGOEX_UNPACK_BYTE_VECTOR(hdr, vector)           do { \
        negoex_swap_ULONG(&(vector)->ByteArrayOffset);        \
        negoex_swap_ULONG(&(vector)->ByteArrayLength);       \
        NEGOEX_CHECK_OFFSET(hdr, (vector)->ByteArrayOffset, (vector)->ByteArrayLength); \
    } while (0)

static OM_uint32
negoex_unpack_nego_message(OM_uint32 *minor,
                           PMESSAGE_HEADER hdr)
{
    PNEGO_MESSAGE negoMessage = (PNEGO_MESSAGE)hdr;

    negoex_swap_ULONG64(&negoMessage->ProtocolVersion);

    NEGOEX_UNPACK_VECTOR(hdr, &negoMessage->AuthSchemes, AuthScheme, AUTH_SCHEME_LENGTH);
    NEGOEX_UNPACK_VECTOR(hdr, &negoMessage->Extensions, Extension, EXTENSION_LENGTH);

    return GSS_S_COMPLETE;
}

static OM_uint32
negoex_unpack_exchange_message(OM_uint32 *minor,
                               PMESSAGE_HEADER hdr)
{
    PEXCHANGE_MESSAGE exchangeMessage = (PEXCHANGE_MESSAGE)hdr;

    NEGOEX_UNPACK_BYTE_VECTOR(hdr, &exchangeMessage->Exchange);

    return GSS_S_COMPLETE;
}

static OM_uint32
negoex_unpack_verify_message(OM_uint32 *minor,
                             PMESSAGE_HEADER hdr)
{
    PVERIFY_MESSAGE verifyMessage = (PVERIFY_MESSAGE)hdr;

    negoex_swap_ULONG(&verifyMessage->Checksum.cbHeaderLength);
    negoex_swap_ULONG(&verifyMessage->Checksum.ChecksumScheme);
    negoex_swap_ULONG(&verifyMessage->Checksum.ChecksumType);
    NEGOEX_UNPACK_BYTE_VECTOR(hdr, &verifyMessage->Checksum.ChecksumValue);

    return GSS_S_COMPLETE;
}

static OM_uint32
negoex_unpack_alert_message(OM_uint32 *minor,
                            PMESSAGE_HEADER hdr)
{
    PALERT_MESSAGE alertMessage = (PALERT_MESSAGE)hdr;
    ULONG i;

    negoex_swap_ULONG(&alertMessage->ErrorCode);

    NEGOEX_UNPACK_VECTOR(hdr, &alertMessage->Alerts, Alert, ALERT_LENGTH);

    for (i = 0; i < alertMessage->Alerts.AlertCount; i++) {
        ALERT *pAlert = (ALERT *)((PUCHAR)alertMessage + alertMessage->Alerts.AlertArrayOffset); /* unaligned */

        NEGOEX_UNPACK_BYTE_VECTOR(hdr, &pAlert->AlertValue);
    }

    return GSS_S_COMPLETE;
}

static OM_uint32
negoex_unpack_message_body(OM_uint32 *minor,
                           PMESSAGE_HEADER message)
{
    OM_uint32 major;

    switch (message->MessageType) {
    case MESSAGE_TYPE_INITIATOR_NEGO:
    case MESSAGE_TYPE_ACCEPTOR_NEGO:
        major = negoex_unpack_nego_message(minor, message);
        break;
    case MESSAGE_TYPE_INITIATOR_META_DATA:
    case MESSAGE_TYPE_ACCEPTOR_META_DATA:
    case MESSAGE_TYPE_CHALLENGE:
    case MESSAGE_TYPE_AP_REQUEST:
        major = negoex_unpack_exchange_message(minor, message);
        break;
        break;
    case MESSAGE_TYPE_VERIFY:
        major = negoex_unpack_verify_message(minor, message);
        break;
    case MESSAGE_TYPE_ALERT:
        major = negoex_unpack_alert_message(minor, message);
        break;
    default:
        *minor = NEGOEX_INVALID_MESSAGE_TYPE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    return major;
}

static OM_uint32
negoex_unpack_message_header(OM_uint32 *minor,
                             PMESSAGE_HEADER hdr)
{
    negoex_swap_ULONG64(&hdr->Signature);
    negoex_swap_ULONG(&hdr->MessageType);
    negoex_swap_ULONG(&hdr->SequenceNum);
    negoex_swap_ULONG(&hdr->cbHeaderLength);
    negoex_swap_ULONG(&hdr->cbMessageLength);

    return GSS_S_COMPLETE;
}

void
negoex_free_messages(PMESSAGE_HEADER *pMessages,
                     ULONG cMessages)
{
    ULONG i;

    for (i = 0; i < cMessages; i++)
        negoex_free(pMessages[i]);
}

OM_uint32
negoex_parse_token(OM_uint32 *minor,
                   gss_const_buffer_t token,
                   PMESSAGE_HEADER **ppMessages,
                   ULONG *pcMessages)
{
    OM_uint32 major;
    PMESSAGE_HEADER *pMessages = *ppMessages;
    PUCHAR p;
    ULONG cbRemain, cMessages = *pcMessages;

    assert(token != GSS_C_NO_BUFFER);

    p = (PUCHAR)token->value;
    cbRemain = token->length;

    while (cbRemain != 0) {
        MESSAGE_HEADER hdr, *message;

        if (cbRemain < MESSAGE_HEADER_LENGTH) {
            major = GSS_S_FAILURE;
            *minor = NEGOEX_INVALID_MESSAGE_SIZE;
            goto cleanup;
        }

        memcpy(&hdr, p, MESSAGE_HEADER_LENGTH);
        negoex_unpack_message_header(minor, (PMESSAGE_HEADER)p);

        if (cbRemain < hdr.cbMessageLength) {
            major = GSS_S_FAILURE;
            *minor = NEGOEX_INVALID_MESSAGE_SIZE;
            goto cleanup;
        }

        major = negoex_validate_header(minor, &hdr);
        if (GSS_ERROR(major))
            goto cleanup;

        pMessages = negoex_realloc(&major, minor, pMessages,
                                   (cMessages + 1) * sizeof(PMESSAGE_HEADER));
        if (GSS_ERROR(major))
            goto cleanup;

        message = negoex_alloc(&major, minor, hdr.cbMessageLength);
        if (GSS_ERROR(major))
            goto cleanup;

        memcpy(message, &hdr, sizeof(hdr));
        memcpy((PUCHAR)message + MESSAGE_HEADER_LENGTH,
               p + MESSAGE_HEADER_LENGTH, hdr.cbMessageLength - MESSAGE_HEADER_LENGTH);

        major = negoex_unpack_message_body(minor, message);
        if (GSS_ERROR(major))
            goto cleanup;

        p += hdr.cbMessageLength;
        cbRemain -= hdr.cbMessageLength;

        pMessages[cMessages++] = message;
    }

    *ppMessages = pMessages;
    *pcMessages = cMessages;

cleanup:
    if (GSS_ERROR(major))
        negoex_free_messages(pMessages, cMessages);

    return major;
}

PMESSAGE_HEADER
negoex_locate_message(PMESSAGE_HEADER *pMessages,
                      ULONG cMessages,
                      MESSAGE_TYPE type)
{
    ULONG i;

    for (i = 0; i < cMessages; i++) {
        if (pMessages[i]->MessageType == type)
            return pMessages[i];
    }

    return NULL;
}

OM_uint32
negoex_make_token(OM_uint32 *minor,
                  PMESSAGE_HEADER *pMessages,
                  ULONG cMessages,
                  gss_buffer_t token)
{
    OM_uint32 major, tmpMinor;
    ULONG i;
    PUCHAR p;

    token->value = NULL;
    token->length = 0;

    for (i = 0; i < cMessages; i++)
        token->length += pMessages[i]->cbMessageLength;

    token->value = negoex_alloc(&major, minor, token->length);
    if (GSS_ERROR(major))
        goto cleanup;

    p = (PUCHAR)token->value;

    for (i = 0; i < cMessages; i++) {
        memcpy(p, pMessages[i], pMessages[i]->cbMessageLength);
        negoex_unpack_message_header(minor, (PMESSAGE_HEADER)p); /* unaligned */
        negoex_unpack_message_body(minor, (PMESSAGE_HEADER)p); /* unaligned */
        p += pMessages[i]->cbMessageLength;
    }

cleanup:
    if (GSS_ERROR(major))
        gss_release_buffer(&tmpMinor, token);

    return major;
}

static void
negoex_release_auth_mech(negoex_auth_mech_t mech)
{
    OM_uint32 tmpMinor;

    if (mech == NULL)
        return;

    gss_release_oid(&tmpMinor, &mech->Oid);
    gss_delete_sec_context(&tmpMinor, &mech->Context, NULL);
    krb5_free_keyblock_contents(NULL, &mech->Key);
    krb5_free_keyblock_contents(NULL, &mech->VerifyKey);

    negoex_free(mech);
}

static OM_uint32
negoex_maybe_add_auth_mech(OM_uint32 *minor,
                          negoex_ctx_id_t ctx,
                          gss_const_OID oid,
                          PUCHAR base,
                          PAUTH_SCHEME_VECTOR authSchemes)
{
    OM_uint32 major;
    negoex_auth_mech_t mech, *last;
    AUTH_SCHEME authScheme;

    major = gss_query_mechanism_info(minor, oid, authScheme);
    if (GSS_ERROR(major))
        return major;

    if (authSchemes != NULL) {
        USHORT i;
        int found = 0;

        for (i = 0; i < authSchemes->AuthSchemeCount; i++) {
            PUCHAR p = base + authSchemes->AuthSchemeArrayOffset;

            p += (i * AUTH_SCHEME_LENGTH);

            if (memcmp(authScheme, p, AUTH_SCHEME_LENGTH) == 0) {
                found++;
                break;
            }
        }

        if (!found) {
            *minor = NEGOEX_AUTH_SCHEME_NOT_FOUND;
            return GSS_S_UNAVAILABLE;
        }
    }

    mech = negoex_calloc(&major, minor, 1, sizeof(*mech));
    if (GSS_ERROR(major))
        return major;

    major = generic_gss_copy_oid(minor, (gss_OID)oid, &mech->Oid);
    if (GSS_ERROR(major)) {
        negoex_free(mech);
        return major;
    }

    memcpy(mech->AuthScheme, authScheme, AUTH_SCHEME_LENGTH);
    mech->Context = GSS_C_NO_CONTEXT;

    last = &ctx->AuthMechs;

    while (*last != NULL) {
        if ((*last)->Next == NULL)
            break;
        last = &(*last)->Next;
    }

    mech->Prev = *last;
    mech->Next = NULL;

    if ((*last) != NULL)
        (*last)->Next = mech;
    else
        (*last) = mech;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
negoex_negotiate_mechs(OM_uint32 *minor,
                       negoex_cred_id_t cred,
                       negoex_ctx_id_t ctx,
                       gss_cred_usage_t usage,
                       PNEGO_MESSAGE pNegoMessage,
                       PAUTH_SCHEME_VECTOR authSchemes)
{
    OM_uint32 major, tmpMinor;
    gss_OID_set credMechs = GSS_C_NO_OID_SET;
    gss_OID_set negMechs = GSS_C_NO_OID_SET;
    ULONG i;
    int present;

    if (cred == NULL) {
        if (usage == GSS_C_INITIATE) {
            gss_cred_id_t tmpCred = GSS_C_NO_CREDENTIAL;

            /* Only select from mechs for which we can acquire a cred */
            major = negoex_gss_acquire_cred_from(minor,
                                                 GSS_C_NO_NAME,
                                                 GSS_C_INDEFINITE,
                                                 GSS_C_NO_OID_SET,
                                                 GSS_C_INITIATE,
                                                 GSS_C_NO_CRED_STORE,
                                                 &tmpCred,
                                                 &credMechs,
                                                 NULL);
            gss_release_cred(&tmpMinor, &tmpCred);
        } else {
            major = gss_indicate_mechs(minor, &credMechs);
        }
    } else {
        major = gss_inquire_cred(minor, cred->Credential,
                                 NULL, NULL, NULL, &credMechs);
    }
    if (GSS_ERROR(major))
        goto cleanup;

    if (cred == NULL || cred->NegMechs == GSS_C_NO_OID_SET)
        negMechs = credMechs;
    else
        negMechs = cred->NegMechs;

    /*
     * The list of available authentication mechanisms is the intersection of
     * the credential mechanisms (if any), the GSS_Set_neg_mechs() mechanisms
     * (if any), the mechanisms that support NegoEx (if any), and those sent
     * by the initiator (if we are an acceptor)
     *
     * (A mechanism supports NegoEx if it advertises an AUTH_SCHEME via the
     * GSS_Query_mechanism_info() SPI. The NegoEx protocol identifies mechs
     * by AUTH_SCHEME GUIDs; negoex_maybe_add_auth_mech() will only add the
     * intersecting mechs if authSchemes is non_NULL.)
     */
    for (i = 0; i < negMechs->count; i++) {
        gss_OID thisMech = &negMechs->elements[i];

        if (credMechs != negMechs) {
            major = gss_test_oid_set_member(&tmpMinor, thisMech,
                                            credMechs, &present);
            if (GSS_ERROR(major) || !present)
                continue;
        }

        major = negoex_maybe_add_auth_mech(minor, ctx, thisMech,
                                           (PUCHAR)pNegoMessage, authSchemes);
        if (major == GSS_S_UNAVAILABLE)
            continue;
        else if (GSS_ERROR(major))
            goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    gss_release_oid_set(&tmpMinor, &credMechs);

    return major;
}

static int
negoex_is_auth_mech_p(negoex_auth_mech_t mech,
                      AUTH_SCHEME authScheme)
{
    return (memcmp(mech->AuthScheme, authScheme, AUTH_SCHEME_LENGTH) == 0);
}

static int
negoex_has_auth_mech_p(negoex_auth_mech_t mech,
                       AUTH_SCHEME *pAuthSchemes,
                       USHORT cAuthSchemes)
{
    ULONG i;

    for (i = 0; i < cAuthSchemes; i++) {
        if (negoex_is_auth_mech_p(mech, pAuthSchemes[i]))
            return TRUE;
    }

    return FALSE;
}

void
negoex_delete_auth_mech(negoex_ctx_id_t ctx,
                        negoex_auth_mech_t *p)
{
    negoex_auth_mech_t tmp = *p;

    if (tmp->Prev == NULL)
        ctx->AuthMechs = tmp->Next;
    else
        tmp->Prev->Next = tmp->Next;

    if (tmp->Next != NULL)
        tmp->Next->Prev = tmp->Prev;

    tmp = tmp->Next;

    negoex_release_auth_mech(*p);

    *p = tmp;
}

/*
 * Move the indicated authentication mechanism to the front of 
 * the list. This now becomes the "active" mechanism.
 */
void
negoex_select_auth_mech(negoex_ctx_id_t ctx,
                        negoex_auth_mech_t mech)
{
    assert(mech != NULL);

    assert((ctx->Flags & NEGOEX_CTX_FLAG_MECH_SELECTED) == 0);

    ctx->Flags |= NEGOEX_CTX_FLAG_MECH_SELECTED;

    if (ctx->AuthMechs == mech) {
        /* Mechanism is already at front of list, nothing to do. */
        return;
    }

    /* Link mech->Prev to mech->Next */
    if (mech->Next != NULL) {
        mech->Next->Prev = mech->Prev;
        mech->Next = NULL;
    }
    if (mech->Prev != NULL) {
        mech->Prev->Next = mech->Next;
        mech->Prev = NULL;
    }

    /* mech is now unlinked; place it at head of list */
    if (ctx->AuthMechs != NULL) {
        assert(ctx->AuthMechs->Prev == NULL);
        ctx->AuthMechs->Prev = mech;

        if (ctx->AuthMechs->Next == mech)
            ctx->AuthMechs->Next = NULL;

        mech->Next = ctx->AuthMechs;
    }

    ctx->AuthMechs = mech;
}

OM_uint32
negoex_add_auth_mech(OM_uint32 *minor,
                     negoex_ctx_id_t ctx,
                     gss_const_OID oid)
{
    return negoex_maybe_add_auth_mech(minor, ctx, oid, NULL, NULL);
}

OM_uint32
negoex_delete_auth_scheme(OM_uint32 *minor,
                          negoex_ctx_id_t ctx,
                          AUTH_SCHEME authScheme)
{
    negoex_auth_mech_t *p = &ctx->AuthMechs;

    while (*p != NULL) {
        if (negoex_is_auth_mech_p(*p, authScheme))
            negoex_delete_auth_mech(ctx, p);
        else
            p = &(*p)->Next;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

negoex_auth_mech_t
negoex_locate_auth_scheme(negoex_ctx_id_t ctx,
                          AUTH_SCHEME authScheme)
{
    negoex_auth_mech_t mech;

    for (mech = ctx->AuthMechs; mech != NULL; mech = mech->Next) {
        if (negoex_is_auth_mech_p(mech, authScheme))
            return mech;
    }

    return NULL;
}

OM_uint32
negoex_common_auth_schemes(OM_uint32 *minor,
                           negoex_ctx_id_t ctx,
                           AUTH_SCHEME *pAuthSchemes,
                           USHORT cAuthSchemes)
{
    negoex_auth_mech_t *p = &ctx->AuthMechs;

    while (*p != NULL) {
        if (!negoex_has_auth_mech_p(*p, pAuthSchemes, cAuthSchemes))
            negoex_delete_auth_mech(ctx, p);
        else
            p = &(*p)->Next;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
negoex_pack_auth_schemes(OM_uint32 *minor,
                         negoex_ctx_id_t ctx,
                         PUCHAR flattenedMechs,
                         USHORT *flattenedMechsCount,
                         ULONG *flattenedMechsLen)
{
    negoex_auth_mech_t mech;
    ULONG cbRequired;
    PUCHAR p;

    *flattenedMechsCount = 0;

    for (mech = ctx->AuthMechs; mech != NULL; mech = mech->Next)
        (*flattenedMechsCount)++;

    cbRequired = *flattenedMechsCount * AUTH_SCHEME_LENGTH;

    if (flattenedMechs == NULL) {
        *flattenedMechsLen = cbRequired;
        *minor = 0;
        return GSS_S_COMPLETE;
    } else if (*flattenedMechsLen < cbRequired) {
        *minor = ERANGE;
        return GSS_S_FAILURE;
    }

    p = flattenedMechs;

    for (mech = ctx->AuthMechs; mech != NULL; mech = mech->Next) {
        memcpy(p, mech->AuthScheme, AUTH_SCHEME_LENGTH);
        p += AUTH_SCHEME_LENGTH;
    }

    *flattenedMechsLen = cbRequired;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
negoex_indicate_mechs(OM_uint32 *minor,
                      negoex_ctx_id_t ctx,
                      gss_OID_set *oids)
{
    OM_uint32 major, tmpMinor;
    negoex_auth_mech_t mech;

    major = gss_create_empty_oid_set(minor, oids);
    if (GSS_ERROR(major))
        goto cleanup;

    for (mech = ctx->AuthMechs; mech != NULL; mech = mech->Next) {
        major = gss_add_oid_set_member(minor, mech->Oid, oids);
        if (GSS_ERROR(major))
            goto cleanup;
    }

cleanup:
    if (GSS_ERROR(major))
        gss_release_oid_set(&tmpMinor, oids);

    return major;
}

OM_uint32
negoex_add_message(OM_uint32 *minor,
                   PMESSAGE_HEADER message,
                   PMESSAGE_HEADER **ppMessages,
                   ULONG *pcMessages)
{
    OM_uint32 major;
    PMESSAGE_HEADER *pMessages = *ppMessages;

    pMessages = negoex_realloc(&major, minor, pMessages,
                               (*pcMessages + 1) * sizeof(PMESSAGE_HEADER));
    if (GSS_ERROR(major))
        return major;

    pMessages[*pcMessages] = message;

    (*pcMessages)++;
    *ppMessages = pMessages;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
negoex_alloc_message(OM_uint32 *minor,
                     negoex_ctx_id_t ctx,
                     MESSAGE_TYPE type,
                     ULONG cbHeaderLength,
                     ULONG cbMessageLength,
                     PMESSAGE_HEADER *pMessage)
{
    OM_uint32 major;
    PMESSAGE_HEADER message;

    *pMessage = NULL;

    assert(cbMessageLength >= cbHeaderLength);

    message = negoex_calloc(&major, minor, 1, cbMessageLength);
    if (GSS_ERROR(major))
        return major;

    message->Signature       = MESSAGE_SIGNATURE;
    message->MessageType     = type;
    message->SequenceNum     = ctx->SequenceNum++;
    message->cbHeaderLength  = cbHeaderLength;
    message->cbMessageLength = cbMessageLength;
    memcpy(message->ConversationId, ctx->ConversationId, CONVERSATION_ID_LENGTH);

    *pMessage = message;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
negoex_make_exchange_message(OM_uint32 *minor,
                             negoex_ctx_id_t ctx,
                             MESSAGE_TYPE type,
                             AUTH_SCHEME authScheme,
                             gss_buffer_t token,
                             PEXCHANGE_MESSAGE *pMessage)
{
    PEXCHANGE_MESSAGE message = NULL;
    OM_uint32 major;

    major = negoex_alloc_message(minor, ctx, type,
                                 EXCHANGE_MESSAGE_HEADER_LENGTH,
                                 EXCHANGE_MESSAGE_HEADER_LENGTH + token->length,
                                 (PMESSAGE_HEADER *)&message);
    if (GSS_ERROR(major))
        return major;

    memcpy(message->AuthScheme, authScheme, AUTH_SCHEME_LENGTH);

    message->Exchange.ByteArrayOffset = message->Header.cbHeaderLength;
    message->Exchange.ByteArrayLength = token->length;

    memcpy((PUCHAR)message + message->Exchange.ByteArrayOffset,
           token->value, token->length);

    *pMessage = message;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
negoex_add_exchange_message(OM_uint32 *minor,
                            negoex_ctx_id_t ctx,
                            MESSAGE_TYPE type,
                            AUTH_SCHEME authScheme,
                            gss_buffer_t token,
                            PMESSAGE_HEADER **ppMessages,
                            ULONG *pcMessages)
{
    OM_uint32 major;
    PEXCHANGE_MESSAGE message;

    major = negoex_make_exchange_message(minor, ctx, type, authScheme, token, &message);
    if (GSS_ERROR(major))
        return major;

    major = negoex_add_message(minor, (PMESSAGE_HEADER)message, ppMessages, pcMessages);
    if (GSS_ERROR(major))
        negoex_free(message);

    return major;
}

OM_uint32
negoex_pulse(OM_uint32 *minor,
             negoex_ctx_id_t ctx,
             ULONG ulReason,
             PMESSAGE_HEADER **ppOutMessages,
             ULONG *pcOutMessages)
{
    OM_uint32 major;
    PALERT_MESSAGE alertMessage;
    ALERT *pAlert;
    ALERT_PULSE *pPulse;
    negoex_auth_mech_t mech = negoex_active_mech(ctx);

    major = negoex_alloc_message(minor, ctx, MESSAGE_TYPE_ALERT,
                                 ALERT_MESSAGE_HEADER_LENGTH,
                                 ALERT_MESSAGE_HEADER_LENGTH + ALERT_LENGTH + ALERT_PULSE_LENGTH,
                                 (PMESSAGE_HEADER *)&alertMessage);
    if (GSS_ERROR(major))
        return major;

    if (mech != NULL)
        memcpy(alertMessage->AuthScheme, mech->AuthScheme, AUTH_SCHEME_LENGTH);

    alertMessage->ErrorCode = 0;
    alertMessage->Alerts.AlertArrayOffset = ALERT_LENGTH;
    alertMessage->Alerts.AlertCount = 1;

    pAlert = (ALERT *)((PUCHAR)alertMessage + alertMessage->Alerts.AlertArrayOffset); /* unaligned */
    pAlert->AlertType = ALERT_TYPE_PULSE;
    pAlert->AlertValue.ByteArrayOffset = alertMessage->Alerts.AlertArrayOffset + ALERT_LENGTH;
    pAlert->AlertValue.ByteArrayLength = ALERT_PULSE_LENGTH;

    pPulse = (ALERT_PULSE *)((PUCHAR)alertMessage + pAlert->AlertValue.ByteArrayOffset); /* unaligned */
    pPulse->cbHeaderLength = ALERT_PULSE_LENGTH;
    pPulse->Reason = ulReason;

    /*
     * Because this is encapsulated in a BYTE_VECTOR, it severs the contract
     * by which negoex_unpack_message_body will perform any byte swapping.
     */
    negoex_swap_ULONG(&pPulse->cbHeaderLength);
    negoex_swap_ULONG(&pPulse->Reason);

    major = negoex_add_message(minor, &alertMessage->Header,
                               ppOutMessages, pcOutMessages);

    return major;
}
