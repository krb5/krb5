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

#ifndef _GSSAPIP_NEGOEX_H_
#define _GSSAPIP_NEGOEX_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <generic/gssapiP_generic.h>
#include <spnego/gssapiP_spnego.h>

#include "k5-int.h"
#include "negoex_err.h"

#define MESSAGE_SIGNATURE   0x535458454F47454EULL

#ifndef GSSAPI_CALLCONV
#define GSSAPI_CALLCONV KRB5_CALLCONV
#endif

#ifdef WIN32
#include <windows.h>
#else
typedef int16_t SHORT;
typedef uint16_t USHORT;

typedef int32_t LONG;
typedef uint32_t ULONG;

typedef int64_t LONG64;
typedef uint64_t ULONG64;
typedef unsigned char UCHAR, *PUCHAR;
#endif /* WIN32 */

#ifdef K5_BE
#define NEGOEX_BIG_ENDIAN       1
#elif defined(K5_LE) || defined(WIN32)
#define NEGOEX_LITTLE_ENDIAN    1
#else
#error Define NEGOEX_XXX_ENDIAN for your platform
#endif

static inline void
negoex_swap_USHORT(USHORT *x)
{
#ifdef NEGOEX_BIG_ENDIAN
    *x = SWAP16(x);
#endif
}

static inline void
negoex_swap_ULONG(ULONG *x)
{
#ifdef NEGOEX_BIG_ENDIAN
    *x = SWAP32(x);
#endif
}

static inline void
negoex_swap_ULONG64(ULONG64 *x)
{
#ifdef NEGOEX_BIG_ENDIAN
    *x = SWAP64(x);
#endif
}

/*
 * Windows does not require any special alignment for NegoEx types, however
 * it requires the outer message to be padded to eight bytes.
 */
#define NEGOEX_PADDING  8
#define NEGOEX_PAD(n)   ((((n) + NEGOEX_PADDING - 1) / NEGOEX_PADDING) * NEGOEX_PADDING)

#pragma pack(push, 1)

typedef struct _BYTE_VECTOR {
    ULONG ByteArrayOffset;
    ULONG ByteArrayLength;
} BYTE_VECTOR, *PBYTE_VECTOR;

typedef struct _AUTH_SCHEME_VECTOR {
    ULONG AuthSchemeArrayOffset;
    USHORT AuthSchemeCount;
} AUTH_SCHEME_VECTOR, *PAUTH_SCHEME_VECTOR;

typedef struct _EXTENSION_VECTOR {
    ULONG ExtensionArrayOffset;
    USHORT ExtensionCount;
} EXTENSION_VECTOR, *PEXTENSION_VECTOR;

typedef struct _EXTENSION {
    ULONG ExtensionType;
    BYTE_VECTOR ExtensionValue;
} EXTENSION, *PEXTENSION;

#define EXTENSION_LENGTH                    (sizeof(EXTENSION))

#define EXTENSION_FLAG_CRITICAL             0x80000000

#define CHECKSUM_SCHEME_RFC3961             1

#define NEGOEX_KEYUSAGE_INITIATOR_CHECKSUM  23
#define NEGOEX_KEYUSAGE_ACCEPTOR_CHECKSUM   25

typedef struct _CHECKSUM {
    ULONG cbHeaderLength;
    ULONG ChecksumScheme;
    ULONG ChecksumType;
    BYTE_VECTOR ChecksumValue;
} CHECKSUM, *PCHECKSUM;

#define CHECKSUM_HEADER_LENGTH              (sizeof(CHECKSUM))

#define AUTH_SCHEME_LENGTH                  16
typedef UCHAR AUTH_SCHEME[AUTH_SCHEME_LENGTH];

#define CONVERSATION_ID_LENGTH              16
typedef UCHAR CONVERSATION_ID[CONVERSATION_ID_LENGTH];

typedef enum _MESSAGE_TYPE {
    MESSAGE_TYPE_INITIATOR_NEGO = 0,        /* NEGO_MESSAGE */
    MESSAGE_TYPE_ACCEPTOR_NEGO,             /* NEGO_MESSAGE */
    MESSAGE_TYPE_INITIATOR_META_DATA,       /* EXCHANGE_MESSAGE */
    MESSAGE_TYPE_ACCEPTOR_META_DATA,        /* EXCHANGE_MESSAGE */
    MESSAGE_TYPE_CHALLENGE,                 /* EXCHANGE_MESSAGE */
    MESSAGE_TYPE_AP_REQUEST,                /* EXCHANGE_MESSAGE */
    MESSAGE_TYPE_VERIFY,                    /* VERIFY_MESSAGE */
    MESSAGE_TYPE_ALERT,                     /* ALERT */
} MESSAGE_TYPE;

typedef struct _MESSAGE_HEADER {
    ULONG64 Signature;
    ULONG MessageType;
    ULONG SequenceNum;
    ULONG cbHeaderLength;
    ULONG cbMessageLength;
    CONVERSATION_ID ConversationId;
} MESSAGE_HEADER, *PMESSAGE_HEADER;

#define MESSAGE_HEADER_LENGTH               NEGOEX_PAD(sizeof(MESSAGE_HEADER))

typedef struct _NEGO_MESSAGE {
    MESSAGE_HEADER Header;
    UCHAR Random[32];
    ULONG64 ProtocolVersion;
    AUTH_SCHEME_VECTOR AuthSchemes;
    EXTENSION_VECTOR Extensions;
} NEGO_MESSAGE, *PNEGO_MESSAGE;

#define NEGO_MESSAGE_HEADER_LENGTH          NEGOEX_PAD(sizeof(NEGO_MESSAGE))

typedef struct _EXCHANGE_MESSAGE {
    MESSAGE_HEADER Header;
    AUTH_SCHEME AuthScheme;
    BYTE_VECTOR Exchange;
} EXCHANGE_MESSAGE, *PEXCHANGE_MESSAGE;

#define EXCHANGE_MESSAGE_HEADER_LENGTH      NEGOEX_PAD(sizeof(EXCHANGE_MESSAGE))

typedef struct _VERIFY_MESSAGE {
    MESSAGE_HEADER Header;
    AUTH_SCHEME AuthScheme;
    CHECKSUM Checksum;
} VERIFY_MESSAGE, *PVERIFY_MESSAGE;

#define VERIFY_MESSAGE_HEADER_LENGTH        NEGOEX_PAD(sizeof(VERIFY_MESSAGE))

typedef struct _ALERT {
    ULONG AlertType;
    BYTE_VECTOR AlertValue;
} ALERT, *PALERT;

#define ALERT_LENGTH                        (sizeof(ALERT))

#define ALERT_TYPE_PULSE                    1
#define ALERT_VERIFY_NO_KEY                 1

typedef struct _ALERT_PULSE {
    ULONG cbHeaderLength;
    ULONG Reason;
} ALERT_PULSE, *PALERT_PULSE;

#define ALERT_PULSE_LENGTH                  (sizeof(ALERT_PULSE))

typedef struct _ALERT_VECTOR {
    ULONG AlertArrayOffset;
    USHORT AlertCount;
} ALERT_VECTOR, *PALERT_VECTOR;

typedef struct {
    MESSAGE_HEADER Header;
    AUTH_SCHEME AuthScheme;
    ULONG ErrorCode;
    ALERT_VECTOR Alerts;
} ALERT_MESSAGE, *PALERT_MESSAGE;

#define ALERT_MESSAGE_HEADER_LENGTH         (sizeof(ALERT_MESSAGE))

#pragma pack(pop)

typedef struct _negoex_cred_id_rec {
    gss_cred_id_t Credential;
    gss_OID_set NegMechs;
} negoex_cred_id_rec, *negoex_cred_id_t;

enum negoex_state {
    NEGOEX_STATE_INITIAL      = 0x01,
    NEGOEX_STATE_NEGOTIATE    = 0x02,
    NEGOEX_STATE_AUTHENTICATE = 0x04,
    NEGOEX_STATE_VERIFY       = 0x08,
    NEGOEX_STATE_COMPLETE     = 0x10,
    NEGOEX_STATE_ALL          = 0xFF
};

typedef struct _negoex_auth_mech_rec {
    gss_OID Oid;
    AUTH_SCHEME AuthScheme;
    gss_ctx_id_t Context;
    krb5_keyblock Key;
    krb5_keyblock VerifyKey;
    struct _negoex_auth_mech_rec *Prev, *Next;
} negoex_auth_mech_rec, *negoex_auth_mech_t;

#define NEGOEX_CTX_FLAG_INITIATOR           0x00000001
#define NEGOEX_CTX_FLAG_VERIFY_NO_KEY       0x00000002
#define NEGOEX_CTX_FLAG_MECH_COMPLETE       0x00000004
#define NEGOEX_CTX_FLAG_PEER_VERIFIED       0x00000008
#define NEGOEX_CTX_FLAG_MECH_SELECTED       0x00000010
#define NEGOEX_CTX_FLAG_OPTIMISTIC          0x00000020

typedef struct _negoex_ctx_id_rec {
    enum negoex_state State;
    ULONG SequenceNum;
    ULONG Flags;
    ULONG GssFlags;
    ULONG Lifetime;
    CONVERSATION_ID ConversationId;
    PMESSAGE_HEADER *Messages;
    ULONG MessageCount;
    negoex_auth_mech_t AuthMechs;
    gss_name_t InitiatorName;
    gss_OID ActualMech;
    gss_cred_id_t DelegCred;
} negoex_ctx_id_rec, *negoex_ctx_id_t;

/* negoex_util.c */
OM_uint32
negoex_parse_token(OM_uint32 *minor,
                   gss_const_buffer_t token,
                   PMESSAGE_HEADER **ppMessages,
                   ULONG *pcMessages);

OM_uint32
negoex_make_token(OM_uint32 *minor,
                  MESSAGE_HEADER **ppMessages,
                  ULONG cMessages,
                  gss_buffer_t token);

PMESSAGE_HEADER
negoex_locate_message(PMESSAGE_HEADER *pMessages,
                      ULONG cMessages,
                      MESSAGE_TYPE type);

PUCHAR
negoex_auth_scheme_at_index(negoex_ctx_id_t ctx, ULONG i);

OM_uint32
negoex_alloc_context(OM_uint32 *minor,
                     negoex_ctx_id_t *pCtx);

void *
negoex_alloc(OM_uint32 *major,
             OM_uint32 *minor,
             size_t length);

void *
negoex_calloc(OM_uint32 *major,
              OM_uint32 *minor,
              size_t count,
              size_t size);

void *
negoex_realloc(OM_uint32 *major,
               OM_uint32 *minor,
               void *ptr,
               size_t size);

void
negoex_free(void *ptr);

OM_uint32
negoex_random(OM_uint32 *minor,
              unsigned char *data,
              size_t length);

void
negoex_free_messages(PMESSAGE_HEADER *pMessages,
                     ULONG cMessages);

void
negoex_release_context(negoex_ctx_id_t ctx);

OM_uint32
negoex_add_auth_mech(OM_uint32 *minor,
                     negoex_ctx_id_t ctx,
                     gss_const_OID oid);

OM_uint32
negoex_negotiate_mechs(OM_uint32 *minor,
                       negoex_cred_id_t cred,
                       negoex_ctx_id_t ctx,
                       gss_cred_usage_t usage,
                       PNEGO_MESSAGE pMessage,
                       PAUTH_SCHEME_VECTOR schemes);

void
negoex_delete_auth_mech(negoex_ctx_id_t ctx,
                        negoex_auth_mech_t *p);

void
negoex_select_auth_mech(negoex_ctx_id_t ctx,
                        negoex_auth_mech_t mech);

OM_uint32
negoex_common_auth_schemes(OM_uint32 *minor,
                           negoex_ctx_id_t ctx,
                           AUTH_SCHEME *pAuthSchemes,
                           USHORT cAuthSchemes);

OM_uint32
negoex_delete_auth_scheme(OM_uint32 *minor,
                          negoex_ctx_id_t ctx,
                          AUTH_SCHEME authScheme);

negoex_auth_mech_t
negoex_locate_auth_scheme(negoex_ctx_id_t ctx,
                          AUTH_SCHEME authScheme);

OM_uint32
negoex_pack_auth_schemes(OM_uint32 *minor,
                         negoex_ctx_id_t ctx,
                         PUCHAR flattenedMechs,
                         USHORT *flattenedMechsCount,
                         ULONG *flattenedMechsLen);

OM_uint32
negoex_indicate_mechs(OM_uint32 *minor,
                      negoex_ctx_id_t ctx,
                      gss_OID_set *oids);

OM_uint32
negoex_add_message(OM_uint32 *minor,
                   PMESSAGE_HEADER message,
                   PMESSAGE_HEADER **ppMessages,
                   ULONG *pcMessages);

OM_uint32
negoex_alloc_message(OM_uint32 *minor,
                     negoex_ctx_id_t ctx,
                     MESSAGE_TYPE type,
                     ULONG cbHeaderLength,
                     ULONG cbMessageLength,
                     PMESSAGE_HEADER *pMessage);

OM_uint32
negoex_make_exchange_message(OM_uint32 *minor,
                             negoex_ctx_id_t ctx,
                             MESSAGE_TYPE type,
                             AUTH_SCHEME authScheme,
                             gss_buffer_t token,
                             PEXCHANGE_MESSAGE *pMessage);

OM_uint32
negoex_add_exchange_message(OM_uint32 *minor,
                            negoex_ctx_id_t ctx,
                            MESSAGE_TYPE type,
                            AUTH_SCHEME authScheme,
                            gss_buffer_t token,
                            PMESSAGE_HEADER **ppMessages,
                            ULONG *pcMessages);

OM_uint32
negoex_pulse(OM_uint32 *minor,
             negoex_ctx_id_t ctx,
             ULONG ulReason,
             PMESSAGE_HEADER **ppOutMessages,
             ULONG *pcOutMessages);

/* negoex_mech.c */
extern gss_OID GSS_NEGOEX_MECHANISM;

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_names_for_mech(OM_uint32 *minor,
                                  gss_OID mech,
                                  gss_OID_set *name_types);


OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_attrs_for_mech(OM_uint32 *minor,
                                  gss_const_OID mech,
                                  gss_OID_set *mech_attrs,
                                  gss_OID_set *known_mech_attrs);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_saslname_for_mech(OM_uint32 *minor,
                                     const gss_OID desired_mech,
                                     gss_buffer_t sasl_mech_name,
                                     gss_buffer_t mech_name,
                                     gss_buffer_t mech_description);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_mech_for_saslname(OM_uint32 *minor,
                                     const gss_buffer_t sasl_mech_name,
                                     gss_OID *mech_type);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_display_status(OM_uint32 *minor,
                          OM_uint32 status_value,
                          int status_type,
                          gss_OID mech_type,
                          OM_uint32 *message_context,
                          gss_buffer_t status_string);

/* negoex_ctx.c */
gss_ctx_id_t
negoex_active_context(negoex_ctx_id_t ctx);

negoex_auth_mech_t
negoex_active_mech(negoex_ctx_id_t ctx);

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
                            OM_uint32 *time_rec);

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
                              gss_cred_id_t *delegated_cred_handle);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_delete_sec_context(OM_uint32 *minor,
                              gss_ctx_id_t *context_handle,
                              gss_buffer_t output_token);

/* negoex_cred.c */
OM_uint32
negoex_acquire_cred(OM_uint32 *minor,
                    negoex_cred_id_t cred,
                    negoex_ctx_id_t ctx);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_acquire_cred(OM_uint32 *minor,
                        const gss_name_t desired_name,
                        OM_uint32 time_req,
                        const gss_OID_set desired_mechs,
                        int cred_usage,
                        gss_cred_id_t *output_cred_handle,
                        gss_OID_set *actual_mechs,
                        OM_uint32 *time_rec);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_acquire_cred_with_password(OM_uint32 *minor,
                                      const gss_name_t desired_name,
                                      const gss_buffer_t password,
                                      OM_uint32 time_req,
                                      const gss_OID_set desired_mechs,
                                      int cred_usage,
                                      gss_cred_id_t *output_cred_handle,
                                      gss_OID_set *actual_mechs,
                                      OM_uint32 *time_rec);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_acquire_cred_from(OM_uint32 *minor,
                             const gss_name_t desired_name,
                             OM_uint32 time_req,
                             const gss_OID_set desired_mechs,
                             gss_cred_usage_t cred_usage,
                             gss_const_key_value_set_t cred_store,
                             gss_cred_id_t *output_cred_handle,
                             gss_OID_set *actual_mechs,
                             OM_uint32 *time_rec);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_release_cred(OM_uint32 *minor,
                        gss_cred_id_t *cred);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_cred(OM_uint32 *minor,
                        gss_cred_id_t cred_handle,
                        gss_name_t *name,
                        OM_uint32 *lifetime,
                        int *cred_usage,
                        gss_OID_set *mechanisms);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_cred_by_oid(OM_uint32 *minor,
                               const gss_cred_id_t cred_handle,
                               const gss_OID desired_object,
                               gss_buffer_set_t *data_set);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_set_cred_option(OM_uint32 *minor,
                           gss_cred_id_t *cred_handle,
                           const gss_OID desired_object,
                           const gss_buffer_t value);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_set_neg_mechs(OM_uint32 *minor,
                         gss_cred_id_t cred_handle,
                         const gss_OID_set mech_list);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_store_cred(OM_uint32 *minor,
                      gss_cred_id_t input_cred,
                      gss_cred_usage_t cred_usage,
                      const gss_OID desired_mech,
                      OM_uint32 overwrite_cred,
                      OM_uint32 default_cred,
                      gss_OID_set *elements_stored,
                      gss_cred_usage_t *cred_usage_stored);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_store_cred_into(OM_uint32 *minor,
                           gss_cred_id_t input_cred,
                           gss_cred_usage_t cred_usage,
                           const gss_OID desired_mech,
                           OM_uint32 overwrite_cred,
                           OM_uint32 default_cred,
                           gss_const_key_value_set_t cred_store,
                           gss_OID_set *elements_stored,
                           gss_cred_usage_t *cred_usage_stored);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_export_cred(OM_uint32 *minor,
                       gss_cred_id_t cred_handle,
                       gss_buffer_t token);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_import_cred(OM_uint32 *minor,
                       gss_buffer_t token,
                       gss_cred_id_t *cred_handle);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_acquire_cred_impersonate_name(OM_uint32 *minor,
                                         const gss_cred_id_t impersonator_cred_handle,
                                         const gss_name_t desired_name,
                                         OM_uint32 time_req,
                                         gss_OID_set desired_mechs,
                                         gss_cred_usage_t cred_usage,
                                         gss_cred_id_t *output_cred_handle,
                                         gss_OID_set *actual_mechs,
                                         OM_uint32 *time_rec);
/* negoex_mit.c */
#ifdef _GSS_STATIC_LINK
int gss_negoexint_lib_init(void);
void gss_negoexint_lib_fini(void);
#endif

/* reentrancy protection */
OM_uint32
negoex_enter_call(OM_uint32 *minor);

OM_uint32
negoex_leave_call(OM_uint32 *minor);

int
negoex_in_call_p(void);

#define negoex_zero_buffer(x) zap((x)->value, (x)->length)

/* negoex_stubs.c */
OM_uint32 GSSAPI_CALLCONV
negoex_gss_context_time(OM_uint32 *minor,
                        gss_ctx_id_t context_handle,
                        OM_uint32 *time_rec);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_get_mic(OM_uint32 *minor,
                   gss_ctx_id_t context_handle,
                   gss_qop_t qop_req,
                   gss_buffer_t message_buffer,
                   gss_buffer_t message_token);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_verify_mic(OM_uint32 *minor,
                      gss_ctx_id_t context_handle,
                      gss_buffer_t message_buffer,
                      gss_buffer_t message_token,
                      gss_qop_t *qop_state);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_wrap(OM_uint32 *minor,
                gss_ctx_id_t context_handle,
                int conf_req_flag,
                gss_qop_t qop_req,
                gss_buffer_t input_message_buffer,
                int *conf_state,
                gss_buffer_t output_message_buffer);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_unwrap(OM_uint32 *minor,
                  gss_ctx_id_t ctx,
                  gss_buffer_t input_message_buffer,
                  gss_buffer_t output_message_buffer,
                  int *conf_state,
                  gss_qop_t *qop_state);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_compare_name(OM_uint32 *minor,
                        gss_name_t name1,
                        gss_name_t name2,
                        int *name_equal);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_display_name(OM_uint32 *minor,
                        gss_name_t name,
                        gss_buffer_t output_name_buffer,
                        gss_OID *output_name_type);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_import_name(OM_uint32 *minor,
                       gss_buffer_t import_name_buffer,
                       gss_OID input_name_type,
                       gss_name_t *output_name);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_release_name(OM_uint32 *minor,
                        gss_name_t *name);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_export_sec_context(OM_uint32 *minor,
                             gss_ctx_id_t *context_handle,
                             gss_buffer_t interprocess_token);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_import_sec_context(OM_uint32 *minor,
                              gss_buffer_t interprocess_token,
                              gss_ctx_id_t *context_handle);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_context(OM_uint32 *minor,
                           gss_ctx_id_t context_handle,
                           gss_name_t *src_name,
                           gss_name_t *targ_name,
                           OM_uint32 *lifetime_rec,
                           gss_OID *mech_type,
                           OM_uint32 *ctx_flags,
                           int *locally_initiated,
                           int *open);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_wrap_size_limit(OM_uint32 *minor,
                           gss_ctx_id_t context_handle,
                           int conf_req_flag,
                           gss_qop_t qop_req,
                           OM_uint32 req_output_size,
                           OM_uint32 *max_input_size);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_duplicate_name(OM_uint32 *minor,
                          const gss_name_t input_name,
                          gss_name_t *dest_name);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_sec_context_by_oid(OM_uint32 *minor,
                                      const gss_ctx_id_t context_handle,
                                      const gss_OID desired_object,
                                      gss_buffer_set_t *data_set);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_set_sec_context_option(OM_uint32 *minor,
                                  gss_ctx_id_t *pCtx,
                                  const gss_OID desired_object,
                                  const gss_buffer_t value);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_wrap_iov(OM_uint32 *minor,
                    gss_ctx_id_t context_handle,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    int *conf_state,
                    gss_iov_buffer_desc *iov,
                    int iov_count);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_unwrap_iov(OM_uint32 *minor,
                      gss_ctx_id_t context_handle,
                      int *conf_state,
                      gss_qop_t *qop_state,
                      gss_iov_buffer_desc *iov,
                      int iov_count);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_wrap_iov_length(OM_uint32 *minor,
                           gss_ctx_id_t context_handle,
                           int conf_req_flag,
                           gss_qop_t qop_req,
                           int *conf_state,
                           gss_iov_buffer_desc *iov,
                           int iov_count);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_get_mic_iov(OM_uint32 *minor, gss_ctx_id_t context_handle,
                       gss_qop_t qop_req, gss_iov_buffer_desc *iov,
                       int iov_count);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_verify_mic_iov(OM_uint32 *minor, gss_ctx_id_t context_handle,
                          gss_qop_t *qop_state, gss_iov_buffer_desc *iov,
                          int iov_count);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_get_mic_iov_length(OM_uint32 *minor,
                              gss_ctx_id_t context_handle, gss_qop_t qop_req,
                              gss_iov_buffer_desc *iov, int iov_count);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_complete_auth_token(OM_uint32 *minor,
                               const gss_ctx_id_t context_handle,
                               gss_buffer_t input_message_buffer);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_display_name_ext(OM_uint32 *minor,
                            gss_name_t name,
                            gss_OID display_as_name_type,
                            gss_buffer_t display_name);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_name(OM_uint32 *minor,
                        gss_name_t name,
                        int *name_is_MN,
                        gss_OID *MN_mech,
                        gss_buffer_set_t *attrs);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_get_name_attribute(OM_uint32 *minor,
                              gss_name_t name,
                              gss_buffer_t attr,
                              int *authenticated,
                              int *complete,
                              gss_buffer_t value,
                              gss_buffer_t display_value,
                              int *more);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_set_name_attribute(OM_uint32 *minor,
                              gss_name_t name,
                              int complete,
                              gss_buffer_t attr,
                              gss_buffer_t value);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_delete_name_attribute(OM_uint32 *minor,
                                 gss_name_t name,
                                 gss_buffer_t attr);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_export_name_composite(OM_uint32 *minor,
                                 gss_name_t input_name,
                                 gss_buffer_t exported_name);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_map_name_to_any(OM_uint32 *minor,
                           gss_name_t name,
                           int authenticated,
                           gss_buffer_t type_id,
                           gss_any_t *output);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_release_any_name_mapping(OM_uint32 *minor,
                                    gss_name_t name,
                                    gss_buffer_t type_id,
                                    gss_any_t *input);

OM_uint32 GSSAPI_CALLCONV
negoex_gss_pseudo_random(OM_uint32 *minor,
                         gss_ctx_id_t context_handle,
                         int prf_key,
                         const gss_buffer_t prf_in,
                         ssize_t desired_output_len,
                         gss_buffer_t prf_out);

/* negoex_trace.c */
void
negoex_trace_auth_schemes(const char *prefix,
                          PUCHAR base,
                          PAUTH_SCHEME_VECTOR schemes);

void
negoex_trace_message(int direction, PMESSAGE_HEADER message);

#ifdef __cplusplus
}
#endif

#endif /* _GSSAPIP_NEGOEX_H_ */
