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

#ifndef WIN32
/*
 * draft-zhu-negoex-04.txt defines a GUID as a byte array, but it's typically
 * defined as follows; use this definition for tracing.
 */
#pragma pack(push)
typedef struct _GUID {
    ULONG Data1;
    USHORT Data2;
    USHORT Data3;
    UCHAR Data4[8];
} GUID, *PGUID;
#pragma pack(pop)
#endif /* WIN32 */

static int
negoex_guid_to_string(UCHAR ProtocolGuid[16],
                      char *buffer,
                      size_t bufsiz)
{
    union {
        GUID Guid;
        UCHAR ProtocolGuid[16];
    } guid;

    assert(sizeof(GUID) == 16);

    memcpy(guid.ProtocolGuid, ProtocolGuid, sizeof(GUID));

    negoex_swap_ULONG(&guid.Guid.Data1);
    negoex_swap_USHORT(&guid.Guid.Data2);
    negoex_swap_USHORT(&guid.Guid.Data3);

    return snprintf(buffer, bufsiz,
                    "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                    guid.Guid.Data1, guid.Guid.Data2, guid.Guid.Data3,
                    guid.Guid.Data4[0], guid.Guid.Data4[1], guid.Guid.Data4[2],
                    guid.Guid.Data4[3], guid.Guid.Data4[4], guid.Guid.Data4[5],
                    guid.Guid.Data4[6], guid.Guid.Data4[7]);
}

void
negoex_trace_auth_schemes(const char *prefix,
                          PUCHAR base,
                          PAUTH_SCHEME_VECTOR schemes)
{
    ULONG i;
    char szTraceMsg[128];
    char szAuthScheme[37];
    krb5_context context;

    for (i = 0; i < schemes->AuthSchemeCount; i++) {
        PUCHAR p = base + schemes->AuthSchemeArrayOffset +
                   (i * AUTH_SCHEME_LENGTH);

        negoex_guid_to_string(p, szAuthScheme, sizeof(szAuthScheme));

        snprintf(szTraceMsg, sizeof(szTraceMsg),
                 "NEGOEXTS: %20s[%02u] -- AuthScheme %s",
                 prefix, i, szAuthScheme);
        if (krb5_init_context(&context) == 0) {
            TRACE_NEGOEX_AUTH_SCHEMES(context, szTraceMsg);
            krb5_free_context(context);
        }
    }
}

void
negoex_trace_message(int direction, PMESSAGE_HEADER message)
{
    char szTraceMsg[128];
    char szConvId[37];
    char *szMessageType;
    krb5_context context;

    switch (message->MessageType) {
    case MESSAGE_TYPE_INITIATOR_NEGO:
        szMessageType = "INITIATOR_NEGO";
        break;
    case MESSAGE_TYPE_ACCEPTOR_NEGO:
        szMessageType = "ACCEPTOR_NEGO";
        break;
    case MESSAGE_TYPE_INITIATOR_META_DATA:
        szMessageType = "INITIATOR_META_DATA";
        break;
    case MESSAGE_TYPE_ACCEPTOR_META_DATA:
        szMessageType = "ACCEPTOR_META_DATA";
        break;
    case MESSAGE_TYPE_CHALLENGE:
        szMessageType = "CHALLENGE";
        break;
    case MESSAGE_TYPE_AP_REQUEST:
        szMessageType = "AP_REQUEST";
        break;
    case MESSAGE_TYPE_VERIFY:
        szMessageType = "VERIFY";
        break;
    case MESSAGE_TYPE_ALERT:
        szMessageType = "ALERT";
        break;
    default:
        szMessageType = "UNKNOWN";
        break;
    }

    negoex_guid_to_string(message->ConversationId, szConvId, sizeof(szConvId));
    snprintf(szTraceMsg, sizeof(szTraceMsg),
            "NEGOEXTS%c %20s[%02u] -- ConvId %s HdrLength %u MsgLength %u",
            direction ? '<' : '>',
            szMessageType, message->SequenceNum, szConvId,
            message->cbHeaderLength, message->cbMessageLength);

    if (krb5_init_context(&context) == 0) {
        TRACE_NEGOEX_MESSAGE(context, szTraceMsg);
        krb5_free_context(context);
    }
}
