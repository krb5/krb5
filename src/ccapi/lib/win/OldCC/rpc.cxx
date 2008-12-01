/*
 * $Header$
 *
 * Copyright 2008 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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

#include <stdlib.h>
#include <stdio.h>

extern "C" {
#include "CredentialsCache.h"
#include "secure.hxx"
#include "client.h"
#include "autolock.hxx"
#include "cci_debugging.h"
    }

extern HANDLE hCCAPIv2Mutex;

#define MAKE_RPC_CALL(rc, x) \
do { \
    WaitForSingleObject( hCCAPIv2Mutex, INFINITE ); \
    SecureClient* s = 0; \
    SecureClient::Start(s); \
    CcAutoLock* a = 0; \
    CcAutoLock::Start(a, Client::sLock); \
    RpcTryExcept { \
    cci_debug_printf("RpcTry: #x"); \
        x; \
    } \
    RpcExcept(1) { \
        rc = handle_exception(RpcExceptionCode()); \
    } \
    RpcEndExcept; \
    CcAutoLock::Stop(a); \
    SecureClient::Stop(s); \
    ReleaseMutex( hCCAPIv2Mutex ); \
} while (0)

static
DWORD
handle_exception(DWORD code) {
    cci_debug_printf("Runtime reported exception %u", code);
    if (code == RPC_S_SERVER_UNAVAILABLE) {
        Client::Reconnect(0);
        }
    return 4;
    }

//////////////////////////////////////////////////////////////////////////////

cc_int32 cc_initialize() {

    CLIENT_INIT_EX(true, 4);
    cc_int32 rc = ccNoError;

    MAKE_RPC_CALL(rc, rc = 5);
    return rc;
    }