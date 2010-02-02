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

extern "C" {
#include "k5-thread.h"
#include "ccapi_os_ipc.h"
#include "cci_debugging.h"
#include "ccs_reply.h"
#include "ccs_request.h"
#include "ccutils.h"
#include "tls.h"
#include "util.h"
#include "win-utils.h"
    }

#include "autolock.hxx"
#include "CredentialsCache.h"
#include "secure.hxx"
#include "opts.hxx"
#include "client.h"

extern "C" DWORD GetTlsIndex();

#define SECONDS_TO_WAIT 10
#define CLIENT_REQUEST_RPC_HANDLE ccs_request_IfHandle

extern HANDLE           hCCAPIv2Mutex;
ParseOpts::Opts         opts                = { 0 };
PSECURITY_ATTRIBUTES    psa                 = 0;
SECURITY_ATTRIBUTES     sa                  = { 0 };

/* The layout of the rest of this module:  

   The entrypoints defined in ccs_os_ipc.h:
    cci_os_ipc_thread_init
    cci_os_ipc

   Other routines needed by those four.
    cci_os_connect
    handle_exception
 */

cc_int32        ccapi_connect(const struct tspdata* tsp);
static DWORD    handle_exception(DWORD code);

extern "C" {
cc_int32        cci_os_ipc_msg( cc_int32        in_launch_server,
                                k5_ipc_stream    in_request_stream,
                                cc_int32        in_msg,
                                k5_ipc_stream*   out_reply_stream);
    }

/* ------------------------------------------------------------------------ */

extern "C" cc_int32 cci_os_ipc_thread_init (void) {
    cc_int32                    err         = ccNoError;
    struct tspdata*             ptspdata;
    HANDLE                      replyEvent;
    UUID __RPC_FAR              uuid;
    unsigned char __RPC_FAR*    uuidString  = NULL;

    if (!GetTspData(GetTlsIndex(), &ptspdata)) return ccErrNoMem;

    opts.cMinCalls  = 1;
    opts.cMaxCalls  = 20;
    opts.fDontWait  = TRUE;

    err   = cci_check_error(UuidCreate(&uuid)); // Get a UUID
    if (err == RPC_S_OK) {                      // Convert to string
        err = UuidToString(&uuid, &uuidString);
        }
    if (!err) {                                 // Save in thread local storage
        tspdata_setUUID(ptspdata, uuidString);
        }
#if 0
    cci_debug_printf("%s UUID:<%s>", __FUNCTION__, tspdata_getUUID(ptspdata));
#endif
    // Initialize old CCAPI if necessary:
    if (!err) if (!Init::  Initialized()) err = Init::  Initialize( );
    if (!err) if (!Client::Initialized()) err = Client::Initialize(0);

    if (!err) {
        /* Whenever a reply to an RPC request is received, the RPC caller needs to
           know when the reply has been received.  It does that by waiting for a 
           client-specific event to be set.  Define the event name to be <UUID>_reply:  */
        replyEvent = createThreadEvent((char*)uuidString, REPLY_SUFFIX);
        }

    if (replyEvent) tspdata_setReplyEvent(ptspdata, replyEvent);
    else            err = cci_check_error(GetLastError());

    if (uuidString) RpcStringFree(&uuidString);

    return cci_check_error(err);
    }


/* ------------------------------------------------------------------------ */

void cci_os_ipc_thread_fini (void)
{    
}


/* ------------------------------------------------------------------------ */

cc_int32 cci_os_ipc (cc_int32      in_launch_server,
                     k5_ipc_stream in_request_stream,
                     k5_ipc_stream* out_reply_stream) {
    return cci_os_ipc_msg(  in_launch_server, 
                            in_request_stream, 
                            CCMSG_REQUEST, 
                            out_reply_stream);
    }

extern "C" cc_int32 cci_os_ipc_msg( cc_int32        in_launch_server,
                                    k5_ipc_stream    in_request_stream,
                                    cc_int32        in_msg,
                                    k5_ipc_stream*   out_reply_stream) {

    cc_int32        err             = ccNoError;
    cc_int32        done            = FALSE;
    cc_int32        try_count       = 0;
    cc_int32        server_died     = FALSE;
    TCHAR*          pszStringBinding= NULL;
    struct tspdata* ptspdata        = NULL;
    char*           uuid            = NULL;
    int             lenUUID         = 0;
    unsigned int    trycount        = 0;
    time_t          sst             = 0;
    STARTUPINFO             si      = { 0 };
    PROCESS_INFORMATION     pi      = { 0 };
    HANDLE          replyEvent      = 0;
    BOOL            bCCAPI_Connected= FALSE;

    if (!in_request_stream) { err = cci_check_error (ccErrBadParam); }
    if (!out_reply_stream ) { err = cci_check_error (ccErrBadParam); }
    
    if (!GetTspData(GetTlsIndex(), &ptspdata)) {return ccErrBadParam;}
    bCCAPI_Connected = tspdata_getConnected  (ptspdata);
    replyEvent       = tspdata_getReplyEvent (ptspdata);
    sst              = tspdata_getSST (ptspdata);
    uuid             = tspdata_getUUID(ptspdata);

    // The lazy connection to the server has been put off as long as possible!
    // ccapi_connect starts listening for replies as an RPC server and then
    //   calls ccs_rpc_connect.
    if (!bCCAPI_Connected) {
        err                 = cci_check_error(ccapi_connect(ptspdata));
        bCCAPI_Connected    = !err;
        tspdata_setConnected(ptspdata, bCCAPI_Connected);
        }

    // Clear replyEvent so we can detect when a reply to our request has been received:
    ResetEvent(replyEvent);
    
    //++ Use the old CCAPI implementation to try to talk to the server:
    // It has all the code to use the RPC in a thread-safe way, make the endpoint, 
    //   (re)connect and (re)start the server.
    // Note:  the old implementation wrapped the thread-safety stuff in a macro.
    //   Here it is expanded and thus duplicated for each RPC call.  The new code has
    //   a very limited number of RPC calls, unlike the older code.
    WaitForSingleObject( hCCAPIv2Mutex, INFINITE );
    SecureClient*   s = 0;
    SecureClient::Start(s);
    CcAutoLock*     a = 0;
    CcAutoLock::Start(a, Client::sLock);

    // Initialize old CCAPI if necessary:
    if (!err) if (!Init::  Initialized()) err = cci_check_error(Init::  Initialize( ));
    if (!err) if (!Client::Initialized()) err = cci_check_error(Client::Initialize(0));

    // New code using new RPC procedures for sending the data and receiving a reply:
    if (!err) {
        RpcTryExcept {
            if (!GetTspData(GetTlsIndex(), &ptspdata)) {return ccErrBadParam;}
            uuid    = tspdata_getUUID(ptspdata);
            lenUUID = 1 + strlen(uuid);     /* 1+ includes terminating \0. */
#if 0
            cci_debug_printf("%s calling remote ccs_rpc_request tsp*:0x%X", __FUNCTION__, ptspdata);
            cci_debug_printf("  rpcmsg:%d; UUID[%d]:<%s> SST:%ld", in_msg, lenUUID, uuid, sst);
#endif
            ccs_rpc_request(                    /* make call with user message: */
                in_msg,                         /* Message type */
                (unsigned char*)&ptspdata,      /* Our tspdata* will be sent back to the reply proc. */
                (unsigned char*)uuid,
                k5_ipc_stream_size(in_request_stream),
                (unsigned char*)k5_ipc_stream_data(in_request_stream), /* Data buffer */
                sst,                            /* session start time */
                (long*)(&err) );                /* Return code */
            }
        RpcExcept(1) {
            handle_exception(RpcExceptionCode());
            }
        RpcEndExcept;
        }

    cci_check_error(err);
    CcAutoLock::Stop(a);
    SecureClient::Stop(s);
    ReleaseMutex(hCCAPIv2Mutex);       
    //-- Use the old CCAPI implementation to try to talk to the server.

    // Wait for reply handler to set event:
    if (!err) {
        err = cci_check_error(WaitForSingleObject(replyEvent, INFINITE));//(SECONDS_TO_WAIT)*1000));
        }

    if (!err) {
        err = cci_check_error(RpcMgmtIsServerListening(CLIENT_REQUEST_RPC_HANDLE));
        }

    if (!err && server_died) {
        err = cci_check_error (ccErrServerUnavailable);
        }
#if 0    
    if (err == BOOTSTRAP_UNKNOWN_SERVICE && !in_launch_server) {
        err = ccNoError;  /* If the server is not running just return an empty stream. */
        }
#endif

    if (!err) {
        *out_reply_stream = tspdata_getStream(ptspdata);
        }

    return cci_check_error (err);    
    }



static DWORD handle_exception(DWORD code) {
    cci_debug_printf("%s code %u; ccs_request_IfHandle:0x%X", __FUNCTION__, code, ccs_request_IfHandle);
    if ( (code == RPC_S_SERVER_UNAVAILABLE) || (code == RPC_S_INVALID_BINDING) ) {
        Client::Reconnect(0);
        }
    return 4;
    }


/* Establish a CCAPI connection with the server.
 * The connect logic here is identical to the logic in the send request code.
 * TODO:  merge this connect code with that request code.
 */
cc_int32 ccapi_connect(const struct tspdata* tsp) {
    BOOL                    bListen     = TRUE;
    char*                   endpoint    = NULL;
    HANDLE                  replyEvent  = 0;
    RPC_STATUS              status      = FALSE;
    char*                   uuid        = NULL;

    /* Start listening to our uuid before establishing the connection,
     *  so that when the server tries to call ccapi_listen, we will be ready.
     */

    /* Build complete RPC uuid using previous CCAPI implementation: */
    replyEvent      = tspdata_getReplyEvent(tsp);
    uuid            = tspdata_getUUID(tsp);
    endpoint        = clientEndpoint(uuid);
    cci_debug_printf("%s Registering endpoint %s", __FUNCTION__, endpoint);

    opts.cMinCalls  = 1;
    opts.cMaxCalls  = 20;
    opts.fDontWait  = TRUE;

    if (!status) {
        status = RpcServerUseProtseqEp((RPC_CSTR)"ncalrpc",
                                       opts.cMaxCalls,
                                       (RPC_CSTR)endpoint,
                                       sa.lpSecurityDescriptor);  // SD
        cci_check_error(status);
        }

    if (!status) {
        status = RpcServerRegisterAuthInfo(0, // server principal
                                           RPC_C_AUTHN_WINNT,
                                           0,
                                           0 );
        cci_check_error(status);
        }

    cci_debug_printf("%s is listening ...", __FUNCTION__);

    if (!status) {
        if (!isNT()) {
            status = RpcServerRegisterIf(ccs_reply_ServerIfHandle,  // interface 
                                         NULL,                      // MgrTypeUuid
                                         NULL);                     // MgrEpv; null means use default
            } 
        else {
            status = RpcServerRegisterIfEx(ccs_reply_ServerIfHandle,// interface
                                         NULL,                      // MgrTypeUuid
                                         NULL,                      // MgrEpv; 0 means default
                                         RPC_IF_ALLOW_SECURE_ONLY,
                                         opts.cMaxCalls,
                                         NULL);                     // No security callback.
            }

        cci_check_error(status);

        if (!status) {
            status = RpcServerListen(opts.cMinCalls,
                                     opts.cMaxCalls,
                                     TRUE);
            cci_check_error(status);
            }
        }

    // Clear replyEvent so we can detect when a reply to our connect request has been received:
    ResetEvent(replyEvent);

    // We use the old CCAPI implementation to try to talk to the server.  
    // It has all the code to make the uuid, (re)connect and (re)start the server.
    WaitForSingleObject( hCCAPIv2Mutex, INFINITE );
    SecureClient*   s = 0;
    SecureClient::Start(s);
    CcAutoLock*     a = 0;
    CcAutoLock::Start(a, Client::sLock);

    // Initialize old CCAPI if necessary:
    if (!status) if (!Init::  Initialized()) status = Init::  Initialize( );
    if (!status) if (!Client::Initialized()) status = Client::Initialize(0);

    // New code using new RPC procedures for sending the data and receiving a reply:
    if (!status) {
        RpcTryExcept {
            ccs_rpc_connect(                /* make call with user message: */
                CCMSG_CONNECT,              /* Message type */
                (unsigned char*)&tsp,       /* Our tspdata* will be sent back to the reply proc. */
                (unsigned char*)uuid,
                (long*)(&status) );         /* Return code */
            }
        RpcExcept(1) {
            cci_check_error(RpcExceptionCode());
            status  = ccErrBadInternalMessage;
            }
        RpcEndExcept;
        }

    CcAutoLock::Stop(a);
    SecureClient::Stop(s);
    ReleaseMutex(hCCAPIv2Mutex);       

    if (!status) {
#if 0
        cci_debug_printf("%s Waiting for replyEvent.", __FUNCTION__);
#endif
        status = WaitForSingleObject(replyEvent, INFINITE);//(SECONDS_TO_WAIT)*1000);
        status = cci_check_error(RpcMgmtIsServerListening(CLIENT_REQUEST_RPC_HANDLE));
        cci_debug_printf("  Server %sFOUND!", (status) ? "NOT " : "");
        }
    if (status) {
        cci_debug_printf("  unexpected error while looking for server... (%u)", status);
        } 
    
    return status;
    }