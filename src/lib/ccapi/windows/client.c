#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include "ntccrpc.h"
#include <strsafe.h>
#include "CredentialsCache.h"
#include "msg.h"

static RPC_BINDING_HANDLE hRpcBinding;

void * __RPC_USER MIDL_user_allocate(size_t s) {
    return malloc(s);
}

void __RPC_USER MIDL_user_free(void * p) {
    free(p);
}

int cc_rpc_init(void) {
    RPC_STATUS status;
    TCHAR * bindstring = NULL;
    RPC_SECURITY_QOS sqos;

    status = RpcStringBindingCompose(NULL,
                                     _T("ncalrpc"),
                                     NULL,
                                     NULL,
                                     NULL,
                                     &bindstring);

    if (status != RPC_S_OK) {
        fprintf(stderr, "RpcStringBindingCompose failed: %d\n",
                status);
        return 1;
    }

    status = RpcBindingFromStringBinding(bindstring,
                                         &hRpcBinding);

    if (status != RPC_S_OK) {
        fprintf(stderr, "RpcBindingFromStringBinding failed: %d\n",
                status);
        return 1;
    }

    status = RpcStringFree(&bindstring);

    ZeroMemory(&sqos, sizeof(sqos));

    sqos.Version = 1;
    sqos.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
    sqos.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;
    sqos.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;

    status = RpcBindingSetAuthInfoEx(hRpcBinding,
                                     NULL,
                                     RPC_C_AUTHN_LEVEL_CALL,
                                     RPC_C_AUTHN_WINNT,
                                     NULL,
                                     0,
                                     &sqos);
    if (status != RPC_S_OK) {
        fprintf(stderr, "RpcBindingSetAuthInfoEx failed: %d\n",
                status);
        return 1;
    }

    return 0;
}

int cc_rpc_cleanup(void) {
    RPC_STATUS status;

    status = RpcBindingFree(&hRpcBinding);

    return 0;
}

cc_int32 cci_set_thread_session_id(unsigned char * client_name, LUID luid) {

}

void cci_get_thread_session_id(unsigned char * client_name, int len, LUID *pluid) {

}


/* __int32 ccapi_Message(
 * [in] handle_t h,
 * [string][in] unsigned char *client_name,
 * [in] struct _LUID luid,
 * [in] __int32 cb_buffer,
 * [out] __int32 *cb_len,
 * [size_is][string][out] unsigned char buffer[  ]);
 */

cc_int32 cci_perform_rpc(cc_msg_t *request, cc_msg_t **response)
{
    __int32 rpc_code;
    unsigned char client_name[256];
    LUID luid;
    struct __LUID __luid;
    unsigned char out_buf[MAXMSGLEN];
    __int32  out_len = MAXMSGLEN;

    if (!cc_rpc_init())
	return -1;

    cci_get_thread_session_id(client_name, sizeof(client_name), &luid);

    __luid.HighPart = luid.HighPart;
    __luid.LowPart  = luid.LowPart;

    rpc_code = ccapi_Message(hRpcBinding, client_name, __luid, 
 			     request->flat, request->flat_len, 
			     out_buf, &out_len);

    return rpc_code;
}
