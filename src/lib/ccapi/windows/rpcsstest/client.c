#include<windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<tchar.h>
#include"cstest.h"
#include<strsafe.h>

void * __RPC_USER MIDL_user_allocate(size_t s) {
    return malloc(s);
}

void __RPC_USER MIDL_user_free(void * p) {
    free(p);
}

int main(int argc, char ** argv) {
    RPC_STATUS status;
    RPC_BINDING_HANDLE h;
    TCHAR * bindstring = NULL;
    RPC_SECURITY_QOS sqos;
    char inbuf[256];
    char outbuf[256];
    long cb_out;

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
                                         &h);

    if (status != RPC_S_OK) {
        fprintf(stderr, "RpcBindingFromStringBinding failed: %d\n",
                status);
        return 1;
    }

    ZeroMemory(&sqos, sizeof(sqos));

    sqos.Version = 1;
    sqos.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
    sqos.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;
    sqos.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;

    status = RpcBindingSetAuthInfoEx(h,
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

    StringCbCopyA(inbuf, sizeof(inbuf), "Echo Test 1");
    StringCbCopyA(outbuf, sizeof(outbuf), "Blank blank blank");

    printf("Before call: in[%s], out[%s]\n", inbuf, outbuf);
    cb_out = 0;

    status = EchoString(h, inbuf, sizeof(outbuf), &cb_out, outbuf);

    if (status) {
        printf("Call failed: status = %d\n", status);
    } else {
        printf("After call: out[%s], outlen[%d]\n", outbuf, cb_out);
    }

    status = RpcBindingFree(&h);

    status = RpcStringFree(&bindstring);

    return 0;
}
