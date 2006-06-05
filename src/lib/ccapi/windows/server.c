
#include <windows.h>
#include "msg.h"
#include "marshall.h"
#include "serv_ops.h"
#include "datastore.h"
#include <stdio.h>
#include <process.h>
#include <tchar.h>
#include <rpc.h>
#include <rpcndr.h>
#include "ntccrpc.h"
#include <strsafe.h>

#define SVCNAME "MIT_CCAPI_NT_Service"

HANDLE hMainThread = 0;
HANDLE WaitToTerminate = 0;

SERVICE_STATUS_HANDLE h_service_status = NULL;
SERVICE_STATUS service_status;
FILE * logfile = NULL;

/* Log File */
void begin_log(void) {
    char temppath[512];

    temppath[0] = L'\0';

    GetTempPathA(sizeof(temppath), temppath);
    StringCbCatA(temppath, sizeof(temppath), "mit_nt_ccapi.log");
    logfile = fopen(temppath, "w");
}

void end_log(void) {
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
}

BOOL report_status(DWORD state,
                   DWORD exit_code,
                   DWORD wait_hint) {
    static DWORD checkpoint = 1;
    BOOL rv = TRUE;

    if (state == SERVICE_START_PENDING)
        service_status.dwControlsAccepted = 0;
    else
        service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    service_status.dwCurrentState = state;
    service_status.dwWin32ExitCode = exit_code;
    service_status.dwWaitHint = wait_hint;

    if (state == SERVICE_RUNNING ||
        state == SERVICE_STOPPED)
        service_status.dwCheckPoint = 0;
    else
        service_status.dwCheckPoint = checkpoint++;

    rv = SetServiceStatus(h_service_status, &service_status);

    return rv;
}

void service_start(DWORD argc, LPTSTR * argv) {
    RPC_STATUS status;
    RPC_BINDING_VECTOR * bv;

    status = RpcServerUseProtseq("ncalrpc",
                                 RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
                                 NULL);

    if (status != RPC_S_OK) {
	if (logfile) fprintf(logfile, "service_start RpcServerUseProtseq = 0x%x\n", status);
        goto cleanup;
    }

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    status = RpcServerRegisterIf(portable_ccapi_v1_0_s_ifspec,
                                 0, 0);

    if (status != RPC_S_OK) {
	if (logfile) fprintf(logfile, "service_start RpcServerRegisterIf = 0x%x\n", status);
        goto cleanup;
    }

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    status = RpcServerInqBindings(&bv);

    if (status != RPC_S_OK) {
	if (logfile) fprintf(logfile, "service_start RpcServerInqBindings = 0x%x\n", status);
        goto cleanup;
    }

    status = RpcEpRegister(portable_ccapi_v1_0_s_ifspec,
                           bv, 0, 0);

    if (status != RPC_S_OK) {
	if (logfile) fprintf(logfile, "service_start RpcEpRegister = 0x%x\n", status);
        goto cleanup;
    }

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    status = RpcServerRegisterAuthInfo(NULL,
                                       RPC_C_AUTHN_WINNT,
                                       0, 0);

    if (status != RPC_S_OK) {
	if (logfile) fprintf(logfile, "service_start RpcServerRegisterAuthInfo = 0x%x\n", status);
        goto cleanup;
    }

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    status = RpcServerListen(2,
                             RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                             TRUE);

    if (status != RPC_S_OK) {
	if (logfile) fprintf(logfile, "service_start RpcServerListen = 0x%x\n", status);
        goto cleanup;
    }

    report_status(SERVICE_RUNNING, NO_ERROR, 0);


    if (logfile) fprintf(logfile, "service_start calling RpcMgmtWaitServerListen\n");
    status = RpcMgmtWaitServerListen();
    if (logfile) fprintf(logfile, "service_start RpcMgmtWaitServerListen = 0x%x\n", status);

  cleanup:
    RpcEpUnregister(portable_ccapi_v1_0_s_ifspec, bv, 0);

    RpcBindingVectorFree(&bv);
}

void service_stop(void) {
    if (logfile) fprintf(logfile, "service_stop\n");
    RpcMgmtStopServerListening(0);
}

void * __RPC_USER MIDL_user_allocate(size_t s) {
    return malloc(s);
}

void __RPC_USER MIDL_user_free(void * p) {
    free(p);
}

typedef struct tag_client_info {
    char client_name[512];
    LUID luid;    
} client_info_t;

int obtain_auth_info(client_info_t * client_info, cc_auth_info_t ** pauth_info)
{
    *pauth_info = (cc_auth_info_t *)malloc(sizeof(cc_auth_info_t));
    if ( !*pauth_info )
	return ccErrNoMem;
    
    (*pauth_info)->len  = strlen(client_info->client_name) + 1;
    (*pauth_info)->info = malloc((*pauth_info)->len);
    if ( !(*pauth_info)->info ) {
	free(*pauth_info);
	return ccErrNoMem;
    }

    memcpy((*pauth_info)->info, client_info->client_name, (*pauth_info)->len);
    
    return 0;
}

void destroy_auth_info(cc_auth_info_t *auth_info)
{
    free(auth_info->info);
    free(auth_info);
}

int obtain_session_info(client_info_t * client_info, cc_session_info_t ** psession_info)
{
    *psession_info = (cc_session_info_t *)malloc(sizeof(cc_session_info_t));
    if ( !*psession_info )
	return ccErrNoMem;
    
    (*psession_info)->len  = sizeof(LUID);
    (*psession_info)->info = malloc((*psession_info)->len);
    if ( !(*psession_info)->info ) {
	free(*psession_info);
	return ccErrNoMem;
    }

    memcpy((*psession_info)->info, &client_info->luid, (*psession_info)->len);
    
    return 0;
}

void destroy_session_info(cc_session_info_t *session_info)
{
    free(session_info->info);
    free(session_info);
}

RPC_STATUS check_auth(handle_t h, client_info_t * client_info) {
    RPC_BINDING_HANDLE bh = (RPC_BINDING_HANDLE) h;
    RPC_STATUS status;
    HANDLE htoken = NULL;
    char name[256];
    char domain[256];
    DWORD name_len;
    DWORD domain_len;
    SID_NAME_USE snu = 0;

    struct {
        TOKEN_ORIGIN origin;
        char pad[512];
    } torigin;

    struct {
        TOKEN_OWNER owner;
        char pad[4096];
    } towner;

    DWORD len;

    status = RpcImpersonateClient(bh);

    if (status != RPC_S_OK)
        return status;

    if (!OpenThreadToken(GetCurrentThread(),
                         TOKEN_READ | TOKEN_QUERY_SOURCE,
                         FALSE,
                         &htoken)) {
        status = GetLastError();
        goto _cleanup;
    }

    len = 0;

    if (!GetTokenInformation(htoken,
                             TokenOrigin,
                             &torigin.origin,
                             sizeof(torigin),
                             &len)) {
        status = GetLastError();
        goto _cleanup;
    }

    if (!GetTokenInformation(htoken,
                             TokenOwner,
                             &towner.owner,
                             sizeof(towner),
                             &len)) {
        status = GetLastError();
        goto _cleanup;
    }


    name_len = sizeof(name)/sizeof(name[0]);
    domain_len = sizeof(domain)/sizeof(domain[0]);

    if (!LookupAccountSidA(NULL,
                           towner.owner.Owner,
                           name,
                           &name_len,
                           domain,
                           &domain_len,
                           &snu)) {
        status = GetLastError();
        goto _cleanup;
    }

    client_info->luid = torigin.origin.OriginatingLogonSession;
    StringCbPrintfA(client_info->client_name,
                    sizeof(client_info->client_name),
                    "%s\\%s", domain, name);

    status = 0;

 _cleanup:

    RpcRevertToSelf();

    return status;
}

__int32 ccapi_Message( 
    /* [in] */ handle_t h,
    /* [string][in] */ unsigned char *client_name,
    /* [in] */ struct __LUID luid,
    /* [size_is][length_is][in] */ unsigned char in_buf[],
    /* [in] */ __int32 in_len,
    /* [size_is][length_is][out] */ unsigned char out_buf[],
    /* [out] */ __int32 *out_len)
{
    client_info_t client_info;
    cc_msg_t *          msg;
    cc_msg_t *          resp;
    cc_auth_info_t    * auth_info;
    cc_session_info_t * session_info;
    cc_int32            code;

    if (logfile) fprintf(logfile, "ccapi_Message\n");

    if ( ccs_serv_initialize() != ccNoError ) {
	code = ccErrServerUnavailable;
	goto done;
    }

    code = check_auth(h, &client_info);
    if (code == 0) {
	if (!strcmp("SYSTEM",client_info.client_name) &&
	     client_info.luid.HighPart == 0 &&
	     client_info.luid.LowPart == 0 &&
	     client_name != NULL &&
	     client_name[0] != '\0') {
	    StringCbPrintfA(client_info.client_name,
			     sizeof(client_info.client_name),
			     "%s", client_name);
	    client_info.luid.HighPart = luid.HighPart;
	    client_info.luid.LowPart  = luid.LowPart;
	}
    } else {
	code = ccErrServerCantBecomeUID;
	goto done;
    }

    /* allocate message */
    msg = (cc_msg_t *)malloc(sizeof(cc_msg_t));
    if (!msg) {
	code = ccErrNoMem;
	goto done;
    }

    /* unflatten message */
    code = cci_msg_unflatten(in_buf, in_len, &msg);
    if (code)
	goto cleanup;

    /* obtain auth info */
    code = obtain_auth_info(&client_info, &auth_info);
    if (code)
	goto cleanup;

    /* obtain session info */
    code = obtain_session_info(&client_info, &session_info);
    if (code)
	goto cleanup;

    /* process message */
    code = ccs_serv_process_msg(msg, auth_info, session_info, &resp);
    if (code)
	goto cleanup;

    /* flatten response */
    code = cci_msg_flatten(resp, NULL);
    if (code)
	goto cleanup;

    /* send response */
    if (resp->flat_len > MAXMSGLEN) {
	code = ccErrBadInternalMessage;
	goto cleanup;
    }
    memcpy(out_buf, resp->flat, resp->flat_len);
    *out_len = resp->flat_len;
    code = ccNoError;

  cleanup:
    if (auth_info)
	destroy_auth_info(auth_info);

    if (session_info)
	destroy_session_info(session_info);

    /* free message */
    if (msg)
	cci_msg_destroy(msg);

    /* free response */
    if (resp)
	cci_msg_destroy(resp);

  done:
    return code ? -1 : 0;
}

void WINAPI service_control(DWORD ctrl_code) {
    switch(ctrl_code) {
    case SERVICE_CONTROL_STOP:
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
        service_stop();
        return;

        /* everything else falls through */
    }

    report_status(service_status.dwCurrentState, NO_ERROR, 0);
}

void WINAPI service_main(DWORD argc, LPTSTR * argv) {

    begin_log();

    h_service_status = RegisterServiceCtrlHandler( _T(SVCNAME), service_control);

    if (!h_service_status)
        goto cleanup;

    ZeroMemory(&service_status, sizeof(service_status));

    service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status.dwServiceSpecificExitCode = 0;

    if (!report_status(SERVICE_START_PENDING,
                       NO_ERROR,
                       3000))
        goto cleanup;

    service_start(argc, argv);

 cleanup:

    if (h_service_status) {
        report_status(SERVICE_STOPPED, NO_ERROR, 0);
    }

    end_log();
}


BOOL
IsInstalled()
{
    BOOL bResult = FALSE;
    SC_HANDLE hSCM;
    SC_HANDLE hService;

    // Open the Service Control Manager
    hSCM = OpenSCManager( NULL, // local machine
                          NULL, // ServicesActive database
                          SC_MANAGER_ALL_ACCESS); // full access
    if (hSCM) {

        // Try to open the service
        hService = OpenService( hSCM,
                                SVCNAME,
                                SERVICE_QUERY_CONFIG);
        if (hService) {
            bResult = TRUE;
            CloseServiceHandle(hService);
        }

        CloseServiceHandle(hSCM);
    }

    return bResult;
}

BOOL
Install()
{
    char szFilePath[_MAX_PATH];
    SC_HANDLE hSCM;
    SC_HANDLE hService;
    TCHAR szKey[256];
    HKEY hKey = NULL;
    DWORD dwData;

    // Open the Service Control Manager
    hSCM = OpenSCManager( NULL, // local machine
                          NULL, // ServicesActive database
                          SC_MANAGER_ALL_ACCESS); // full access
    if (!hSCM)
        return FALSE;

    // Get the executable file path
    GetModuleFileName(NULL, szFilePath, sizeof(szFilePath));

    // Create the service
    hService = CreateService( hSCM,
                              SVCNAME,
                              SVCNAME,
                              SERVICE_ALL_ACCESS,
                              SERVICE_WIN32_OWN_PROCESS,
                              SERVICE_AUTO_START,        // start condition
                              SERVICE_ERROR_NORMAL,
                              szFilePath,
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    // make registry entries to support logging messages
    // Add the source name as a subkey under the Application
    // key in the EventLog service portion of the registry.
    StringCbCopyA(szKey, 256, "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\IKSD");
    if (RegCreateKey(HKEY_LOCAL_MACHINE, szKey, &hKey) != ERROR_SUCCESS) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    // Add the Event ID message-file name to the 'EventMessageFile' subkey.
    RegSetValueEx( hKey,
                   "EventMessageFile",
                    0,
                    REG_EXPAND_SZ,
                    (CONST BYTE*)szFilePath,
                    strlen(szFilePath) + 1);

    // Set the supported types flags.
    dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    RegSetValueEx( hKey,
                   "TypesSupported",
                    0,
                    REG_DWORD,
                    (CONST BYTE*)&dwData,
                     sizeof(DWORD));
    RegCloseKey(hKey);

    // LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_INSTALLED, SVCNAME);

    // tidy up
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return TRUE;
}

BOOL
Uninstall()
{
    BOOL bResult = FALSE;
    SC_HANDLE hService;
    SC_HANDLE hSCM;

    // Open the Service Control Manager
    hSCM = OpenSCManager( NULL, // local machine
                          NULL, // ServicesActive database
                          SC_MANAGER_ALL_ACCESS); // full access
    if (!hSCM)
        return FALSE;

    hService = OpenService( hSCM,
                            _T(SVCNAME),
                            DELETE);
    if (hService) {
        if (DeleteService(hService)) {
            // LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_REMOVED, SVCNAME);
            bResult = TRUE;
        } else {
            // LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_NOTREMOVED, SVCNAME);
        }
        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCM);
    return bResult;
}


// Returns TRUE if it found an arg it recognised, FALSE if not
// Note: processing some arguments causes output to stdout to be generated.
BOOL
ParseStandardArgs(int argc, char* argv[])
{
    char szFilePath[_MAX_PATH]="not a file name";

    // See if we have any command line args we recognize
    if (argc <= 1)
        return FALSE;

    if ( _stricmp(argv[1], "-h") == 0 ||
         _stricmp(argv[1], "-?") == 0 ||
         _stricmp(argv[1], "/h") == 0 ||
         _stricmp(argv[1], "/?") == 0) {

        //
        GetModuleFileNameA(NULL, szFilePath, sizeof(szFilePath));
        fprintf(stderr, "usage: %s [-v | -i | -u | -h]\r\n",szFilePath);
        return TRUE;
    } else if (_stricmp(argv[1], "-v") == 0 ||
               _stricmp(argv[1], "/v") == 0 ) {

        // Spit out version info
        fprintf(stderr, "%s Version 0.1\n",_T(SVCNAME));
        fprintf(stderr, "The service is %s installed\n",
               IsInstalled() ? "currently" : "not");
        return TRUE; // say we processed the argument

    } else if (_stricmp(argv[1], "-i") == 0 ||
               _stricmp(argv[1], "/i") == 0) {

        // Request to install.
        if (IsInstalled()) {
            fprintf(stderr, "%s is already installed\n", _T(SVCNAME));
        } else {
            // Try and install the copy that's running
            if (Install()) {
                fprintf(stderr, "%s installed\n", _T(SVCNAME));
            } else {
                fprintf(stderr, "%s failed to install. Error %d\n", _T(SVCNAME), GetLastError());
            }
        }
        return TRUE; // say we processed the argument

    } else if (_stricmp(argv[1], "-u") == 0 ||
               _stricmp(argv[1], "/u") == 0) {

        // Request to uninstall.
        if (!IsInstalled()) {
            fprintf(stderr, "%s is not installed\n", _T(SVCNAME));
        } else {
            // Try and remove the copy that's installed
            if (Uninstall()) {
                // Get the executable file path
                GetModuleFileNameA(NULL, szFilePath, sizeof(szFilePath));
                fprintf(stderr, "%s removed. (You must delete the file (%s) yourself.)\n",
                       _T(SVCNAME), szFilePath);
            } else {
                fprintf(stderr, "Could not remove %s. Error %d\n", _T(SVCNAME), GetLastError());
            }
        }
        return TRUE; // say we processed the argument

    }

    // Don't recognise the args
    return FALSE;
}

DWORD __stdcall Main_thread(void* notUsed)
{
    char * argv[2] = {SVCNAME, NULL};
    begin_log();
    service_start(1, (LPTSTR*)argv);
    end_log();
    return(0);
}

int main(int argc, char ** argv) {
    SERVICE_TABLE_ENTRY dispatch_table[] = {
        { _T(SVCNAME), (LPSERVICE_MAIN_FUNCTION) service_main },
        { NULL, NULL }
    };

    if ( ParseStandardArgs(argc, argv) )
	return 0;

    if (!StartServiceCtrlDispatcher(dispatch_table)) {
        LONG status = GetLastError();
        if (status == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            DWORD tid;
            hMainThread = CreateThread(NULL, 0, Main_thread, 0, 0, &tid);

            printf("Hit <Enter> to terminate MIT CCAPI Server\n");
            getchar();
	    service_stop();
	}
    }

    if ( hMainThread ) {
	WaitForSingleObject( hMainThread, INFINITE );
	CloseHandle( hMainThread );
    }
    return 0;
}
