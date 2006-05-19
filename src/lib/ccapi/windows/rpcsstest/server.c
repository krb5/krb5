#include<windows.h>
#include<stdio.h>
#include<process.h>
#include<tchar.h>
#include<rpc.h>
#include"cstest.h"
#include<strsafe.h>

#define SVCNAME "CCAPICSTest"

SERVICE_STATUS_HANDLE h_service_status = NULL;
SERVICE_STATUS service_status;
FILE * logfile = NULL;

void begin_log(void) {
    char temppath[512];

    temppath[0] = L'\0';

    GetTempPathA(sizeof(temppath), temppath);
    StringCbCatA(temppath, sizeof(temppath), "csserverconn.log");
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
        return;
    }

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    status = RpcServerRegisterIf(ccapi_cstest_v1_0_s_ifspec,
                                 0, 0);

    if (status != RPC_S_OK)
        return;

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    status = RpcServerInqBindings(&bv);

    if (status != RPC_S_OK)
        return;

    status = RpcEpRegister(ccapi_cstest_v1_0_s_ifspec,
                           bv, 0, 0);

    if (status != RPC_S_OK)
        return;

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    status = RpcServerRegisterAuthInfo(NULL,
                                       RPC_C_AUTHN_WINNT,
                                       0, 0);

    if (status != RPC_S_OK)
        return;

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    status = RpcServerListen(1,
                             RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                             TRUE);

    if (status != RPC_S_OK)
        return;

    report_status(SERVICE_RUNNING, NO_ERROR, 0);

    begin_log();

    status = RpcMgmtWaitServerListen();

    end_log();

    RpcEpUnregister(ccapi_cstest_v1_0_s_ifspec, bv, 0);

    RpcBindingVectorFree(&bv);
}

void service_stop(void) {
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

long EchoString(
    /* [in] */ handle_t h,
    /* [string][in] */ unsigned char *in_str,
    /* [in] */ long cb_buffer,
    /* [out] */ long *cb_len,
    /* [size_is][string][out] */ unsigned char buffer[  ]) {

    size_t cb;
    long rv = 0;
    client_info_t client_info;

    rv = check_auth(h, &client_info);

    if (rv == 0 && logfile) {
        fprintf(logfile,
                "Client name [%s], LUID [%x:%x]\n",
                client_info.client_name,
                (client_info.luid.HighPart),
                (client_info.luid.LowPart));
        fflush(logfile);
    }

    if (!in_str) {
        rv = 1;
        if (cb_len)
            *cb_len = 0;
        if (buffer)
            buffer[0] = '\0';
    } else {
        if (FAILED(StringCbLengthA(in_str, 256, &cb))) {
            rv = 2;
            goto _exit_f;
        }

        cb += sizeof(char);

        if (((long)cb) > cb_buffer) {
            rv = 3;
            goto _exit_f;
        }

        *cb_len = cb;

        if (buffer)
            StringCbCopyA(buffer, cb_buffer, in_str);

        rv = 0;
    }

 _exit_f:

    return rv;
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
                            SVCNAME,
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
    char szFilePath[_MAX_PATH];

    // See if we have any command line args we recognize
    if (argc <= 1)
        return FALSE;

    if ( _stricmp(argv[1], "-h") == 0 ||
         _stricmp(argv[1], "-?") == 0 ||
         _stricmp(argv[1], "/h") == 0 ||
         _stricmp(argv[1], "/?") == 0) {

        //
        GetModuleFileName(NULL, szFilePath, sizeof(szFilePath));
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
                GetModuleFileName(NULL, szFilePath, sizeof(szFilePath));
                fprintf(stderr, "%s removed. (You must delete the file (%s) yourself.)\n"
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

int main(int argc, char ** argv) {

    SERVICE_TABLE_ENTRY dispatch_table[] = {
        { _T(SVCNAME), (LPSERVICE_MAIN_FUNCTION) service_main },
        { NULL, NULL }
    };

    if ( ParseStandardArgs(argc, argv) )
	return 0;

    if (!StartServiceCtrlDispatcher(dispatch_table)) {
        fprintf(stderr, "Can't start service control dispatcher\n");
    }

    return 0;
}
