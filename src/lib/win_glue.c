/* 
 * WinSock support.
 *
 * Do the WinSock initialization call, keeping all the hair here.
 *
 * This routine is called by SOCKET_INITIALIZE in include/c-windows.h.
 * The code is pretty much copied from winsock.txt from winsock-1.1,
 * available from:
 * ftp://sunsite.unc.edu/pub/micro/pc-stuff/ms-windows/winsock/winsock-1.1
 *
 * Note: WSAStartup and WSACleanup is called here (and only here).
 * This assumes that under Windows, we only use this library via the
 * DLL.  Note that calls to WSAStartup and WSACleanup must be in
 * matched pairs.  If there is a missing WSACleanup call when a
 * program exits, under Lan Workplace, the name resolver will stop
 * working. 
 */

/* We can't include winsock.h directly because of /Za (stdc) options */
#define NEED_SOCKETS
#include "k5-int.h"

#ifdef SAP_VERSERV
#define VERSERV
#define APP_TITLE "KRB5-SAP"
#define APP_VER "3.0c"
#define APP_INI "krb5sap.ini"
#endif

#ifdef VERSERV
#define WINDOWS
#include <vs.h>
#include <v.h>

/*
 * Use the version server to give us some control on distribution and usage
 * We're going to test track as well
 */
static int CallVersionServer(app_title, app_version, app_ini, code_cover)
	char FAR *app_title;
	char FAR *app_version;
	char FAR *app_ini;
	char FAR *code_cover
{
	VS_Request vrequest;
	VS_Status  vstatus;

	SetCursor(LoadCursor(NULL, IDC_WAIT));

	vrequest = VSFormRequest(app_title, app_ver, app_ini,
				 code_cover, NULL, V_CHECK_AND_LOG);

	SetCursor(LoadCursor(NULL, IDC_ARROW));
	/*
	 * If the user presses cancel when registering the test
	 * tracker, we'll let them continue.
	 */
	if (ReqStatus(vrequest) == V_E_CANCEL) {
		VSDestroyRequest(vrequest);
		return 0;
	}
	vstatus = VSProcessRequest(vrequest);
	/*
	 * Only complain periodically, if the test tracker isn't
	 * working... 
	 */
	if (v_complain(vstatus, app_ini)) {
		WinVSReportRequest(vrequest, NULL, 
				   "Version Server Status Report");
	}                 					  
	if (vstatus == V_REQUIRED) {
		SetCursor(LoadCursor(NULL, IDC_WAIT));
		VSDestroyRequest(vrequest);
		return( -1 );
	}
	VSDestroyRequest(vrequest);
	return (0);
}   

#endif

int
win_socket_initialize()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = 0x0101;                 /* We need version 1.1 */

    err = WSAStartup (wVersionRequested, &wsaData);
    if (err != 0)
        return err;                             /* Library can't initialize */

    if (wVersionRequested != wsaData.wVersion) {
	/* DLL couldn't support our version of the spec */
        WSACleanup ();
        return -104;                            /* FIXME -- better error? */
    }

    return 0;
}

BOOL CALLBACK
LibMain (hInst, wDataSeg, cbHeap, CmdLine)
HINSTANCE hInst;
WORD wDataSeg;
WORD cbHeap;
LPSTR CmdLine;
{
#ifdef SAP_VERSERV
   if (CallVersionServer(APP_TITLE, APP_VER, APP_INI, NULL))
	   PostQuitMessage(0);
#endif
	
    win_socket_initialize ();
    return 1;
}

int CALLBACK __export
WEP(nParam)
	int nParam;
{
    WSACleanup();
    return 1;
}
