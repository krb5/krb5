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

/*
 * #defines for MIT-specific time-based timebombs and/or version
 * server for the Kerberos DLL.
 */
#ifdef SAP_TIMEBOMB
#define TIMEBOMB 853304400      /* 15-Jan-97 */
#define TIMEBOMB_PRODUCT "SAPGUI"
#define TIMEBOMB_WARN  15
#endif

#ifdef KRB_TIMEBOMB
#define TIMEBOMB 853304400      /* 15-Jan-97 */
#define TIMEBOMB_PRODUCT "Kerberos V5"
#define TIMEBOMB_WARN 15
#endif

/*
 * #defines for using MIT's version server DLL
 */
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
	char FAR *code_cover;
{
	VS_Request vrequest;
	VS_Status  vstatus;

	SetCursor(LoadCursor(NULL, IDC_WAIT));

	vrequest = VSFormRequest(app_title, app_version, app_ini,
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

#ifdef TIMEBOMB
static void do_timebomb()
{
	char buf[1024];
	long timeleft;

	timeleft = TIMEBOMB - time(0);
	if (timeleft <= 0) {
		sprintf(buf, "Your version of %s has expired.\n",
			TIMEBOMB_PRODUCT);
		strcat(buf, "Please upgrade it.");
#ifdef TIMEBOMB_INFO
		strcat(buf, TIMEBOMB_INFO);
#endif
		MessageBox(NULL, buf, "", MB_OK);
#ifdef SAP_TIMEBOMB
		/* 
		 * The SAP R/3 application doesn't listen to a polite
		 * request to quit, so we hit it over the head with a
		 * hammer.  Unfortunately, this leaves dangling system
		 * resources that don't get freed, so the user will
		 * have to reboot (or at least restart windows).
		 */
		FatalAppExit(0, "Note: you should reboot now.");
		return;
#else
		PostQuitMessage(0);
#endif
	}
	timeleft = timeleft / ((long) 60*60*24);
	if (timeleft < TIMEBOMB_WARN) {
		sprintf(buf, "Your version of %s will expire in %ld days.\n",
			TIMEBOMB_PRODUCT, timeleft);
		strcat(buf, "Please upgrade it soon.");
#ifdef TIMEBOMB_INFO
		strcat(buf, TIMEBOMB_INFO);
#endif
		MessageBox(NULL, buf, "", MB_OK);
	}
}
#endif

/*
 * This was originally called from LibMain; unfortunately, Windows 3.1
 * doesn't allow you to make messaging calls from LibMain.  So, we now
 * do the timebomb/version server stuff from krb5_init_context().
 */
void krb5_win_do_init()
{
#ifdef TIMEBOMB
	do_timebomb();
#endif
#ifdef VERSERV
   if (CallVersionServer(APP_TITLE, APP_VER, APP_INI, NULL))
	   PostQuitMessage(0);
#endif

}

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
