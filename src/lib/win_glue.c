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

#ifdef KRB4
#include <kerberosIV/krb.h>
#endif
#define NEED_SOCKETS
#include "k5-int.h"

#ifndef NEED_WINSOCK
#if defined(KRB4) || defined(KRB5) || defined(GSSAPI)
#define NEED_WINSOCK 1
#endif
#endif

#ifdef KRB4
#include <kerberosIV/krb_err.h>
#endif
#ifdef KRB5
#include "krb5_err.h"
#include "kv5m_err.h"
#include "asn1_err.h"
#include "kdb5_err.h"
#include "profile.h"
#include "adm_err.h"
#endif
#ifdef GSSAPI
#include "gssapi/generic/gssapi_err_generic.h"
#include "gssapi/krb5/gssapi_err_krb5.h"
#endif


/*
 * #defines for MIT-specific time-based timebombs and/or version
 * server for the Kerberos DLL.
 */

#ifdef SAP_TIMEBOMB
#define TIMEBOMB 865141200	/* 1-Jun-97 */
#define TIMEBOMB_PRODUCT "SAPGUI"
#define TIMEBOMB_WARN  15
#define TIMEBOMB_INFO "  Please see the web page at:\nhttp://web.mit.edu/reeng/www/saphelp for more information"
#define TIMEBOMB_ERROR KRB5_APPL_EXPIRED
#endif

#ifdef KRB_TIMEBOMB
#define TIMEBOMB 865141200	/* 1-Jun-97 */
#define TIMEBOMB_PRODUCT "Kerberos V5"
#define TIMEBOMB_WARN 15
#define TIMEBOMB_INFO "  Please see the web page at:\nhttp://web.mit.edu/reeng/www/saphelp for more information"
#define TIMEBOMB_ERROR KRB5_LIB_EXPIRED
#endif

/*
 * #defines for using MIT's version server DLL
 */
#ifdef SAP_VERSERV
#define VERSERV
#define APP_TITLE "KRB5-SAP"
#define APP_VER "3.0c"
#define APP_INI "krb5sap.ini"
#define VERSERV_ERROR 	KRB5_APPL_EXPIRED
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
static krb5_error_code do_timebomb()
{
	char buf[1024];
	long timeleft;
	static first_time = 1;

	timeleft = TIMEBOMB - time(0);
	if (timeleft <= 0) {
		if (first_time) {
			sprintf(buf, "Your version of %s has expired.\n",
				TIMEBOMB_PRODUCT);
			strcat(buf, "Please upgrade it.");
#ifdef TIMEBOMB_INFO
			strcat(buf, TIMEBOMB_INFO);
#endif
			MessageBox(NULL, buf, "", MB_OK);
			first_time = 0;
		}
		return TIMEBOMB_ERROR;
	}
	timeleft = timeleft / ((long) 60*60*24);
	if (timeleft < TIMEBOMB_WARN) {
		if (first_time) {
			sprintf(buf, "Your version of %s will expire in %ld days.\n",
				TIMEBOMB_PRODUCT, timeleft);
			strcat(buf, "Please upgrade it soon.");
#ifdef TIMEBOMB_INFO
			strcat(buf, TIMEBOMB_INFO);
#endif
			MessageBox(NULL, buf, "", MB_OK);
			first_time = 0;
		}
	}
	return 0;
}
#endif

/*
 * This was originally called from LibMain; unfortunately, Windows 3.1
 * doesn't allow you to make messaging calls from LibMain.  So, we now
 * do the timebomb/version server stuff from krb5_init_context().
 */
krb5_error_code krb5_vercheck()
{
#ifdef TIMEBOMB
	krb5_error_code retval = do_timebomb();
	if (retval)
		return retval;
#endif
#ifdef VERSERV
	if (CallVersionServer(APP_TITLE, APP_VER, APP_INI, NULL))
		return VERSERV_ERROR;
#endif
	return 0;
}


static HINSTANCE hlibinstance;

HINSTANCE get_lib_instance()
{
    return hlibinstance;
}

#define DLL_STARTUP 0
#define DLL_SHUTDOWN 1

static int
control(int mode)
{
    void ((KRB5_CALLCONV *et_func)(struct error_table FAR *));
#ifdef NEED_WINSOCK
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
#endif

    switch(mode) {
    case DLL_STARTUP:
	et_func = add_error_table;

#ifdef NEED_WINSOCK
	wVersionRequested = 0x0101;		/* We need version 1.1 */
	if ((err = WSAStartup (wVersionRequested, &wsaData)))
	    return err;
	if (wVersionRequested != wsaData.wVersion) {
	    /* DLL couldn't support our version of the spec */
	    WSACleanup ();
	    return -104;			/* FIXME -- better error? */
	}
#endif

	break;

    case DLL_SHUTDOWN:
	et_func = remove_error_table;
#ifdef NEED_WINSOCK
	WSACleanup ();
#endif
	break;

    default:
	return -1;
    }

#ifdef KRB4
    (*et_func)(&et_krb_error_table);
#endif
#ifdef KRB5
    (*et_func)(&et_krb5_error_table);
    (*et_func)(&et_kv5m_error_table);
    (*et_func)(&et_kdb5_error_table);
    (*et_func)(&et_asn1_error_table);
    (*et_func)(&et_prof_error_table);
    (*et_func)(&et_kadm_error_table);
#endif
#ifdef GSSAPI
    (*et_func)(&et_k5g_error_table);
    (*et_func)(&et_ggss_error_table);
#endif

    return 0;
}

#ifdef _WIN32

BOOL WINAPI DllMain (HANDLE hModule, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
	    hlibinstance = (HINSTANCE) hModule;
	    if (control(DLL_STARTUP))
		return FALSE;
	    break;

        case DLL_THREAD_ATTACH:
	    break;

        case DLL_THREAD_DETACH:
	    break;

        case DLL_PROCESS_DETACH:
	    if (control(DLL_SHUTDOWN))
		return FALSE;
	    break;

        default:
	    return FALSE;
    }
 
    return TRUE;   // successful DLL_PROCESS_ATTACH
}

#else

BOOL CALLBACK
LibMain (hInst, wDataSeg, cbHeap, CmdLine)
HINSTANCE hInst;
WORD wDataSeg;
WORD cbHeap;
LPSTR CmdLine;
{
    hlibinstance = hInst;
    if (control(DLL_STARTUP))
	return 0;
    else 
	return 1;
}

int CALLBACK __export
WEP(nParam)
	int nParam;
{
    if (control(DLL_SHUTDOWN))
	return 0;
    else
	return 1;
}

#endif
