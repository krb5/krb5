
/*
  Copyright (c) 1996 Microsoft Corporation

Module Name:
  ginastub.c

Abstract:
  This sample illustrates a pass-thru "stub" gina which can be used
  in some cases to simplify gina development.

  A common use for a gina is to implement code which requires the
  credentials of the user logging onto the workstation. The credentials
  may be required for syncronization with foreign account databases
  or custom authentication activities.

  In this example case, it is possible to implement a simple gina
  stub layer which simply passes control for the required functions
  to the previously installed gina, and captures the interesting
  parameters from that gina. In this scenario, the existing functionality
  in the existent gina is retained. In addition, the development time
  is reduced drastically, as existing functionality does not need to
  be duplicated.

  When dealing with credentials, take steps to maintain the security
  of the credentials. For instance, if transporting credentials over
  a network, be sure to encrypt the credentials.

Author:
  Scott Field (sfield) 18-Jul-96
*/


#include <windows.h>
#include <stdio.h>
#include <winwlx.h>
#include "ginastub.h"


/* Location of the real msgina. */

#define REALGINA_PATH TEXT("MSGINA.DLL")


/* winlogon function dispatch table */
PGWLX_DISPATCH_VERSION pWlxFuncs;


/* winlogon version */
DWORD WlxVersion;


/* Functions pointers to the real msgina which we will call. */

PGWLX_Negotiate GWlxNegotiate;
PGWLX_Initialize GWlxInitialize;
PGWLX_DisplaySASNotice GWlxDisplaySASNotice;
PGWLX_LoggedOutSAS GWlxLoggedOutSAS;
PGWLX_ActivateUserShell GWlxActivateUserShell;
PGWLX_LoggedOnSAS GWlxLoggedOnSAS;
PGWLX_DisplayLockedNotice GWlxDisplayLockedNotice;
PGWLX_WkstaLockedSAS GWlxWkstaLockedSAS;
PGWLX_IsLockOk GWlxIsLockOk;
PGWLX_IsLogoffOk GWlxIsLogoffOk;
PGWLX_Logoff GWlxLogoff;
PGWLX_Shutdown GWlxShutdown;


/* NEW for version 1.1 */

PGWLX_StartApplication GWlxStartApplication;
PGWLX_ScreenSaverNotify GWlxScreenSaverNotify;


/* hook into the real GINA. */

static BOOL
MyInitialize(void)
{
    HINSTANCE hDll;

    /* Load MSGINA.DLL. */

    if (! (hDll = LoadLibrary(REALGINA_PATH)))
	return FALSE;


    /* Get pointers to all of the WLX functions in the real MSGINA. */

    GWlxNegotiate = (PGWLX_Negotiate)
	GetProcAddress(hDll, "WlxNegotiate");
    if (! GWlxNegotiate)
	return FALSE;

    GWlxInitialize = (PGWLX_Initialize)
	GetProcAddress(hDll, "WlxInitialize");
    if (! GWlxInitialize)
	return FALSE;

    GWlxDisplaySASNotice = (PGWLX_DisplaySASNotice)
	GetProcAddress(hDll, "WlxDisplaySASNotice");
    if (! GWlxDisplaySASNotice)
	return FALSE;

    GWlxLoggedOutSAS = (PGWLX_LoggedOutSAS)
	GetProcAddress(hDll, "WlxLoggedOutSAS");
    if (! GWlxLoggedOutSAS)
	return FALSE;

    GWlxActivateUserShell = (PGWLX_ActivateUserShell)
	GetProcAddress(hDll, "WlxActivateUserShell");
    if (! GWlxActivateUserShell)
	return FALSE;

    GWlxLoggedOnSAS = (PGWLX_LoggedOnSAS)
	GetProcAddress(hDll, "WlxLoggedOnSAS");
    if (! GWlxLoggedOnSAS)
	return FALSE;

    GWlxDisplayLockedNotice = (PGWLX_DisplayLockedNotice)
	GetProcAddress(hDll, "WlxDisplayLockedNotice");
    if (! GWlxDisplayLockedNotice)
	return FALSE;

    GWlxIsLockOk = (PGWLX_IsLockOk)
	GetProcAddress(hDll, "WlxIsLockOk");
    if (! GWlxIsLockOk)
	return FALSE;

    GWlxWkstaLockedSAS = (PGWLX_WkstaLockedSAS)
	GetProcAddress(hDll, "WlxWkstaLockedSAS");
    if (! GWlxWkstaLockedSAS)
	return FALSE;

    GWlxIsLogoffOk = (PGWLX_IsLogoffOk)
	GetProcAddress(hDll, "WlxIsLogoffOk");
    if (! GWlxIsLogoffOk)
	return FALSE;

    GWlxLogoff = (PGWLX_Logoff)
	GetProcAddress(hDll, "WlxLogoff");
    if (! GWlxLogoff)
	return FALSE;

    GWlxShutdown = (PGWLX_Shutdown)
	GetProcAddress(hDll, "WlxShutdown");
    if (! GWlxShutdown)
	return FALSE;


    /* Don't check for failure because these don't exist prior to NT 4.0 */

    GWlxStartApplication = (PGWLX_StartApplication)
	GetProcAddress(hDll, "WlxStartApplication");
    GWlxScreenSaverNotify = (PGWLX_ScreenSaverNotify)
	GetProcAddress(hDll, "WlxScreenSaverNotify");


    /* Everything loaded ok. Return success. */
    return TRUE;
}

BOOL
WINAPI
WlxNegotiate(
	DWORD dwWinlogonVersion,
	DWORD *pdwDllVersion)
{
    if (! MyInitialize())
	return FALSE;

    WlxVersion = dwWinlogonVersion;
    return (* GWlxNegotiate)(dwWinlogonVersion, pdwDllVersion);
}

BOOL
WINAPI
WlxInitialize(
	LPWSTR lpWinsta,
	HANDLE hWlx,
	PVOID pvReserved,
	PVOID pWinlogonFunctions,
	PVOID *pWlxContext)
{
    pWlxFuncs = (PGWLX_DISPATCH_VERSION) pWinlogonFunctions;
    
    return (* GWlxInitialize)(
	lpWinsta,
	hWlx,
	pvReserved,
	pWinlogonFunctions,
	pWlxContext
	);
}

VOID
WINAPI
WlxDisplaySASNotice(
	PVOID pWlxContext)
{
    (* GWlxDisplaySASNotice)(pWlxContext);
}

int
WINAPI
WlxLoggedOutSAS(
	PVOID pWlxContext,
	DWORD dwSasType,
	PLUID pAuthenticationId,
	PSID pLogonSid,
	PDWORD pdwOptions,
	PHANDLE phToken,
	PWLX_MPR_NOTIFY_INFO pMprNotifyInfo,
	PVOID *pProfile)
{
    int iRet;
  
    iRet = (* GWlxLoggedOutSAS)(
	pWlxContext,
	dwSasType,
	pAuthenticationId,
	pLogonSid,
	pdwOptions,
	phToken,
	pMprNotifyInfo,
	pProfile
	);
  
    if (iRet == WLX_SAS_ACTION_LOGON) {
	/* copy pMprNotifyInfo and pLogonSid for later use */
	
	/* pMprNotifyInfo->pszUserName */
	/* pMprNotifyInfo->pszDomain */
	/* pMprNotifyInfo->pszPassword */
	/* pMprNotifyInfo->pszOldPassword */
    }
  
    return iRet;
}

BOOL
WINAPI
WlxActivateUserShell(
	PVOID pWlxContext,
	PWSTR pszDesktopName,
	PWSTR pszMprLogonScript,
	PVOID pEnvironment)
{
    return (* GWlxActivateUserShell)(
	pWlxContext,
	pszDesktopName,
	pszMprLogonScript,
	pEnvironment
	);
}

int
WINAPI
WlxLoggedOnSAS(
	PVOID pWlxContext,
	DWORD dwSasType,
	PVOID pReserved)
{
    return (* GWlxLoggedOnSAS)(pWlxContext, dwSasType, pReserved);
}

VOID
WINAPI
WlxDisplayLockedNotice(
	PVOID pWlxContext)
{
    (* GWlxDisplayLockedNotice)(pWlxContext);
}

BOOL
WINAPI
WlxIsLockOk(
	PVOID pWlxContext)
{
    return (* GWlxIsLockOk)(pWlxContext);
}

int
WINAPI
WlxWkstaLockedSAS(
	PVOID pWlxContext,
	DWORD dwSasType)
{
    return (* GWlxWkstaLockedSAS)(pWlxContext, dwSasType);
}

BOOL
WINAPI
WlxIsLogoffOk(
	PVOID pWlxContext
	)
{
    BOOL bSuccess;
  
    bSuccess = (* GWlxIsLogoffOk)(pWlxContext);
    if (bSuccess) {
	/* if it's ok to logoff, finish with the stored credentials */
	/* and scrub the buffers */
    }
  
    return bSuccess;
}

VOID
WINAPI
WlxLogoff(
	PVOID pWlxContext
	)
{
    (* GWlxLogoff)(pWlxContext);
}

VOID
WINAPI
WlxShutdown(
PVOID pWlxContext,
DWORD ShutdownType
)
{
    (* GWlxShutdown)(pWlxContext, ShutdownType);
}


/* NEW for version 1.1 */

BOOL
WINAPI
WlxScreenSaverNotify(
PVOID pWlxContext,
BOOL * pSecure
)
{
    if (GWlxScreenSaverNotify)
	return (* GWlxScreenSaverNotify)(pWlxContext, pSecure);
  
    /* if not exported, return something intelligent */
    *pSecure = TRUE;
    return TRUE;
}

BOOL
WINAPI
WlxStartApplication(
	PVOID pWlxContext,
	PWSTR pszDesktopName,
	PVOID pEnvironment,
	PWSTR pszCmdLine
	)
{
    if (GWlxStartApplication)
	return (* GWlxStartApplication)(
		pWlxContext,
		pszDesktopName,
		pEnvironment,
		pszCmdLine
		);

    /* if not exported, return something intelligent */
    return TRUE;	/* ??? */
}
