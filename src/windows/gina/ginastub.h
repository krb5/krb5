/* WinLogin 1.0 */
typedef BOOL	(CALLBACK * PGWLX_Negotiate)
	(DWORD, DWORD *);
typedef BOOL	(CALLBACK * PGWLX_Initialize)
	(LPWSTR, HANDLE, PVOID, PVOID, PVOID);
typedef VOID	(CALLBACK * PGWLX_DisplaySASNotice)
	(PVOID);
typedef int	(CALLBACK * PGWLX_LoggedOutSAS)
	(PVOID, DWORD, PLUID, PSID, PDWORD, PHANDLE,
	 PWLX_MPR_NOTIFY_INFO, PVOID *);
typedef BOOL	(CALLBACK * PGWLX_ActivateUserShell)
	(PVOID, PWSTR, PWSTR, PVOID);
typedef int	(CALLBACK * PGWLX_LoggedOnSAS)
	(PVOID, DWORD, PVOID);
typedef VOID	(CALLBACK * PGWLX_DisplayLockedNotice)
	(PVOID);
typedef int	(CALLBACK * PGWLX_WkstaLockedSAS)
	(PVOID, DWORD);
typedef BOOL	(CALLBACK * PGWLX_IsLockOk)
	(PVOID);
typedef BOOL	(CALLBACK * PGWLX_IsLogoffOk)
	(PVOID);
typedef VOID	(CALLBACK * PGWLX_Logoff)
	(PVOID);
typedef VOID	(CALLBACK * PGWLX_Shutdown)
	(PVOID, DWORD);

/* WinLogin 1.1 */
typedef BOOL	(CALLBACK * PGWLX_StartApplication)
	(PVOID, PWSTR, PVOID, PWSTR);
typedef BOOL	(CALLBACK * PGWLX_ScreenSaverNotify)
	(PVOID, BOOL *);


#if defined(WLX_VERSION_1_1)
typedef PWLX_DISPATCH_VERSION_1_1 PGWLX_DISPATCH_VERSION;
#else
typedef PWLX_DISPATCH_VERSION_1_0 PGWLX_DISPATCH_VERSION;
#endif
