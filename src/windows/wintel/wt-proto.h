/* wt-proto.h */
	int PASCAL WinMain(
		HANDLE,
		HANDLE,
		LPSTR,
		int);

	BOOL InitApplication(
		HANDLE);

	BOOL InitInstance(
		HANDLE,
		int);

	long PASCAL MainWndProc(
		HWND,
		UINT,
		WPARAM,
		LPARAM);

	BOOL PASCAL About(
		HWND,
		WORD,
		WORD,
		LONG);

	BOOL PASCAL OpenTelnetDlg(
		HWND,
		WORD,
		WORD,
		LONG);

	int TelnetSend(
		kstream,
		char *,
		int,
		int);

	BOOL PASCAL ConfigSessionDlg(
		HWND,
		WORD,
		WORD,
		LONG);

	int OpenTelnetConnection(void);

	int NEAR DoDialog(char *szDialog,
		FARPROC lpfnDlgProc);

	BOOL parse_cmdline(
		char *cmdline);

	CONNECTION *GetNewConnection(void);

	void start_negotiation(
		kstream ks);

	/* somewhere... */
	struct machinfo *PASCAL Shostlook(
		char *hname);
