/*+*************************************************************************
**
** GSS test	- Windows scaffolding to test the gssapi dll
**
** Given a hostname it does the equivalent of the Unix command
** ./gss-client [-port <port>] <hostname> host@<hostname> "msg"
**
***************************************************************************/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "gss.h"

#define GSS_CONNECT_NAME            102
#define GSS_OK                      100
#define GSS_CANCEL                  101

#define GSSAPI_INI	"kerberos.ini"				// Which INI file
#define INI_HOSTS	"GSSAPI Hosts"				// INI file section
#define INI_HOST	"Host"						// INI file line label

#define MAX_HOSTS 9
char hosts[MAX_HOSTS][256];
char szHost[256];			// GSSAPI Host to connect to
char szServiceName[256];		// Service to do
char szOID[256];			// OID to use	
int port = 0;				// Which port to use

static void do_gssapi_test (char *name);
static void parse_name (char *name);
static int read_hosts(void);
static void write_hosts (void);
static void	update_hosts (char *name);
static void fill_combo (HWND hDlg);

/*+*************************************************************************
**
** WinMain
**
** Sets up the Dialog that drives our program
**
***************************************************************************/
int PASCAL
WinMain (hInstance, hPrevInstance, lpszCmdLine, nCmdShow)
HANDLE hInstance, hPrevInstance;
LPSTR lpszCmdLine;
int nCmdShow;
{
	FARPROC lpfnDlgProc;
	WSADATA wsadata;
	WORD versionrequested;
	int rc;

	versionrequested = 0x0101;		/* Version 1.1 */
	rc = WSAStartup(versionrequested, &wsadata);
	if (rc) {
	    MessageBox(NULL, "Couldn't initialize Winsock library", "",
		       MB_OK | MB_ICONSTOP);
	    return FALSE;
	}
	if (versionrequested != wsadata.wVersion) {
	    WSACleanup();
	    MessageBox(NULL, "Winsock version 1.1 not available", "",
		       MB_OK | MB_ICONSTOP);
	    return FALSE;
	}
	
	lpfnDlgProc = MakeProcInstance(OpenGssapiDlg, hInstance);
	DialogBox (hInstance, "OPENGSSAPIDLG", NULL, lpfnDlgProc);
	FreeProcInstance(lpfnDlgProc);

	WSACleanup();
	return 0;
}
/*+*************************************************************************
**
** Do_gssapi_test
**
** Does the actual call to GSS-client
**
***************************************************************************/
void
do_gssapi_test (char *name) {
	int n;										// Return value
	HCURSOR hcursor;							// For the hourglass cursor

	parse_name(name);							// Get host, service and port

	hcursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
	n = gss (szHost, szServiceName, szOID, "Test Gssapi Message", port);
	SetCursor(hcursor);

	if (n)
		MessageBox (NULL, "gss failed", "", IDOK | MB_ICONINFORMATION);
}

/*+*************************************************************************
**
** OpenGssapiDlg(HWND, unsigned, WORD, LONG)
**
** Processes messages for "Open Gssapi Connection" dialog box
**
** Messages:
** 	WM_INITDIALOG - initialize dialog box
** 	WM_COMMAND    - Input received
**
***************************************************************************/
BOOL PASCAL
OpenGssapiDlg(
	HWND hDlg,
	WORD message,
	WORD wParam,
	LONG lParam)
{
	HDC hDC;									// For getting graphic info
	DWORD Ext;									// Size of dialog
	int xExt, yExt;								// Size broken apart
	char hostname[256];							// What the user typed
	switch (message) {
	case WM_INITDIALOG:
		/*
		** First center the dialog
		*/
		hDC = GetDC(hDlg);
		Ext = GetDialogBaseUnits();
		xExt = (190 *LOWORD(Ext)) /4 ;
		yExt = (72 * HIWORD(Ext)) /8 ;
		SetWindowPos(hDlg, NULL,
			(GetSystemMetrics(SM_CXSCREEN)/2)-(xExt/2),
			(GetSystemMetrics(SM_CYSCREEN)/2)-(yExt/2),
			0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_SHOWWINDOW);
		ReleaseDC(hDlg, hDC);

		read_hosts ();							// Get the host list
		fill_combo (hDlg);						// Put into combo box

		SendMessage(hDlg, WM_SETFOCUS, NULL, NULL);
		return (TRUE);

	case WM_COMMAND:
		switch (wParam) {
		case GSS_CANCEL:						// Only way out of the dialog
		case IDCANCEL:							// From the menu
			EndDialog(hDlg, FALSE);
			break;

		case GSS_OK:
			GetDlgItemText(hDlg, GSS_CONNECT_NAME, hostname, 256);
			SendDlgItemMessage(hDlg, GSS_CONNECT_NAME, CB_SHOWDROPDOWN,
				FALSE, NULL);

			if (! *hostname) {
				MessageBox(hDlg, "You must enter a host name",
					NULL, MB_OK);
				break;
			}
			do_gssapi_test (hostname);			// Test GSSAPI
			update_hosts (hostname);			// Add it to the host list
			fill_combo (hDlg);					// Update the combo box

			//EndDialog(hDlg, TRUE);
			break;
		}
		return FALSE;
	}
	return FALSE;

}
/*+*************************************************************************
**
** Parse_name
**
** Turns NAME which the user entered into host, service and port.
** The host is up to first space, port is after that and service is made
** from host.
**
***************************************************************************/
static void
parse_name (char *name) {
	char *ptr;
	char seps[] = " ,\t";
	char tempname[256];
	
	memset( &tempname[0], '\0', 256 );
	strcpy( tempname, name);
	ptr = strtok( tempname, seps);
	if (ptr != NULL ){
	    strcpy( szHost, ptr );
	} else {
	    wsprintf( szHost, "k5test" );
	}
	if(ptr){
	    ptr = strtok( NULL, seps);
	}
	if( ptr ){
		port = atoi (ptr);
	}
	if( ptr ){
	    ptr = strtok( NULL, seps);
	}
	if( ptr ){
	    strcpy( szServiceName, ptr );
	}else{
	    wsprintf (szServiceName, "sample@%s", szHost); // Make the service name
	}
	if( ptr ){
	    ptr = strtok( NULL, seps);
	}
	if( ptr ){
	    wsprintf (szOID, "{ %s }", ptr); // Put in the OID
	    for (ptr = szOID; *ptr; ptr++)
		    if (*ptr == '.')
			    *ptr = ' ';
    } else {
	   szOID[0] = 0;
	}

}
/*+*************************************************************************
**
** Read_hosts
**
** Reads all the hosts listed in the INI file.
**
***************************************************************************/
static int
read_hosts (void) {
	int i;					/* Index */
	char buff[10];
	
	for (i = 0; MAX_HOSTS; ++i) {		/* Read this many entries */
		wsprintf (buff, INI_HOST "%d", i);
		GetPrivateProfileString(INI_HOSTS, buff, "", hosts[i], 256, GSSAPI_INI);
		if (*hosts[i] == '\0')		/* No more entries??? */
			break;
	}

	return i;
}
/*+*************************************************************************
**
** Write_hosts
**
** Writes the hosts list back to the ini file.
**
***************************************************************************/
static void
write_hosts () {
	int i;										// Index
	char buff[10];

	for (i = 0; i < MAX_HOSTS; ++i) {
		if (*hosts[i] == '\0')					// End of the list?
			break;
		wsprintf (buff, INI_HOST "%d", i);
		WritePrivateProfileString(INI_HOSTS, buff, hosts[i], GSSAPI_INI);
	}
}
/*+*************************************************************************
**
** Update_hosts
**
** Updates the host list with the new NAME the user typed.
**
***************************************************************************/
static void
update_hosts (char *name) {
	int i;										// Index

	for (i = 0; i < MAX_HOSTS-1; ++i) {			// Find it in the list
		if (! _stricmp (name, hosts[i])) 		// A match
			break;
		if (*hosts[i] == '\0')					// End of the list
			break;
	}
	memmove (hosts[1], hosts[0], i * sizeof(hosts[0])); // Move the data down
	strcpy (hosts[0], name);					// Insert this item

	write_hosts ();
}
/*+*************************************************************************
**
** Fill_combo
**
** Fills the combo box with the contents of the host list. Item 0 goes
** into the edit portion and the rest go into the libt box.
**
***************************************************************************/
static void
fill_combo (HWND hDlg) {
	int i;										// Index

	SendDlgItemMessage(hDlg, GSS_CONNECT_NAME, CB_RESETCONTENT, NULL, NULL);

	SetDlgItemText(hDlg, GSS_CONNECT_NAME, hosts[0]);
	SendDlgItemMessage(hDlg, GSS_CONNECT_NAME, CB_SETEDITSEL, NULL, NULL);

	for (i = 1; i < MAX_HOSTS; ++i) {			// Fill in the list box
		if (*hosts[i] == '\0')
			break;
		SendDlgItemMessage(hDlg, GSS_CONNECT_NAME, CB_ADDSTRING, 0,
			(LPARAM) ((LPSTR) hosts[i]));
	}
}
