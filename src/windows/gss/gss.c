/*+*************************************************************************
**
** GSS test	- Windows scaffolding to test the gssapi dll
**
** Given a hostname it does the equivalent of the Unix command
** ./gss-client <hostname> host@<hostname> "msg"
**
***************************************************************************/

#include <windows.h>
#include <stdio.h>
#include "gss.h"

#define GSS_CONNECT_NAME            102
#define GSS_OK                      100
#define GSS_CANCEL                  101

char szConnectName[256];
char szServiceName[256];

int PASCAL 
WinMain (hInstance, hPrevInstance, lpszCmdLine, nCmdShow)
HANDLE hInstance, hPrevInstance;
LPSTR lpszCmdLine;
int nCmdShow;
{
	int n;										// Return value
	FARPROC lpfnDlgProc;

	lpfnDlgProc = MakeProcInstance(OpenGssapiDlg, hInstance);
	n = DialogBox (hInstance, "OPENGSSAPIDLG", NULL, lpfnDlgProc);
	FreeProcInstance(lpfnDlgProc);

	if (n) {
		strcpy (szServiceName, "host@");
		strcat (szServiceName, szConnectName);
		n = gss (szConnectName, szServiceName, "Test Gssapi Message", 0);
		if (n)
			MessageBox (NULL, "gss failed", "", IDOK | MB_ICONINFORMATION);
	}

	return 0;
}

/*+***************************************************************************

	FUNCTION: OpenGssapiDlg(HWND, unsigned, WORD, LONG)

	PURPOSE:  Processes messages for "Open Gssapi Connection" dialog box

	MESSAGES:

	WM_INITDIALOG - initialize dialog box
	WM_COMMAND    - Input received

****************************************************************************/

BOOL FAR PASCAL OpenGssapiDlg(
	HWND hDlg,
	WORD message,
	WORD wParam,
	LONG lParam)
{
	HDC hDC;
	int xExt, yExt;
	DWORD Ext;
//	HWND hEdit;
//	int n;
//	int iHostNum = 0;
//	char tmpName[128];
//	char tmpBuf[80];
//	char *tmpCommaLoc;
	
	switch (message) {

	case WM_INITDIALOG:
		hDC = GetDC(hDlg);
		Ext = GetDialogBaseUnits();
		xExt = (190 *LOWORD(Ext)) /4 ;
		yExt = (72 * HIWORD(Ext)) /8 ;
		SetWindowPos(hDlg, NULL,
			(GetSystemMetrics(SM_CXSCREEN)/2)-(xExt/2),
			(GetSystemMetrics(SM_CYSCREEN)/2)-(yExt/2),
			0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_SHOWWINDOW);
		ReleaseDC(hDlg, hDC);      
//		GetPrivateProfileString(INI_HOSTS, INI_HOST "0", "", tmpName, 
//			128, TELNET_INI);
//		if (tmpName[0]) {
//			tmpCommaLoc = strchr(tmpName, ',');
//			if (tmpCommaLoc)
//				*tmpCommaLoc = '\0';
//			SetDlgItemText(hDlg, GSS_CONNECT_NAME, tmpName);
//		}	
//		hEdit = GetWindow(GetDlgItem(hDlg, GSS_CONNECT_NAME), GW_CHILD);
//		while (TRUE) {
//			wsprintf(tmpBuf, INI_HOST "%d", iHostNum++);
//			GetPrivateProfileString(INI_HOSTS, tmpBuf, "", tmpName, 
//				128, TELNET_INI);
//			tmpCommaLoc = strchr(tmpName, ',');  
//			if (tmpCommaLoc)
//				*tmpCommaLoc = '\0';
//			if (tmpName[0])
//				SendDlgItemMessage(hDlg, GSS_CONNECT_NAME, CB_ADDSTRING, 0, 
//					(LPARAM) ((LPSTR) tmpName));
//			else
//				break;
//		}
//		SendMessage(hEdit, WM_USER+1, NULL, NULL);
		SendMessage(hDlg, WM_SETFOCUS, NULL, NULL);
		return (TRUE);

	case WM_COMMAND:
		switch (wParam) {
		case GSS_CANCEL:
			EndDialog(hDlg, FALSE);
			break;
				
		case GSS_OK:
			GetDlgItemText(hDlg, GSS_CONNECT_NAME, szConnectName, 256);
			if (! *szConnectName) {
				MessageBox(hDlg, "You must enter a host name",
					NULL, MB_OK);
				break;
			}
			EndDialog(hDlg, TRUE);
			break;
		}                
		return (FALSE);                    
	}
	return(FALSE);

} /* OpenGssapiDlg */
