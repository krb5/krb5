/*
 * Copyright (C) 2003, 2004 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */
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
#include <commctrl.h>
#include "gss.h"
#include <krb5.h>
#ifdef USE_LEASH
#include <cacheapi.h>
#endif

#include "resource.h"

#define GSSAPI_INI	"gsstest.ini"				// Which INI file
#define INI_HOSTS	"GSSAPI Hosts"				// INI file section
#define INI_HOST	"Host"						// INI file line label
#define INI_SVCS	"GSSAPI Services"			// INI file section
#define INI_SVC	    "Service"					// INI file line label
#define INI_MSGS	"GSSAPI Messages"			// INI file section
#define INI_MSG	    "Message"					// INI file line label
#define INI_MECHS	"GSSAPI Mechanisms"			// INI file section
#define INI_MECH	"Mech"  					// INI file line label
#define INI_LAST    "GSSAPI Most Recent" 
#define INI_LAST_HOST "Host"
#define INI_LAST_PORT "Port"
#define INI_LAST_SVC  "Service"
#define INI_LAST_MECH "Mechanism"
#define INI_LAST_MSG  "Message"
#define INI_LAST_DELEGATE  "Delegation"
#define INI_LAST_SEQUENCE  "Sequence"
#define INI_LAST_MUTUAL    "Mutual"
#define INI_LAST_REPLAY    "Replay"
#define INI_LAST_VERBOSE   "Verbose"
#define INI_LAST_CCOUNT    "Call Count"
#define INI_LAST_MCOUNT    "Message Count"
#define INI_LAST_VER1      "Version One"
#define INI_LAST_NOAUTH    "No Auth"
#define INI_LAST_NOWRAP    "No Wrap"
#define INI_LAST_NOCRYPT   "No Encrypt"
#define INI_LAST_NOMIC     "No Mic"
#define INI_LAST_CCACHE    "CCache"

#define MAX_SAVED 9
char hosts[MAX_SAVED][256];
char svcs[MAX_SAVED][256];
char msgs[MAX_SAVED][256];
char mechs[MAX_SAVED][256];
char szHost[256];			// GSSAPI Host to connect to
char szService[256];		// Service to do
char szMessage[256];        // Message to send
char szMech[256];			// OID to use
char szCCache[256];         // CCache to use
int port = 0;				// Which port to use
int delegate = 0;           // Delegate?
int replay = 1;             // Replay?
int mutual = 1;             // Mutual?
int sequence = 0;           // Sequence?
int verbose = 1;            // Verbose?
int ccount = 1;             // Call Count
int mcount = 1;             // Message Count
int gssv1 = 0;              // Version 1?
int noauth = 0;             // No Auth?
int nowrap = 0;             // No Wrap?
int nocrypt = 0;            // No Crypt?
int nomic = 0;              // No Mic?

HWND hDialog = 0;

static void do_gssapi_test (void);
static void parse_name (char *name);
static void read_saved(void);
static void write_saved (void);
static void	update_saved (void);
static void fill_combo (HWND hDlg);

/*+*************************************************************************
**
** WinMain
**
** Sets up the Dialog that drives our program
**
***************************************************************************/
int __stdcall
WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdLine, int nCmdShow)
{
	WSADATA wsadata;
	WORD versionrequested;
	int rc;

	InitCommonControls();

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
	
	rc = DialogBoxParam (hInstance, "GSSAPIDLG", HWND_DESKTOP, OpenGssapiDlg, 0L);
	rc = GetLastError();

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
do_gssapi_test (void) {
	int n;										// Return value
	HCURSOR hcursor;							// For the hourglass cursor

	hcursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
	n = gss (szHost, szService, szMech, szMessage[0] ? szMessage : "Test Gssapi Message", port,
             verbose, delegate, mutual, replay, sequence, 
             gssv1, !noauth, !nowrap, !nocrypt, !nomic, ccount, mcount,
             szCCache);
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
INT_PTR CALLBACK
OpenGssapiDlg(
	HWND hDlg,
	UINT message,
	WPARAM wParam,
	LPARAM lParam)
{
	HDC hDC;									// For getting graphic info
	DWORD Ext;									// Size of dialog
	int xExt, yExt;								// Size broken apart
    char buff[64];

	switch (message) {
	case WM_INITDIALOG:
        hDialog = hDlg;
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

        SendDlgItemMessage(hDlg, GSS_HOST_NAME, CB_LIMITTEXT, sizeof(szHost), 0);
		read_saved ();							// Get the host list
		fill_combo (hDlg);						// Put into combo box

		SendMessage(hDlg, WM_SETFOCUS, 0, 0);
		return (TRUE);

    case WM_HSCROLL:
		switch (LOWORD(wParam)) {
		case TB_THUMBTRACK:
		case TB_THUMBPOSITION: 
			{
				long pos = HIWORD(wParam); // the position of the slider
				int  ctrlID = GetDlgCtrlID((HWND)lParam);

				if (ctrlID == GSS_CALL_COUNT) {
                    sprintf(buff,"Call Count: %d",pos);
					SetWindowText(GetDlgItem(hDialog, IDC_STATIC_CCOUNT),buff);
				}
				if (ctrlID == GSS_MESSAGE_COUNT) {
                    sprintf(buff,"Message Count: %d",pos);
					SetWindowText(GetDlgItem(hDialog, IDC_STATIC_MSG_COUNT),buff);
				}
			}
			break;
        case TB_BOTTOM:
        case TB_TOP:
        case TB_ENDTRACK:
        case TB_LINEDOWN:
        case TB_LINEUP:
        case TB_PAGEDOWN:
        case TB_PAGEUP:
		default:
			{
				int  ctrlID = GetDlgCtrlID((HWND)lParam);
				long pos = SendMessage(GetDlgItem(hDialog,ctrlID), TBM_GETPOS, 0, 0); // the position of the slider

				if (ctrlID == GSS_CALL_COUNT) {
                    sprintf(buff,"Call Count: %d",pos);
					SetWindowText(GetDlgItem(hDialog, IDC_STATIC_CCOUNT),buff);
				}
				if (ctrlID == GSS_MESSAGE_COUNT) {
                    sprintf(buff,"Message Count: %d",pos);
					SetWindowText(GetDlgItem(hDialog, IDC_STATIC_MSG_COUNT),buff);
				}
			}
		}
        break;


	case WM_COMMAND:
		switch (wParam) {
		case GSS_CANCEL:						// Only way out of the dialog
		case IDCANCEL:							// From the menu
			EndDialog(hDlg, FALSE);
			break;

		case GSS_OK:
			GetDlgItemText(hDlg, GSS_HOST_NAME, szHost, 256);
			SendDlgItemMessage(hDlg, GSS_HOST_NAME, CB_SHOWDROPDOWN, FALSE, 0);

			if (!*szHost) {
				MessageBox(hDlg, "You must enter a host name", NULL, MB_OK);
				break;
			}

			GetDlgItemText(hDlg, GSS_SERVICE_NAME, szService, 256);
			SendDlgItemMessage(hDlg, GSS_SERVICE_NAME, CB_SHOWDROPDOWN, FALSE, 0);

			if (!*szService) {
				MessageBox(hDlg, "You must enter a service name", NULL, MB_OK);
				break;
			}

            GetDlgItemText(hDlg, GSS_MECHANISM, szMech, 256);
            GetDlgItemText(hDlg, GSS_CCACHE_NAME, szCCache, 256);
            GetDlgItemText(hDlg, GSS_MESSAGE, szMessage, 256);
            GetDlgItemText(hDlg, GSS_PORT, buff, 32);
            if (!*buff) {
				MessageBox(hDlg, "You must enter a valid port number", NULL, MB_OK);
				break;
            }
            port = atoi(buff);
            if (port == 0 || port == -1)
                port = 4444;

            ccount = SendDlgItemMessage( hDlg, GSS_CALL_COUNT, TBM_GETPOS, 0, 0);
            mcount = SendDlgItemMessage( hDlg, GSS_MESSAGE_COUNT, TBM_GETPOS, 0, 0);

            verbose = IsDlgButtonChecked(hDlg, GSS_VERBOSE);
            delegate = IsDlgButtonChecked(hDlg, GSS_DELEGATION);
            mutual = IsDlgButtonChecked(hDlg, GSS_MUTUAL);
            replay = IsDlgButtonChecked(hDlg, GSS_REPLAY);
            sequence = IsDlgButtonChecked(hDlg, GSS_SEQUENCE);
            gssv1 = IsDlgButtonChecked(hDlg, GSS_VERSION_ONE);

            noauth = IsDlgButtonChecked(hDlg, GSS_NO_AUTH);
            if ( noauth ) {
                nowrap = nocrypt = nomic = 0;
            } else {
                nowrap = IsDlgButtonChecked(hDlg, GSS_NO_WRAP);
                nocrypt = IsDlgButtonChecked(hDlg, GSS_NO_ENCRYPT);
                nomic = IsDlgButtonChecked(hDlg, GSS_NO_MIC);
            }

			update_saved ();        			// Add it to the host list
			fill_combo (hDlg);					// Update the combo box
            SetDlgItemText(hDlg, GSS_OUTPUT, "");
            do_gssapi_test ();      			// Test GSSAPI

			//EndDialog(hDlg, TRUE);
			break;
		
        case GSS_NO_AUTH:
            if ( IsDlgButtonChecked(hDlg, GSS_NO_AUTH) ) {
                // disable the other no_xxx options
                EnableWindow(GetDlgItem(hDlg, GSS_NO_WRAP), FALSE);
                EnableWindow(GetDlgItem(hDlg, GSS_NO_ENCRYPT), FALSE);
                EnableWindow(GetDlgItem(hDlg, GSS_NO_MIC), FALSE);
            } else {
                // enable the other no_xxx options
                EnableWindow(GetDlgItem(hDlg, GSS_NO_WRAP), TRUE);
                EnableWindow(GetDlgItem(hDlg, GSS_NO_ENCRYPT), TRUE);
                EnableWindow(GetDlgItem(hDlg, GSS_NO_MIC), TRUE);
            }
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
	    strcpy( szService, ptr );
	}else{
	    wsprintf (szService, "sample@%s", szHost); // Make the service name
	}
	if( ptr ){
	    ptr = strtok( NULL, seps);
	}
	if( ptr ){
	    wsprintf (szMech, "{ %s }", ptr); // Put in the OID
	    for (ptr = szMech; *ptr; ptr++)
		    if (*ptr == '.')
			    *ptr = ' ';
    } else {
	   szMech[0] = 0;
	}

}
/*+*************************************************************************
**
** read_saved
**
** Reads all the hosts listed in the INI file.
**
***************************************************************************/
static void
read_saved (void) {
	int i;					/* Index */
	char buff[32];
	
	for (i = 0; MAX_SAVED; ++i) {		/* Read this many entries */
		wsprintf (buff, INI_HOST "%d", i);
		GetPrivateProfileString(INI_HOSTS, buff, "", hosts[i], 256, GSSAPI_INI);
		if (*hosts[i] == '\0')		/* No more entries??? */
			break;
	}
	for (i = 0; MAX_SAVED; ++i) {		/* Read this many entries */
		wsprintf (buff, INI_SVC "%d", i);
		GetPrivateProfileString(INI_SVCS, buff, "", svcs[i], 256, GSSAPI_INI);
		if (*svcs[i] == '\0')		/* No more entries??? */
			break;
	}
	for (i = 0; MAX_SAVED; ++i) {		/* Read this many entries */
		wsprintf (buff, INI_MSG "%d", i);
		GetPrivateProfileString(INI_MSGS, buff, "", msgs[i], 256, GSSAPI_INI);
		if (*msgs[i] == '\0')		/* No more entries??? */
			break;
	}
	for (i = 0; MAX_SAVED; ++i) {		/* Read this many entries */
		wsprintf (buff, INI_MECH "%d", i);
		GetPrivateProfileString(INI_MECHS, buff, "", mechs[i], 256, GSSAPI_INI);
		if (*mechs[i] == '\0')		/* No more entries??? */
			break;
	}
    GetPrivateProfileString(INI_LAST, INI_LAST_HOST, "", szHost, 256, GSSAPI_INI);
    GetPrivateProfileString(INI_LAST, INI_LAST_PORT, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        port = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_SVC, "", szService, 256, GSSAPI_INI);
    GetPrivateProfileString(INI_LAST, INI_LAST_MSG, "", szMessage, 256, GSSAPI_INI);
    GetPrivateProfileString(INI_LAST, INI_LAST_MECH, "", szMech, 256, GSSAPI_INI);
    GetPrivateProfileString(INI_LAST, INI_LAST_CCACHE, "", szCCache, 256, GSSAPI_INI);
    GetPrivateProfileString(INI_LAST, INI_LAST_DELEGATE, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        delegate = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_MUTUAL, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        mutual = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_REPLAY, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        replay = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_SEQUENCE, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        sequence = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_VERBOSE, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        verbose = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_CCOUNT, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        ccount = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_MCOUNT, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        mcount = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_VER1, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        gssv1 = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_NOAUTH, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        noauth = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_NOWRAP, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        nowrap = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_NOCRYPT, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        nocrypt = atoi(buff);
    GetPrivateProfileString(INI_LAST, INI_LAST_NOMIC, "", buff, 32, GSSAPI_INI);
    if ( buff[0] )  
        nomic = atoi(buff);
}

/*+*************************************************************************
**
** write_saved
**
** Writes the hosts list back to the ini file.
**
***************************************************************************/
static void
write_saved () {
	int i;										// Index
	char buff[32];

	for (i = 0; i < MAX_SAVED; ++i) {
		if (*hosts[i] == '\0')					// End of the list?
			break;
		wsprintf (buff, INI_HOST "%d", i);
		WritePrivateProfileString(INI_HOSTS, buff, hosts[i], GSSAPI_INI);
	}
	for (i = 0; i < MAX_SAVED; ++i) {
		if (*svcs[i] == '\0')					// End of the list?
			break;
		wsprintf (buff, INI_SVC "%d", i);
		WritePrivateProfileString(INI_SVCS, buff, svcs[i], GSSAPI_INI);
	}
	for (i = 0; i < MAX_SAVED; ++i) {
		if (*msgs[i] == '\0')					// End of the list?
			break;
		wsprintf (buff, INI_MSG "%d", i);
		WritePrivateProfileString(INI_MSGS, buff, msgs[i], GSSAPI_INI);
	}
	for (i = 0; i < MAX_SAVED; ++i) {
		if (*mechs[i] == '\0')					// End of the list?
			break;
		wsprintf (buff, INI_MECH "%d", i);
		WritePrivateProfileString(INI_MECHS, buff, mechs[i], GSSAPI_INI);
	}
    WritePrivateProfileString(INI_LAST, INI_LAST_HOST, szHost, GSSAPI_INI);
    wsprintf(buff, "%d", port);
    WritePrivateProfileString(INI_LAST, INI_LAST_PORT, buff, GSSAPI_INI);
    WritePrivateProfileString(INI_LAST, INI_LAST_SVC, szService, GSSAPI_INI);
    WritePrivateProfileString(INI_LAST, INI_LAST_MECH, szMech, GSSAPI_INI);
    WritePrivateProfileString(INI_LAST, INI_LAST_CCACHE, szCCache, GSSAPI_INI);
    WritePrivateProfileString(INI_LAST, INI_LAST_MSG, szMessage, GSSAPI_INI);
    wsprintf(buff, "%d", delegate);
    WritePrivateProfileString(INI_LAST, INI_LAST_DELEGATE, buff, GSSAPI_INI);
    wsprintf(buff, "%d", mutual);
    WritePrivateProfileString(INI_LAST, INI_LAST_MUTUAL, buff, GSSAPI_INI);
    wsprintf(buff, "%d", replay);
    WritePrivateProfileString(INI_LAST, INI_LAST_REPLAY, buff, GSSAPI_INI);
    wsprintf(buff, "%d", sequence);
    WritePrivateProfileString(INI_LAST, INI_LAST_SEQUENCE, buff, GSSAPI_INI);
    wsprintf(buff, "%d", verbose);
    WritePrivateProfileString(INI_LAST, INI_LAST_VERBOSE, buff, GSSAPI_INI);
    wsprintf(buff, "%d", ccount);
    WritePrivateProfileString(INI_LAST, INI_LAST_CCOUNT, buff, GSSAPI_INI);
    wsprintf(buff, "%d", mcount);
    WritePrivateProfileString(INI_LAST, INI_LAST_MCOUNT, buff, GSSAPI_INI);
    wsprintf(buff, "%d", gssv1);
    WritePrivateProfileString(INI_LAST, INI_LAST_VER1, buff, GSSAPI_INI);
    wsprintf(buff, "%d", noauth);
    WritePrivateProfileString(INI_LAST, INI_LAST_NOAUTH, buff, GSSAPI_INI);
    wsprintf(buff, "%d", nowrap);
    WritePrivateProfileString(INI_LAST, INI_LAST_NOWRAP, buff, GSSAPI_INI);
    wsprintf(buff, "%d", nocrypt);
    WritePrivateProfileString(INI_LAST, INI_LAST_NOCRYPT, buff, GSSAPI_INI);
    wsprintf(buff, "%d", nomic);
    WritePrivateProfileString(INI_LAST, INI_LAST_NOMIC, buff, GSSAPI_INI);
}
/*+*************************************************************************
**
** Update_saved
**
** Updates the host list with the new NAME the user typed.
**
***************************************************************************/
static void
update_saved (void) {
	int i;										// Index

	for (i = 0; i < MAX_SAVED-1; ++i) {			// Find it in the list
		if (! _stricmp (szHost, hosts[i])) 		// A match
			break;
		if (*hosts[i] == '\0')					// End of the list
			break;
	}
	memmove (hosts[1], hosts[0], i * sizeof(hosts[0])); // Move the data down
	strcpy (hosts[0], szHost);					// Insert this item

    for (i = 0; i < MAX_SAVED-1; ++i) {			// Find it in the list
		if (! _stricmp (szService, svcs[i])) 		// A match
			break;
		if (*svcs[i] == '\0')					// End of the list
			break;
	}
	memmove (svcs[1], svcs[0], i * sizeof(svcs[0])); // Move the data down
	strcpy (svcs[0], szService);					// Insert this item

	for (i = 0; i < MAX_SAVED-1; ++i) {			// Find it in the list
		if (! _stricmp (szMessage, msgs[i])) 		// A match
			break;
		if (*msgs[i] == '\0')					// End of the list
			break;
	}
	memmove (msgs[1], msgs[0], i * sizeof(msgs[0])); // Move the data down
	strcpy (msgs[0], szMessage);					// Insert this item

	for (i = 0; i < MAX_SAVED-1; ++i) {			// Find it in the list
		if (! _stricmp (szMech, mechs[i])) 		// A match
			break;
		if (*mechs[i] == '\0')					// End of the list
			break;
	}
	memmove (mechs[1], mechs[0], i * sizeof(hosts[0])); // Move the data down
	strcpy (mechs[0], szMech);					// Insert this item

	write_saved ();
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
    char buff[256];
#ifdef USE_LEASH
    krb5_error_code retval;
    apiCB * cc_ctx = 0;
    struct _infoNC ** pNCi = 0;
#endif

	SendDlgItemMessage(hDlg, GSS_HOST_NAME, CB_RESETCONTENT, 0, 0);
	SetDlgItemText(hDlg, GSS_HOST_NAME, szHost);
	SendDlgItemMessage(hDlg, GSS_HOST_NAME, CB_SETEDITSEL, 0, 0);
	for (i = 1; i < MAX_SAVED; ++i) {			// Fill in the list box
		if (*hosts[i] == '\0')
			break;
		SendDlgItemMessage(hDlg, GSS_HOST_NAME, CB_ADDSTRING, 0, (LPARAM) ((LPSTR) hosts[i]));
	}

	SendDlgItemMessage(hDlg, GSS_SERVICE_NAME, CB_RESETCONTENT, 0, 0);
	SetDlgItemText(hDlg, GSS_SERVICE_NAME, szService);
	SendDlgItemMessage(hDlg, GSS_SERVICE_NAME, CB_SETEDITSEL, 0, 0);
	for (i = 1; i < MAX_SAVED; ++i) {			// Fill in the list box
		if (*svcs[i] == '\0')
			break;
		SendDlgItemMessage(hDlg, GSS_SERVICE_NAME, CB_ADDSTRING, 0, (LPARAM) ((LPSTR) svcs[i]));
	}

	SendDlgItemMessage(hDlg, GSS_MECHANISM, CB_RESETCONTENT, 0, 0);
	SetDlgItemText(hDlg, GSS_MECHANISM, szMech);
	SendDlgItemMessage(hDlg, GSS_MECHANISM, CB_SETEDITSEL, 0, 0);
	for (i = 1; i < MAX_SAVED; ++i) {			// Fill in the list box
		if (*mechs[i] == '\0')
			break;
		SendDlgItemMessage(hDlg, GSS_MECHANISM, CB_ADDSTRING, 0, (LPARAM) ((LPSTR) mechs[i]));
	}

    SendDlgItemMessage(hDlg, GSS_CCACHE_NAME, CB_RESETCONTENT, 0, 0);
	SetDlgItemText(hDlg, GSS_CCACHE_NAME, szCCache);
	SendDlgItemMessage(hDlg, GSS_CCACHE_NAME, CB_SETEDITSEL, 0, 0);

#ifdef USE_LEASH
    retval = cc_initialize(&cc_ctx, CC_API_VER_2, NULL, NULL);
    if (retval)
        goto skip_ccache;

    retval = cc_get_NC_info(cc_ctx, &pNCi);
    if (retval) 
        goto clean_ccache;

    for ( i=0; pNCi[i]; i++ ) {
        if (pNCi[i]->vers == CC_CRED_V5) {
            sprintf(buff,"API:%s",pNCi[i]->name);
            SendDlgItemMessage(hDlg, GSS_CCACHE_NAME, CB_ADDSTRING, 0, (LPARAM) ((LPSTR) buff));
        }
    }

  clean_ccache:
    if (pNCi)
        cc_free_NC_info(cc_ctx, &pNCi);
    if (cc_ctx)
        cc_shutdown(&cc_ctx);
  skip_ccache:
#endif /* USE_LEASH */
    if ( szCCache[0] )
        SendDlgItemMessage(hDlg, GSS_CCACHE_NAME, CB_ADDSTRING, 0, (LPARAM) ((LPSTR) szCCache));
    SendDlgItemMessage(hDlg, GSS_CCACHE_NAME, CB_ADDSTRING, 0, (LPARAM) ((LPSTR) "MSLSA:"));

	SendDlgItemMessage(hDlg, GSS_MESSAGE, CB_RESETCONTENT, 0, 0);
	SetDlgItemText(hDlg, GSS_MESSAGE, szMessage);
	SendDlgItemMessage(hDlg, GSS_MESSAGE, CB_SETEDITSEL, 0, 0);
	for (i = 1; i < MAX_SAVED; ++i) {			// Fill in the list box
		if (*msgs[i] == '\0')
			break;
		SendDlgItemMessage(hDlg, GSS_MESSAGE, CB_ADDSTRING, 0, (LPARAM) ((LPSTR) msgs[i]));
	}

    wsprintf(buff, "%d", port);
    SetDlgItemText(hDlg, GSS_PORT, buff);

    CheckDlgButton(hDlg, GSS_VERBOSE, verbose);
    CheckDlgButton(hDlg, GSS_DELEGATION, delegate);
    CheckDlgButton(hDlg, GSS_MUTUAL, mutual);
    CheckDlgButton(hDlg, GSS_REPLAY, replay);
    CheckDlgButton(hDlg, GSS_SEQUENCE, sequence);
    CheckDlgButton(hDlg, GSS_VERSION_ONE, gssv1);
    CheckDlgButton(hDlg, GSS_NO_AUTH, noauth);
    CheckDlgButton(hDlg, GSS_NO_WRAP, nowrap);
    CheckDlgButton(hDlg, GSS_NO_ENCRYPT, nocrypt);
    CheckDlgButton(hDlg, GSS_NO_MIC, nomic);

    if ( noauth ) {
        // disable the other no_xxx options
        EnableWindow(GetDlgItem(hDlg, GSS_NO_WRAP), FALSE);
        EnableWindow(GetDlgItem(hDlg, GSS_NO_ENCRYPT), FALSE);
        EnableWindow(GetDlgItem(hDlg, GSS_NO_MIC), FALSE);
    } else {
        // enable the other no_xxx options
        EnableWindow(GetDlgItem(hDlg, GSS_NO_WRAP), TRUE);
        EnableWindow(GetDlgItem(hDlg, GSS_NO_ENCRYPT), TRUE);
        EnableWindow(GetDlgItem(hDlg, GSS_NO_MIC), TRUE);
    }

    SendDlgItemMessage(hDlg, GSS_CALL_COUNT, TBM_SETRANGEMIN, (WPARAM) FALSE, (LPARAM) 1);
    SendDlgItemMessage(hDlg, GSS_CALL_COUNT, TBM_SETRANGEMAX, (WPARAM) FALSE, (LPARAM) 20);
    SendDlgItemMessage(hDlg, GSS_CALL_COUNT, TBM_SETPOS, (WPARAM) FALSE, (LPARAM) ccount);
    sprintf(buff,"Call Count: %d",ccount);
    SetWindowText(GetDlgItem(hDialog, IDC_STATIC_CCOUNT),buff);

    SendDlgItemMessage(hDlg, GSS_MESSAGE_COUNT, TBM_SETRANGEMIN, (WPARAM) FALSE, (LPARAM) 1);
    SendDlgItemMessage(hDlg, GSS_MESSAGE_COUNT, TBM_SETRANGEMAX, (WPARAM) FALSE, (LPARAM) 20);
    SendDlgItemMessage(hDlg, GSS_MESSAGE_COUNT, TBM_SETPOS, (WPARAM) FALSE, (LPARAM) mcount);
    sprintf(buff,"Message Count: %d",mcount);
    SetWindowText(GetDlgItem(hDialog, IDC_STATIC_MSG_COUNT),buff);
}

int
gss_printf (const char *format, ...) {
    static char myprtfstr[4096];
    int i, len, rc=0;
    char *cp;
    va_list ap;

    va_start(ap, format);
    rc = _vsnprintf(myprtfstr, sizeof(myprtfstr)-1, format, ap);
    va_end(ap);

    SendDlgItemMessage(hDialog, GSS_OUTPUT, EM_REPLACESEL, FALSE, (LPARAM) myprtfstr);
    return rc;
}
