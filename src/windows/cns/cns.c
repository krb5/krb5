/*
 * cns.c
 *
 * Tabs 4
 *
 * Main routine of the Kerberos user interface.  Also handles
 * all dialog level management functions.
 *
 * Copyright 1994 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#if !defined(KRB5) && !defined(KRB4)
	#define KRB5 1
#endif

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <ctype.h>
#include <time.h>

#ifdef KRB4
	#define	DEFINE_SOCKADDR
	#include "mit-copyright.h"
	#include "krb.h"
	#include "kadm.h"
	#include "org.h"
#endif

#ifdef KRB5
	#include "winsock.h"
	#include "krb5.h"
	#include "krbini.h"
	#include "com_err.h"

	#define DEFAULT_TKT_LIFE    120             // In 5 minute units
	#define ANAME_SZ	        40
	#define	REALM_SZ	        40
	#define	SNAME_SZ	        40
	#define	INST_SZ		        40
	#define MAX_KPW_LEN	        128
	/* include space for '.' and '@' */
	#define	MAX_K_NAME_SZ	    (ANAME_SZ + INST_SZ + REALM_SZ + 2)
#ifdef CYGNUS
	#define ORGANIZATION        "Cygnus Support"
#endif

    #define CREDENTIALS         char
#endif

#include "cns.h"
#include "tktlist.h"

/*
 * Constants
 */
#define BLOCK_MAX_SEC 30				/* Blocking timeout duration */
#define KWIN_UPDATE_PERIOD 30000		/* Every 30 seconds update the screen */
#define TIME_BUFFER	300					/* Pop-up time buffer in seconds */
#define WM_KWIN_SETNAME (WM_USER+100)	/* Sets the name fields in the dialog */

enum {									/* Actions after login */
	LOGIN_AND_EXIT,
	LOGIN_AND_MINIMIZE,
	LOGIN_AND_RUN,
};

/*
 * Globals
 */
static HICON kwin_icons[MAX_ICONS];		/* Icons depicting time */
static HFONT hfontdialog = NULL;		/* Font in which the dialog is drawn. */
static HFONT hfonticon = NULL;			/* Font for icon label */
static HINSTANCE hinstance;
static int dlgncmdshow;					/* ncmdshow from WinMain */
static UINT wm_kerberos_changed;		/* Registered message for cache changing */
static int action;						/* After login actions */
static UINT kwin_timer_id;				/* Timer being used for update */
static BOOL alert;						/* Actions on ticket expiration */
static BOOL beep;
static BOOL alerted;					/* TRUE when user already alerted */
static BOOL isblocking = FALSE;			/* TRUE when blocked in WinSock */
static DWORD blocking_end_time;			/* Ending tick count for blocking timeout */
static FARPROC hook_instance;			/* Intance handle for blocking hook function */

#ifdef KRB5
	krb5_context k5_context;
	krb5_ccache k5_ccache;
    static char ccname[FILENAME_MAX];           /* ccache file location */
#endif

/*+
 * Function: Called during blocking operations.  Implement a timeout
 *	if nothing occurs within the specified time, cancel the blocking
 *	operation.  Also permit the user to press escape in order to
 *	cancel the blocking operation.
 *
 * Returns: TRUE if we got and dispatched a message, FALSE otherwise.
 */
BOOL __export CALLBACK
blocking_hook_proc (void)
{
	MSG msg;
	BOOL rc;

	if (GetTickCount() > blocking_end_time) {
		WSACancelBlockingCall();
		return FALSE;
	}

	rc = (BOOL) PeekMessage(&msg, NULL, 0, 0, PM_REMOVE);
	if (!rc)
		return FALSE;

	if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
		WSACancelBlockingCall();
		blocking_end_time = msg.time - 1;
		return FALSE;
	}

	TranslateMessage(&msg);
	DispatchMessage(&msg);

	return TRUE;

} /* blocking_hook_proc */


/*+
 * Function: Set up a blocking hook function.
 *
 * Parameters:
 *	timeout - # of seconds to block for before cancelling.
 */
static void
start_blocking_hook (
	int timeout)
{
	FARPROC proc;

	if (isblocking)
		return;

	isblocking = TRUE;
	blocking_end_time = GetTickCount() + (1000 * timeout);
	hook_instance = MakeProcInstance(blocking_hook_proc, hinstance);
	proc = WSASetBlockingHook(hook_instance);
	assert(proc != NULL);

} /* start_blocking_hook */


/*+
 * Function: End the blocking hook fuction set up above.
 */
static void
end_blocking_hook (void)
{

	FreeProcInstance(hook_instance);
	WSAUnhookBlockingHook();
	isblocking = FALSE;

} /* end_blocking_hook */


/*+
 * Function: Centers the specified window on the screen.
 *
 * Parameters:
 *		hwnd - the window to center on the screen.
 */
static void
center_dialog (
	HWND hwnd)
{
	int scrwidth, scrheight;
	int dlgwidth, dlgheight;
	RECT r;
	HDC hdc;

	if (hwnd == NULL)
		return;

	GetWindowRect(hwnd, &r);
	dlgwidth = r.right  - r.left;
	dlgheight = r.bottom - r.top ;
	hdc = GetDC(NULL);
	scrwidth = GetDeviceCaps(hdc, HORZRES);
	scrheight = GetDeviceCaps(hdc, VERTRES);
	ReleaseDC(NULL, hdc);
	r.left = (scrwidth - dlgwidth) / 2;
	r.top  = (scrheight - dlgheight) / 2;
	MoveWindow(hwnd, r.left, r.top, dlgwidth, dlgheight, TRUE);

} /* center_dialog */


/*+
 * Function: Positions the kwin dialog either to the saved location
 * 	or the center of the screen if no saved location.
 *
 * Parameters:
 *		hwnd - the window to center on the screen.
 */
static void
position_dialog (
	HWND hwnd)
{
	int n;
	int scrwidth, scrheight;
	HDC hdc;
	char position[256];
	int x, y, cx, cy;

	if (hwnd == NULL)
		return;

	hdc = GetDC(NULL);
	scrwidth = GetDeviceCaps(hdc, HORZRES);
	scrheight = GetDeviceCaps(hdc, VERTRES);
	ReleaseDC(NULL, hdc);
	GetPrivateProfileString(INI_DEFAULTS, INI_POSITION, "",
		position, sizeof(position), KERBEROS_INI);

	n = sscanf(position, " [%d , %d , %d , %d", &x, &y, &cx, &cy);
	if (n != 4 ||
		x > scrwidth ||
		y > scrheight ||
		x + cx < 0 ||
		y + cy < 0)
		center_dialog(hwnd);
    else
		MoveWindow(hwnd, x, y, cx, cy, TRUE);

} /* position_dialog */


/*+
 * Function: Set font of all dialog items.
 *
 * Parameters:
 *		hwnd - the dialog to set the font of
 */
static void
set_dialog_font (
	HWND hwnd,
	HFONT hfont)
{
	hwnd = GetWindow(hwnd, GW_CHILD);

	while (hwnd != NULL) {
		SendMessage(hwnd, WM_SETFONT, (WPARAM) hfont, 0);
		hwnd = GetWindow(hwnd, GW_HWNDNEXT);
	}

} /* set_dialog_font */


/*+
 * Function: Trim leading and trailing white space from a string.
 *
 * Parameters:
 *	s - the string to trim.
 */
void
trim (
	char *s)
{
	int l;
	int i;

	for (i = 0; s[i]; i++)
		if (s[i] != ' ' && s[i] != '\t')
			break;

	l = strlen(&s[i]);
	memmove(s, &s[i], l + 1);

	for (l--; l >= 0; l--) {
		if (s[l] != ' ' && s[l] != '\t')
			break;
	}
	s[l + 1] = 0;

} /* trim */


/*+
 * Function: This routine figures out the current time epoch and
 * returns the conversion factor.  It exists because Microloss
 * screwed the pooch on the time() and _ftime() calls in its release
 * 7.0 libraries.  They changed the epoch to Dec 31, 1899!
 */
time_t
kwin_get_epoch (void)
{
	static struct tm jan_1_70 = {0, 0, 0, 1, 0, 70};
	time_t epoch = 0;

	epoch = -mktime(&jan_1_70);		/* Seconds til 1970 localtime */
	epoch += _timezone;				/* Seconds til 1970 GMT */

	return epoch;

} /* kwin_get_epoch */


/*+
 * Function: Save the credentials for later restoration.
 *
 * Parameters:
 *	c - Returned pointer to saved credential cache.
 *
 *	pname - Returned as principal name of session.
 *
 *	pinstance - Returned as principal instance of session.
 *
 *	ncred - Returned number of credentials saved.
 */
static void
push_credentials (
	CREDENTIALS **cp,
	char *pname,
	char *pinstance,
	int *ncred)
{
#ifdef KRB4
	int i;
    char service[ANAME_SZ];
    char instance[INST_SZ];
    char realm[REALM_SZ];
	CREDENTIALS *c;

	if (krb_get_tf_fullname ((char *) 0, pname, pinstance, (char *) 0) != KSUCCESS) {
		pname[0] = 0;

		pinstance[0] = 0;
	}

	*ncred = krb_get_num_cred();
	if (*ncred <= 0)
		return;

	c= malloc(*ncred * sizeof(CREDENTIALS));
	assert(c != NULL);
	if (c == NULL) {
		*ncred = 0;

		return;
	}

	for (i = 0; i < *ncred; i++) {
		krb_get_nth_cred(service, instance, realm, i + 1);
		krb_get_cred(service, instance, realm, &c[i]);
	}

	*cp = c;
#endif

#ifdef KRB5     /* FIXME */
    return;
#endif

} /* push_credentials */


/*+
 * Function: Restore the saved credentials.
 *
 *	c - Pointer to saved credential cache.
 *
 *	pname - Principal name of session.
 *
 *	pinstance - Principal instance of session.
 *
 *	ncred - Number of credentials saved.
 */
static void
pop_credentials (
	CREDENTIALS *c,
	char *pname,
	char *pinstance,
	int ncred)
{
#ifdef KRB4
	int i;

	if (pname[0])
		in_tkt(pname, pinstance);
	else
		dest_tkt();

	if (ncred <= 0)
		return;

	for (i = 0; i < ncred; i++) {
		krb_save_credentials(c[i].service, c[i].instance, c[i].realm,
			c[i].session, c[i].lifetime, c[i].kvno, &(c[i].ticket_st),
			c[i].issue_date);
	}

	free(c);
#endif
#ifdef KRB5     /* FIXME */
    return;
#endif

} /* pop_credentials */


/*+
 * Function: Changes the password.
 *
 * Parameters:
 *	hwnd - the current window from which command was invoked.
 *
 *	name - name of user to change password for
 *
 *	instance - instance of user to change password for
 *
 *	realm - realm in which to change password
 *
 *	oldpw - the old password
 *
 *	newpw - the new password to change to
 *
 * Returns: TRUE if change took place, FALSE otherwise.
 */
static BOOL
change_password (
	HWND hwnd,
	char *name,
	char *instance,
	char *realm,
	char *oldpw,
	char *newpw)
{
#ifdef KRB4
    des_cblock new_key;
    char *ret_st;
	int krc;
	char *p;
	CREDENTIALS *c;
	int ncred;
    char pname[ANAME_SZ];
    char pinstance[INST_SZ];

	push_credentials(&c, pname, pinstance, &ncred);
	krc = krb_get_pw_in_tkt(
		name, instance, realm, PWSERV_NAME, KADM_SINST,	1, oldpw);

	if (krc != KSUCCESS) {
		if (krc == INTK_BADPW)
			p = "Old password is incorrect";
		else
			p = krb_get_err_text(krc);
		pop_credentials(c, pname, pinstance, ncred);
		MessageBox(hwnd, p, "", MB_OK | MB_ICONEXCLAMATION);

		return FALSE;
    }

	krc = kadm_init_link(PWSERV_NAME, KRB_MASTER, realm);

	if (krc != KSUCCESS) {
		pop_credentials(c, pname, pinstance, ncred);
		MessageBox(hwnd, kadm_get_err_text(krc), "", MB_OK | MB_ICONEXCLAMATION);

		return FALSE;
	}

	des_string_to_key(newpw, new_key);
	krc = kadm_change_pw2(new_key, newpw, &ret_st);
	pop_credentials(c, pname, pinstance, ncred);

	if (ret_st != NULL)
		free(ret_st);

	if (krc != KSUCCESS) {
		MessageBox(hwnd, kadm_get_err_text(krc), "", MB_OK | MB_ICONEXCLAMATION);

		return FALSE;
	}

	return TRUE;
#endif

#ifdef KRB5     /* FIXME */
    char *msg;                                  // Message string
    krb5_error_code code;                       // Return value
    code = k5_change_password (k5_context, name, realm, oldpw, newpw, &msg);

    if (msg != NULL) {
        MessageBox (NULL, msg, NULL, MB_ICONEXCLAMATION);
    } else if (code) {
		if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
			MessageBox (NULL, "Password incorrect", NULL, MB_ICONEXCLAMATION);
		else
			com_err (NULL, code, "while changing password.");
	}

	return (code == 0);

#endif /* KRB5 */
}
/*+
 * Function: Process WM_COMMAND messages for the password dialog.
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - id of the command item
 *
 *	lparam - LOWORD=hwnd of control, HIWORD=notification message.
 *
 * Returns: TRUE if initialized sucessfully, false otherwise.
 */
static LONG
password_command (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	char name[ANAME_SZ];
	char instance[INST_SZ];
	char realm[REALM_SZ];
    char oldpw[MAX_KPW_LEN];
    char newpw1[MAX_KPW_LEN];
    char newpw2[MAX_KPW_LEN];
	HCURSOR hcursor;
	BOOL b;
	int id;

	if (HIWORD(lparam) != BN_CLICKED) {
		GetDlgItemText(hwnd, IDD_PASSWORD_NAME, name, sizeof(name));
		trim(name);
		GetDlgItemText(hwnd, IDD_PASSWORD_REALM, realm, sizeof(realm));
		trim(realm);
		GetDlgItemText(hwnd, IDD_OLD_PASSWORD, oldpw, sizeof(oldpw));
		GetDlgItemText(hwnd, IDD_NEW_PASSWORD1, newpw1, sizeof(newpw1));
		GetDlgItemText(hwnd, IDD_NEW_PASSWORD2, newpw2, sizeof(newpw2));
		b = strlen(name) && strlen(realm) && strlen(oldpw) &&
			strlen(newpw1) && strlen(newpw2);
		EnableWindow(GetDlgItem(hwnd, IDOK), b);
		id = (b) ? IDOK : IDD_PASSWORD_CR;
		SendMessage(hwnd, DM_SETDEFID, id, 0);

		return FALSE;
	}

	switch (wparam) {
	case IDOK:
		if (isblocking)
			return TRUE;

		GetDlgItemText(hwnd, IDD_PASSWORD_NAME, name, sizeof(name));
		trim(name);
        GetDlgItemText(hwnd, IDD_PASSWORD_INSTANCE, instance, sizeof(instance));
        trim(instance);
		GetDlgItemText(hwnd, IDD_PASSWORD_REALM, realm, sizeof(realm));
		trim(realm);
		GetDlgItemText(hwnd, IDD_OLD_PASSWORD, oldpw, sizeof(oldpw));
		GetDlgItemText(hwnd, IDD_NEW_PASSWORD1, newpw1, sizeof(newpw1));
		GetDlgItemText(hwnd, IDD_NEW_PASSWORD2, newpw2, sizeof(newpw2));

		if (strcmp(newpw1, newpw2) != 0) {
			MessageBox(hwnd, "The two passwords you entered don't match!", "",
				MB_OK | MB_ICONEXCLAMATION);
			SetDlgItemText(hwnd, IDD_NEW_PASSWORD1, "");
			SetDlgItemText(hwnd, IDD_NEW_PASSWORD2, "");
			PostMessage(hwnd, WM_NEXTDLGCTL,
				GetDlgItem(hwnd, IDD_NEW_PASSWORD1), MAKELONG(1, 0));

			return TRUE;
		}

		hcursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
		start_blocking_hook(BLOCK_MAX_SEC);

		if (change_password(hwnd, name, instance, realm, oldpw, newpw1))
			EndDialog(hwnd, IDOK);
		else
			PostMessage(hwnd, WM_NEXTDLGCTL,
				GetDlgItem(hwnd, IDD_OLD_PASSWORD), MAKELONG(1, 0));

		end_blocking_hook();
		SetCursor(hcursor);

		return TRUE;

	case IDCANCEL:
		if (isblocking)
			WSACancelBlockingCall();
		EndDialog(hwnd, IDCANCEL);

		return TRUE;

	case IDD_PASSWORD_CR:
		id = GetDlgCtrlID(GetFocus());
		assert(id != 0);

		if (id == IDD_NEW_PASSWORD2)
			PostMessage(hwnd, WM_NEXTDLGCTL,
				GetDlgItem(hwnd, IDD_PASSWORD_NAME), MAKELONG(1, 0));
		else
			PostMessage(hwnd, WM_NEXTDLGCTL, 0, 0);

		return TRUE;

	}

	return FALSE;

} /* password_command */


/*+
 * Function: Process WM_INITDIALOG messages for the password dialog.
 * 	Set up all initial dialog values from the parent dialog.
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - handle of the control for focus.
 *
 *	lparam - lparam from dialog box call.
 *
 * Returns: TRUE if we didn't set the focus here,
 * 	FALSE if we did.
 */
static BOOL
password_initdialog (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	char name[ANAME_SZ];
	char realm[REALM_SZ];
	HWND hwndparent;
	int id;
    #ifdef KRB4
    	char instance[INST_SZ];
    #endif

	center_dialog(hwnd);
	set_dialog_font(hwnd, hfontdialog);

	hwndparent = GetParent(hwnd);
	assert(hwndparent != NULL);

	GetDlgItemText(hwndparent, IDD_LOGIN_NAME, name, sizeof(name));
	trim(name);
	SetDlgItemText(hwnd, IDD_PASSWORD_NAME, name);

    #ifdef KRB4
        GetDlgItemText(hwndparent, IDD_LOGIN_INSTANCE, instance, sizeof(instance));
	    trim(instance);
    	SetDlgItemText(hwnd, IDD_PASSWORD_INSTANCE, instance);
    #endif

	GetDlgItemText(hwndparent, IDD_LOGIN_REALM, realm, sizeof(realm));
	trim(realm);
	SetDlgItemText(hwnd, IDD_PASSWORD_REALM, realm);

	if (strlen(name) == 0)
		id = IDD_PASSWORD_NAME;
	else if (strlen(realm) == 0)
		id = IDD_PASSWORD_REALM;
	else
		id = IDD_OLD_PASSWORD;

	SetFocus(GetDlgItem(hwnd, id));

	return FALSE;

} /* password_initdialog */


/*+
 * Function: Process dialog specific messages for the password dialog.
 *
 * Parameters:
 *	hwnd - the dialog receiving the message.
 *
 *	message - the message to process.
 *
 *	wparam - wparam of the message.
 *
 *	lparam - lparam of the message.
 *
 * Returns: TRUE if message handled locally, FALSE otherwise.
 */
static BOOL CALLBACK
password_dlg_proc (
	HWND hwnd,
	UINT message,
	WPARAM wparam,
	LPARAM lparam)
{
	LRESULT rc;

	switch (message) {

	case WM_INITDIALOG:
		return password_initdialog(hwnd, wparam, lparam);

	case WM_COMMAND:
		password_command(hwnd, wparam, lparam);
		return (BOOL) rc;

	case WM_SETCURSOR:
		if (isblocking) {
			SetCursor(LoadCursor(NULL, IDC_WAIT));
			SetWindowLong(hwnd, DWL_MSGRESULT, TRUE);

			return TRUE;
		}
		break;
	}

	return FALSE;

} /* password_dlg_proc */


/*+
 * Function: Display and process the password dialog.
 *
 * Parameters:
 *	hwnd - the parent window for the dialog
 *
 * Returns: TRUE if the dialog completed successfully, FALSE otherwise.
 */
static BOOL
password_dialog (
	HWND hwnd)
{
	DLGPROC dlgproc;
	int rc;

	dlgproc = (FARPROC) MakeProcInstance(password_dlg_proc, hinstance);
	assert(dlgproc != NULL);

	if (dlgproc == NULL)
		return FALSE;

	rc = DialogBox(hinstance, MAKEINTRESOURCE(ID_PASSWORD), hwnd, dlgproc);
	assert(rc != -1);

	FreeProcInstance((FARPROC) dlgproc);

	return rc == IDOK;

} /* password_dialog */


/*+
 * Function: Process WM_INITDIALOG messages for the options dialog.
 * 	Set up all initial dialog values from the KERBEROS_INI file.
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - handle of the control for focus.
 *
 *	lparam - lparam from dialog box call.
 *
 * Returns: TRUE if we didn't set the focus here,
 * 	FALSE if we did.
 */
static LONG
opts_initdialog (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	char wdir[FILENAME_MAX];
	char defname[FILENAME_MAX];
    char newname[FILENAME_MAX];
	UINT rc;
	int lifetime;

	center_dialog(hwnd);
	set_dialog_font(hwnd, hfontdialog);
	rc = GetWindowsDirectory(wdir, sizeof(wdir));
	assert(rc > 0);
	strcat (wdir, "\\");

	/* krb.conf file */
	strcpy(defname, wdir);
	strcat(defname, DEF_KRB_CONF);
	GetPrivateProfileString(INI_FILES, INI_KRB_CONF, defname,
		newname, sizeof(newname), KERBEROS_INI);
	_strupr(newname);
	SetDlgItemText(hwnd, IDD_CONF, newname);
	
	#ifdef KRB4
	/* krb.realms file */
		strcpy(defname, wdir);
		strcat(defname, DEF_KRB_REALMS);
		GetPrivateProfileString(INI_FILES, INI_KRB_REALMS, defname,
			newname, sizeof(newname), KERBEROS_INI);
		_strupr(newname);
		SetDlgItemText(hwnd, IDD_REALMS, newname);
	#endif /* KRB4 */

	/* Credential cache file */
    #ifdef KRB5
		strcpy(defname, wdir);
    	strcat(defname, INI_KRB_CCACHE);
    	GetPrivateProfileString(INI_FILES, INI_KRB_CCACHE, defname,
    		ccname, sizeof(ccname), KERBEROS_INI);
    	_strupr(ccname);
    	SetDlgItemText(hwnd, IDD_CCACHE, ccname);
    #endif /* KRB5 */

/* Ticket duration */
	lifetime = GetPrivateProfileInt(INI_OPTIONS, INI_DURATION,
		DEFAULT_TKT_LIFE * 5, KERBEROS_INI);
	SetDlgItemInt(hwnd, IDD_LIFETIME, lifetime, FALSE);

/* Expiration action */
	GetPrivateProfileString(INI_EXPIRATION, INI_ALERT, "No",
		defname, sizeof(defname), KERBEROS_INI);
	alert = _stricmp(defname, "Yes") == 0;
	SendDlgItemMessage(hwnd, IDD_ALERT, BM_SETCHECK, alert, 0);
	GetPrivateProfileString(INI_EXPIRATION, INI_BEEP, "No",
		defname, sizeof(defname), KERBEROS_INI);
	beep = _stricmp(defname, "Yes") == 0;
	SendDlgItemMessage(hwnd, IDD_BEEP, BM_SETCHECK, beep, 0);

	return TRUE;

} /* opts_initdialog */


/*+
 * Function: Process WM_COMMAND messages for the options dialog.
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - id of the command item
 *
 *	lparam - LOWORD=hwnd of control, HIWORD=notification message.
 *
 * Returns: TRUE if initialized sucessfully, false otherwise.
 */
static LONG
opts_command (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	char wdir[FILENAME_MAX];
	char defname[FILENAME_MAX];
	char newname[FILENAME_MAX];
	char *p;
	BOOL b;
	int lifetime;
	int rc;

	switch (wparam) {
	case IDOK:
		rc = GetWindowsDirectory(wdir, sizeof(wdir));
		assert(rc > 0);
		strcat(wdir, "\\");

/* Ticket duration */
		lifetime = GetDlgItemInt(hwnd, IDD_LIFETIME, &b, FALSE);

		if (!b) {
			MessageBox(hwnd, "Lifetime must be a number!", "", MB_OK | MB_ICONEXCLAMATION);
			return TRUE;
		}

		_itoa(lifetime, defname, 10);
		b = WritePrivateProfileString(INI_OPTIONS, INI_DURATION, defname, KERBEROS_INI);
		assert(b);

/* krb.conf file */
		GetDlgItemText(hwnd, IDD_CONF, newname, sizeof(newname));
		trim(newname);
		strcpy(defname, wdir);
		strcat(defname, DEF_KRB_CONF);
		p = (*newname && _stricmp(newname, defname)) ? newname : NULL;
		b = WritePrivateProfileString(INI_FILES, INI_KRB_CONF, p, KERBEROS_INI);
		assert(b);

/* krb.realms file */
		#ifdef KRB4
			GetDlgItemText(hwnd, IDD_REALMS, newname, sizeof(newname));
			trim(newname);
			strcpy(defname, wdir);
			strcat(defname, DEF_KRB_REALMS);
			p = (*newname && _stricmp(newname, defname)) ? newname : NULL;
			b = WritePrivateProfileString(INI_FILES, INI_KRB_REALMS, p, KERBEROS_INI);
			assert(b);
		#endif /* KRB4 */

/* Credential cache file */
        #ifdef KRB5
    		GetDlgItemText(hwnd, IDD_CCACHE, newname, sizeof(newname));
    		trim(newname);
			strcpy(defname, wdir);
    		strcat(defname, "krb5cc");
            if (*newname == '\0')				// For detecting name change
                strcpy (newname, defname);
			p = (*newname && _stricmp(newname, defname)) ? newname : NULL;
    		b = WritePrivateProfileString(INI_FILES, INI_KRB_CCACHE, p, KERBEROS_INI);
    		assert(b);

            if (strcmp (ccname, newname)) {     // Did we change ccache file?
                krb5_error_code code;
                krb5_ccache cctemp;

                code = k5_init_ccache (&cctemp);
                if (code) {                     // Problem opening new one?
                    com_err (NULL, code, 
                        "while changing ccache.\r\nRestoring old ccache.");
    		        b = WritePrivateProfileString(INI_FILES, INI_KRB_CCACHE,
                        ccname, KERBEROS_INI);
                } else {
                    code = krb5_cc_close (k5_context, k5_ccache);
                    k5_ccache = cctemp;         // Copy new into old
                    if (k5_name_from_ccache (k5_ccache)) {
                        kwin_init_name (GetParent(hwnd), "");
                		kwin_set_default_focus(GetParent(hwnd));
                    }
                	ticket_init_list (GetDlgItem (GetParent(hwnd),
                        IDD_TICKET_LIST));
                }
            }

        #endif /* KRB5 */

/* Expiration action */
		alert = (BOOL) SendDlgItemMessage(hwnd, IDD_ALERT, BM_GETCHECK, 0, 0);
		p = (alert) ? "Yes" : "No";
		b = WritePrivateProfileString(INI_EXPIRATION, INI_ALERT, p, KERBEROS_INI);
		assert(b);

		beep = (BOOL) SendDlgItemMessage(hwnd, IDD_BEEP, BM_GETCHECK, 0, 0);
		p = (beep) ? "Yes" : "No";
		b = WritePrivateProfileString(INI_EXPIRATION, INI_BEEP, p, KERBEROS_INI);
		assert(b);

		EndDialog(hwnd, IDOK);

		return TRUE;

	case IDCANCEL:
		EndDialog(hwnd, IDCANCEL);

		return TRUE;
	}

	return FALSE;

} /* opts_command */


/*+
 * Function: Process dialog specific messages for the opts dialog.
 *
 * Parameters:
 *	hwnd - the dialog receiving the message.
 *
 *	message - the message to process.
 *
 *	wparam - wparam of the message.
 *
 *	lparam - lparam of the message.
 *
 * Returns: TRUE if message handled locally, FALSE otherwise.
 */
static BOOL CALLBACK
opts_dlg_proc (
	HWND hwnd,
	UINT message,
	WPARAM wparam,
	LPARAM lparam)
{
	LRESULT rc;

	switch (message) {

	case WM_INITDIALOG:
		rc = opts_initdialog(hwnd, wparam, lparam);

		return (BOOL) rc;

	case WM_COMMAND:
		rc = opts_command(hwnd, wparam, lparam);

		return (BOOL) rc;
	}

	return FALSE;

} /* opts_dlg_proc */


/*+
 * Function: Display and process the options dialog.
 *
 * Parameters:
 *	hwnd - the parent window for the dialog
 *
 * Returns: TRUE if the dialog completed successfully, FALSE otherwise.
 */
static BOOL
opts_dialog (
	HWND hwnd)
{
	DLGPROC dlgproc;
	int rc;

	dlgproc = (FARPROC) MakeProcInstance(opts_dlg_proc, hinstance);
	assert(dlgproc != NULL);

	if (dlgproc == NULL)
		return FALSE;

	rc = DialogBox(hinstance, MAKEINTRESOURCE(ID_OPTS), hwnd, dlgproc);
	assert(rc != -1);

	FreeProcInstance((FARPROC) dlgproc);

	return rc == IDOK;

} /* opts_dialog */


/*+
 * Function: Save most recent login triplets for placement on the
 *	bottom of the file menu.
 *
 * Parameters:
 *	hwnd - the handle of the window containing the menu to edit.
 *
 *	name - A login name to save in the recent login list
 *
 *	instance - An instance to save in the recent login list
 *
 *	realm - A realm to save in the recent login list
 */
static void
kwin_push_login (
	HWND hwnd,
	char *name,
	char *instance,
	char *realm)
{
	HMENU hmenu;
	int i;
	int id;
	int ctitems;
	char fullname[MAX_K_NAME_SZ + 3];
	char menuitem[MAX_K_NAME_SZ + 3];
	BOOL rc;

	strcpy(fullname, "&x ");
	strcat(fullname, name);
    strcat(fullname, ".");
    strcat(fullname, instance);
	strcat(fullname, "@");
	strcat(fullname, realm);

	hmenu = GetMenu(hwnd);
	assert(hmenu != NULL);

	hmenu = GetSubMenu(hmenu, 0);
	assert(hmenu != NULL);

	ctitems = GetMenuItemCount(hmenu);
	assert(ctitems >= FILE_MENU_ITEMS);

	if (ctitems == FILE_MENU_ITEMS) {
		rc = AppendMenu(hmenu, MF_SEPARATOR, 0, NULL);
		assert(rc);

		ctitems++;
	}

	for (i = FILE_MENU_ITEMS + 1; i < ctitems; i++) {
		GetMenuString(hmenu, i, menuitem, sizeof(menuitem), MF_BYPOSITION);

		if (strcmp(&fullname[3], &menuitem[3]) == 0) {
			rc = RemoveMenu(hmenu, i, MF_BYPOSITION);
			assert(rc);

			ctitems--;

			break;
		}
	}

	rc = InsertMenu(hmenu, FILE_MENU_ITEMS + 1, MF_BYPOSITION, 1, fullname);
	assert(rc);

	ctitems++;
	if (ctitems - FILE_MENU_ITEMS - 1 > FILE_MENU_MAX_LOGINS) {
		RemoveMenu(hmenu, ctitems - 1, MF_BYPOSITION);

		ctitems--;
	}

	id = 0;
	for (i = FILE_MENU_ITEMS + 1; i < ctitems; i++) {
		GetMenuString(hmenu, i, menuitem, sizeof(menuitem), MF_BYPOSITION);

		rc = RemoveMenu(hmenu, i, MF_BYPOSITION);
		assert(rc);

		menuitem[1] = '1' + id;
		rc = InsertMenu(hmenu, i, MF_BYPOSITION, IDM_FIRST_LOGIN + id, menuitem);
		assert(rc);

		id++;
	}

} /* kwin_push_login */


/*+
 * Function: Initialize the logins on the file menu form the KERBEROS.INI
 *	file.
 *
 * Parameters:
 *	hwnd - handle of the dialog containing the file menu.
 */
static void
kwin_init_file_menu (
	HWND hwnd)
{
	HMENU hmenu;
	int i;
	char login[sizeof(INI_LOGIN)+1];
	char menuitem[MAX_K_NAME_SZ + 3];
	int id;
	BOOL rc;

	hmenu = GetMenu(hwnd);
	assert(hmenu != NULL);

	hmenu = GetSubMenu(hmenu, 0);
	assert(hmenu != NULL);

	strcpy(login, INI_LOGIN);
	id = 0;
	for (i = 0; i < FILE_MENU_MAX_LOGINS; i++) {
		login[sizeof(INI_LOGIN) - 1] = '1' + i;
		login[sizeof(INI_LOGIN)] = 0;
		GetPrivateProfileString(INI_RECENT_LOGINS, login, "",
			&menuitem[3], sizeof(menuitem) - 3, KERBEROS_INI);
		if (!menuitem[3])
			continue;

		menuitem[0] = '&';
		menuitem[1] = '1' + id;
		menuitem[2] = ' ';

		if (id == 0) {
			rc = AppendMenu(hmenu, MF_SEPARATOR, 0, NULL);
			assert(rc);
		}
		AppendMenu(hmenu, MF_STRING, IDM_FIRST_LOGIN + id, menuitem);

		id++;
	}

} /* kwin_init_file_menu */


/*+
 * Function: Save the items on the file menu in the KERBEROS.INI file.
 *
 * Parameters:
 *	hwnd - handle of the dialog containing the file menu.
 */
static void
kwin_save_file_menu (
	HWND hwnd)
{
	HMENU hmenu;
	int i;
	int id;
	int ctitems;
	char menuitem[MAX_K_NAME_SZ + 3];
	char login[sizeof(INI_LOGIN)+1];
	BOOL rc;

	hmenu = GetMenu(hwnd);
	assert(hmenu != NULL);

	hmenu = GetSubMenu(hmenu, 0);
	assert(hmenu != NULL);

	strcpy(login, INI_LOGIN);
	ctitems = GetMenuItemCount(hmenu);
	assert(ctitems >= FILE_MENU_ITEMS);

	id = 0;
	for (i = FILE_MENU_ITEMS + 1; i < ctitems; i++) {
		GetMenuString(hmenu, i, menuitem, sizeof(menuitem), MF_BYPOSITION);
		login[sizeof(INI_LOGIN) - 1] = '1' + id;
		login[sizeof(INI_LOGIN)] = 0;

		rc = WritePrivateProfileString(INI_RECENT_LOGINS, login, &menuitem[3], KERBEROS_INI);
		assert(rc);

		id++;
	}

} /* kwin_save_file_menu */



/*+
 * Function: Given an expiration time, choose an appropriate
 *	icon to display.
 *
 * Parameters:
 *	expiration time of expiration in time() compatible units
 *
 * Returns: Handle of icon to display
 */
HICON
kwin_get_icon (
	time_t expiration)
{
	int ixicon;
	time_t dt;

	dt = expiration - time(NULL);
	dt = dt / 60;			/* convert to minutes */
	if (dt <= 0)
		ixicon = IDI_EXPIRED - IDI_FIRST_CLOCK;
	else if (dt > 60)
		ixicon = IDI_TICKET - IDI_FIRST_CLOCK;
	else
		ixicon = (int) (dt / 5);

	return kwin_icons[ixicon];

} /* kwin_get_icon */


/*+
 * Function: Intialize name fields in the Kerberos dialog.
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	fullname - the full kerberos name to initialize with
 */
static void
kwin_init_name (
	HWND hwnd,
	char *fullname)
{
    char name[ANAME_SZ];
    char instance[INST_SZ];
    char realm[REALM_SZ];
	int krc;

	if (fullname == NULL || fullname[0] == 0) {
		#ifdef KRB4
			strcpy(name, krb_get_default_user());
            GetPrivateProfileString(INI_DEFAULTS, INI_INSTANCE, "",
                instance, sizeof(instance), KERBEROS_INI);
			krc = krb_get_lrealm(realm, 1);
			if (krc != KSUCCESS)
				realm[0] = 0;
    		GetPrivateProfileString(INI_DEFAULTS, INI_REALM, realm,
	    		realm, sizeof(realm), KERBEROS_INI);
		#endif


		#ifdef KRB5
        {
            krb5_error_code code;
            char *ptr;

            GetPrivateProfileString (INI_DEFAULTS, INI_USER, "",
                name, sizeof(name), KERBEROS_INI);

            *realm = '\0';
            code = krb5_get_default_realm (k5_context, &ptr);
            if (! code) {
                strcpy (realm, ptr);
                free (ptr);
            }
    		GetPrivateProfileString(INI_DEFAULTS, INI_REALM, realm,
        		realm, sizeof(realm), KERBEROS_INI);
        }
		#endif

	} else {
		#ifdef KRB4
			kname_parse(name, instance, realm, fullname);
        	SetDlgItemText(hwnd, IDD_LOGIN_INSTANCE, instance);
		#endif

		#ifdef KRB5
			krc = k5_kname_parse(name, realm, fullname);
            *instance = '\0';
		#endif
	}

	SetDlgItemText(hwnd, IDD_LOGIN_NAME, name);
	SetDlgItemText(hwnd, IDD_LOGIN_REALM, realm);

} /* kwin_init_name */


/*+
 * Function: Set the focus to the name control if no name
 * 	exists, the realm control if no realm exists or the
 * 	password control.  Uses PostMessage not SetFocus.
 *
 * Parameters:
 *	hwnd - the Window handle of the parent.
 */
void
kwin_set_default_focus (
	HWND hwnd)
{
	char name[ANAME_SZ];
	char realm[REALM_SZ];
	HWND hwnditem;

	GetDlgItemText(hwnd, IDD_LOGIN_NAME, name, sizeof(name));

	trim(name);
	if (strlen(name) <= 0)
		hwnditem = GetDlgItem(hwnd, IDD_LOGIN_NAME);
	else {
		GetDlgItemText(hwnd, IDD_LOGIN_REALM, realm, sizeof(realm));
		trim(realm);

		if (strlen(realm) <= 0)
			hwnditem = GetDlgItem(hwnd, IDD_LOGIN_REALM);
		else
			hwnditem = GetDlgItem(hwnd, IDD_LOGIN_PASSWORD);
	}

	PostMessage(hwnd, WM_NEXTDLGCTL, hwnditem, MAKELONG(1, 0));

} /* kwin_set_default_focus */


/*+
 * Function: Save the values which live in the KERBEROS.INI file.
 *
 * Parameters:
 *	hwnd - the window handle of the dialog containing fields to
 *		be saved
 */
static void
kwin_save_name (
	HWND hwnd)
{
	char name[ANAME_SZ];
	char instance[INST_SZ];
	char realm[REALM_SZ];

	GetDlgItemText(hwnd, IDD_LOGIN_NAME, name, sizeof(name));
	trim(name);

	#ifdef KRB4
		krb_set_default_user(name);
        GetDlgItemText(hwnd, IDD_LOGIN_INSTANCE, instance, sizeof(instance));
        trim(instance);
        WritePrivateProfileString(INI_DEFAULTS, INI_INSTANCE, instance, KERBEROS_INI);
	#endif

	#ifdef KRB5
        WritePrivateProfileString(INI_DEFAULTS, INI_USER, name, KERBEROS_INI);
        *instance = '\0';
	#endif

	GetDlgItemText(hwnd, IDD_LOGIN_REALM, realm, sizeof(realm));
	trim(realm);
	WritePrivateProfileString(INI_DEFAULTS, INI_REALM, realm, KERBEROS_INI);

	kwin_push_login(hwnd, name, instance, realm);

} /* kwin_save_name */


/*+
 * Function: Process WM_INITDIALOG messages.  Set the fonts
 *	for all items on the dialog and populate the ticket list.
 *	Also set the default values for user, instance and realm.
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - handle of the control for focus.
 *
 *	lparam - lparam from dialog box call.
 *
 * Returns: TRUE if we didn't set the focus here,
 * 	FALSE if we did.
 */
static BOOL
kwin_initdialog (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	LOGFONT lf;
	HDC hdc;
	char name[ANAME_SZ];

	position_dialog(hwnd);
	ticket_init_list(GetDlgItem(hwnd, IDD_TICKET_LIST));
	kwin_init_file_menu(hwnd);
	kwin_init_name(hwnd, (char *) lparam);
	hdc = GetDC(NULL);
	assert(hdc != NULL);

	memset(&lf, 0, sizeof(lf));
	lf.lfHeight = -MulDiv(9, GetDeviceCaps(hdc, LOGPIXELSY), 72);
	strcpy(lf.lfFaceName, "Arial");
	hfontdialog = CreateFontIndirect(&lf);
	assert(hfontdialog != NULL);

	if (hfontdialog == NULL) {
		ReleaseDC(NULL, hdc);

		return TRUE;
	}

	lf.lfHeight = -MulDiv(8, GetDeviceCaps(hdc, LOGPIXELSY), 72);
	hfonticon = CreateFontIndirect(&lf);
	assert(hfonticon != NULL);

	if (hfonticon == NULL) {
		ReleaseDC(NULL, hdc);

		return TRUE;
	}

	ReleaseDC(NULL, hdc);

	set_dialog_font(hwnd, hfontdialog);
	GetDlgItemText(hwnd, IDD_LOGIN_NAME, name, sizeof(name));
	trim(name);

	if (strlen(name) > 0)
		SetFocus(GetDlgItem(hwnd, IDD_LOGIN_PASSWORD));
	else
		SetFocus(GetDlgItem(hwnd, IDD_LOGIN_NAME));

	ShowWindow(hwnd, dlgncmdshow);
	kwin_timer_id = SetTimer(hwnd, 1, KWIN_UPDATE_PERIOD, NULL);
	assert(kwin_timer_id != 0);

	return FALSE;

} /* kwin_initdialog */


/*+
 * Function: Process WM_DESTROY messages.  Delete the font
 *	created for use by the controls.
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - none
 *
 *	lparam - none
 *
 * Returns: 0
 */
static LONG
kwin_destroy (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	char position[256];
	RECT r;
	BOOL b;

	ticket_destroy(GetDlgItem(hwnd, IDD_TICKET_LIST));

	if (hfontdialog != NULL)
		DeleteObject(hfontdialog);

	if (hfonticon != NULL)
		DeleteObject(hfonticon);

	kwin_save_file_menu(hwnd);
	GetWindowRect(hwnd, &r);
	sprintf(position, "[%d,%d,%d,%d]", r.left, r.top,
		r.right - r.left, r.bottom - r.top);
	b = WritePrivateProfileString(INI_DEFAULTS, INI_POSITION, position, KERBEROS_INI);
	assert(b);

	KillTimer(hwnd, kwin_timer_id);

	return 0;

} /* kwin_destroy */


/*+
 * Function: Retrievs item WindowRect in hwnd client
 *	coordiate system.
 *
 * Parameters:
 *	hwnditem - the item to retrieve
 *
 *	item - dialog in which into which to translate
 *
 *	r - rectangle returned
 */
static void
windowrect (
	HWND hwnditem,
	HWND hwnd,
	RECT *r)
{
	GetWindowRect(hwnditem, r);
	ScreenToClient(hwnd, (LPPOINT) &(r->left));
	ScreenToClient(hwnd, (LPPOINT) &(r->right));

} /* windowrect */


/*+
 * Function: Process WM_SIZE messages.  Resize the
 *	list and position the buttons attractively.
 *
 * Parameters:
 *	hwnd - the window receiving the message.
 *
 *	wparam - type of resize occuring
 *
 *	lparam - LOWORD=width of client area,
 *		HIWORD=height of client area.
 *
 * Returns: 0
 */
static LONG
kwin_size (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	#define listgap 8
	RECT r;
	RECT rdlg;
	int hmargin, vmargin;
	HWND hwnditem;
	int cx, cy;
	int cxdlg, cydlg;
	int i;
	int titlebottom;
	int editbottom;
	int listbottom;
	int gap;
	int left;
	int titleleft[IDD_MAX_TITLE - IDD_MIN_TITLE + 1];

	if (wparam == SIZE_MINIMIZED)
		return 0;

	GetClientRect(hwnd, &rdlg);
	cxdlg = LOWORD(lparam);
	cydlg = HIWORD(lparam);

	/*
	 * The ticket list title
	 */
	hwnditem = GetDlgItem(hwnd, IDD_TICKET_LIST_TITLE);

	if (hwnditem == NULL)
		return 0;

	windowrect(hwnditem, hwnd, &r);
	hmargin = r.left;
	vmargin = r.top;
	cx = cxdlg - 2 * hmargin;
	cy = r.bottom - r.top;
	MoveWindow(hwnditem, r.left, r.top, cx, cy, TRUE);

	/*
	 * The buttons
	 */
	cx = 0;

	for (i = IDD_MIN_BUTTON; i <= IDD_MAX_BUTTON; i++) {
		hwnditem = GetDlgItem(hwnd, i);
		windowrect(hwnditem, hwnd, &r);
		if (i == IDD_MIN_BUTTON)
			hmargin = r.left;

		cx += r.right - r.left;
	}

	gap = (cxdlg - 2 * hmargin - cx) / (IDD_MAX_BUTTON - IDD_MIN_BUTTON);
	left = hmargin;
	for (i = IDD_MIN_BUTTON; i <= IDD_MAX_BUTTON; i++) {
		hwnditem = GetDlgItem(hwnd, i);
		windowrect(hwnditem, hwnd, &r);
		editbottom = -r.top;
		cx = r.right - r.left;
		cy = r.bottom - r.top;
		r.top = rdlg.bottom - vmargin - cy;
		MoveWindow(hwnditem, left, r.top, cx, cy, TRUE);

		left += cx + gap;
	}

	/*
	 * Edit fields: stretch boxes, keeping the gap between boxes equal to
     * what it was on entry.
	 */
	editbottom += r.top;

    hwnditem = GetDlgItem(hwnd, IDD_MIN_EDIT);
    windowrect(hwnditem, hwnd, &r);
	gap = r.right;
	hmargin = r.left;
	editbottom += r.bottom;
	titlebottom = -r.top;

    hwnditem = GetDlgItem(hwnd, IDD_MIN_EDIT + 1);
    windowrect(hwnditem, hwnd, &r);
	gap = r.left - gap;

	cx = cxdlg - 2 * hmargin - (IDD_MAX_EDIT - IDD_MIN_EDIT) * gap;
	cx = cx / (IDD_MAX_EDIT - IDD_MIN_EDIT + 1);
	left = hmargin;

	for (i = IDD_MIN_EDIT; i <= IDD_MAX_EDIT; i++) {
		hwnditem = GetDlgItem(hwnd, i);
		windowrect(hwnditem, hwnd, &r);
		cy = r.bottom - r.top;
		r.top = editbottom - cy;
		MoveWindow(hwnditem, left, r.top, cx, cy, TRUE);
		titleleft[i-IDD_MIN_EDIT] = left;

		left += cx + gap;
	}

	/*
	 * Edit field titles
	 */
	titlebottom += r.top;
	windowrect(GetDlgItem(hwnd, IDD_MIN_TITLE), hwnd, &r);
	titlebottom += r.bottom;
	listbottom = -r.top;

	for (i = IDD_MIN_TITLE; i <= IDD_MAX_TITLE; i++) {
		hwnditem = GetDlgItem(hwnd, i);
		windowrect(hwnditem, hwnd, &r);
		cx = r.right - r.left;
		cy = r.bottom - r.top;
		r.top = titlebottom - cy;
		MoveWindow(hwnditem, titleleft[i-IDD_MIN_TITLE], r.top, cx, cy, TRUE);
	}

	/*
	 * The list
	 */
	listbottom = r.top - listgap;
	hwnditem = GetDlgItem(hwnd, IDD_TICKET_LIST);
	windowrect(hwnditem, hwnd, &r);
	hmargin = r.left;
	cx = cxdlg - 2 * hmargin;
	cy = listbottom - r.top;
	MoveWindow(hwnditem, r.left, r.top, cx, cy, TRUE);

	return 0;

} /* kwin_size */


/*+
 * Function: Process WM_GETMINMAXINFO messages
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - none.
 *
 *	lparam - LPMINMAXINFO
 *
 * Returns: 0
 */
static LONG
kwin_getminmaxinfo (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	MINMAXINFO *lpmmi;

	lpmmi = (MINMAXINFO *) lparam;
	lpmmi->ptMinTrackSize.x = (KWIN_MIN_WIDTH * LOWORD(GetDialogBaseUnits())) / 4;
	lpmmi->ptMinTrackSize.y = (KWIN_MIN_HEIGHT * HIWORD(GetDialogBaseUnits())) / 8;

	return 0;

} /*  kwin_getminmaxinfo */


/*+
 * Function: Process WM_TIMER messages
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - the timer id.
 * 
 *	lparam - timer callback proceedure
 *
 * Returns: 0
 */
static LONG
kwin_timer (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	HWND hwndfocus;
	time_t t;
	time_t expiration;
	BOOL expired;
    #ifdef KRB4
        CREDENTIALS c;
	    int ncred;
	    int i;
	    char service[ANAME_SZ];
	    char instance[INST_SZ];
	    char realm[REALM_SZ];
    #endif
    #ifdef KRB5
        krb5_error_code code;
        krb5_cc_cursor cursor;
        krb5_creds cred;
        int n;
        char *s;
    #endif

	if (wparam != 1)
		return DefDlgProc(hwnd, WM_TIMER, wparam, lparam);

	expired = FALSE;
	ticket_init_list(GetDlgItem(hwnd, IDD_TICKET_LIST));

	if (alerted) {
		if (IsIconic(hwnd))
			InvalidateRect(hwnd, NULL, TRUE);

		return 0;
	}

    #ifdef KRB4
	    ncred = krb_get_num_cred();
	    for (i = 1; i <= ncred; i++) {
		    krb_get_nth_cred(service, instance, realm, i);

		    if (_stricmp(service, "krbtgt") == 0) {
                /* Warn if ticket will expire w/i TIME_BUFFER seconds */
			    krb_get_cred(service, instance, realm, &c);
			    expiration = c.issue_date + (long) c.lifetime * 5L * 60L;
			    t = TIME_BUFFER + time(NULL);

			    if (t >= expiration) {
				    expired = TRUE;
                    /* Don't alert because of stale tickets */
				    if (t >= expiration + KWIN_UPDATE_PERIOD / 1000) {
					    alerted = TRUE;

					    if (IsIconic(hwnd))
						    InvalidateRect(hwnd, NULL, TRUE);
					    return 0;
				    }
				    break;
			    }
		    }
	    }
    #endif

    #ifdef KRB5
        code = krb5_cc_start_seq_get (k5_context, k5_ccache, &cursor);

        while (code == 0) {
            code = krb5_cc_next_cred(k5_context, k5_ccache, &cursor, &cred);
            if (code)
                break;
            n = krb5_princ_component(k5_context, cred.server, 0)->length;
            s = krb5_princ_component(k5_context, cred.server, 0)->data;
            if (n != KRB5_TGS_NAME_SIZE)
                continue;
            if (memcmp (KRB5_TGS_NAME, s, KRB5_TGS_NAME_SIZE))
                continue;

            /* Warn if ticket will expire w/i TIME_BUFFER seconds */
            expiration = cred.times.endtime;
            t = TIME_BUFFER + time(NULL);

            if (t >= expiration) {
                expired = TRUE;
                /* Don't alert because of stale tickets */
                if (t >= expiration + KWIN_UPDATE_PERIOD / 1000) {
                    alerted = TRUE;

                    if (IsIconic(hwnd))
                        InvalidateRect(hwnd, NULL, TRUE);
                    return 0;
                }
                break;
            }
        }
        if (code == 0 || code == KRB5_CC_END)
            krb5_cc_end_seq_get(k5_context, k5_ccache, &cursor);
    
    #endif

	if (!expired) {
		if (IsIconic(hwnd))
			InvalidateRect(hwnd, NULL, TRUE);

		return 0;
	}

	alerted = TRUE;

	if (beep)
		MessageBeep(MB_ICONEXCLAMATION);

	if (alert) {
		if (IsIconic(hwnd)) {
			hwndfocus = GetFocus();
			ShowWindow(hwnd, SW_RESTORE);
			SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0,
				SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOMOVE | SWP_NOSIZE);
			SetFocus(hwndfocus);
		}

		SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0,
			SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOMOVE | SWP_NOSIZE);

		return 0;
	}

    if (IsIconic(hwnd))
        InvalidateRect(hwnd, NULL, TRUE);

    return 0;

} /*  kwin_timer */


/*+
 * Function: Process WM_COMMAND messages
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - id of the command item
 *
 *	lparam - LOWORD=hwnd of control, HIWORD=notification message.
 *
 * Returns: TRUE if initialized sucessfully, false otherwise.
 */
static LONG
kwin_command (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
    char name[ANAME_SZ];
    char realm[REALM_SZ];
    char password[MAX_KPW_LEN];
	HCURSOR hcursor;
	BOOL blogin;
	HMENU hmenu;
	char menuitem[MAX_K_NAME_SZ + 3];
	char copyright[128];
	int id;
	#ifdef KRB4
        char instance[INST_SZ];
        int lifetime;
		int krc;
	#endif
	#ifdef KRB5
        long lifetime;
		krb5_error_code code;
        krb5_principal principal;
		krb5_creds creds;
		krb5_principal server;
        krb5_int32 sec, usec;
	#endif

	#ifdef KRB4
		EnableWindow(GetDlgItem(hwnd, IDD_TICKET_DELETE), krb_get_num_cred() > 0);
	#endif

	#ifdef KRB5
		EnableWindow(GetDlgItem(hwnd, IDD_TICKET_DELETE), k5_get_num_cred(0) > 0);
	#endif

	GetDlgItemText(hwnd, IDD_LOGIN_NAME, name, sizeof(name));
	trim(name);
	blogin = strlen(name) > 0;

	if (blogin) {
		GetDlgItemText(hwnd, IDD_LOGIN_REALM, realm, sizeof(realm));
		trim(realm);
		blogin = strlen(realm) > 0;
	}

	if (blogin) {
		GetDlgItemText(hwnd, IDD_LOGIN_PASSWORD, password, sizeof(password));
		blogin = strlen(password) > 0;
	}

	EnableWindow(GetDlgItem(hwnd, IDD_LOGIN), blogin);
    id = (blogin) ? IDD_LOGIN : IDD_PASSWORD_CR2;
    SendMessage(hwnd, DM_SETDEFID, id, 0);

	if (HIWORD(lparam) != BN_CLICKED && HIWORD(lparam) != 0 && HIWORD(lparam) != 1)
		return FALSE;

	if (wparam >= IDM_FIRST_LOGIN && wparam < IDM_FIRST_LOGIN + FILE_MENU_MAX_LOGINS) {
		hmenu = GetMenu(hwnd);
		assert(hmenu != NULL);

		hmenu = GetSubMenu(hmenu, 0);
		assert(hmenu != NULL);

		if (!GetMenuString(hmenu, wparam, menuitem, sizeof(menuitem), MF_BYCOMMAND))
			return TRUE;

		if (menuitem[0])
			kwin_init_name(hwnd, &menuitem[3]);

		return TRUE;
	}

	switch (wparam) {
	case IDM_EXIT:
		if (isblocking)
			WSACancelBlockingCall();
		WinHelp(hwnd, KERBEROS_HLP, HELP_QUIT, 0);
		PostQuitMessage(0);

		return TRUE;

    case IDD_PASSWORD_CR2:                      // Make CR == TAB
		id = GetDlgCtrlID(GetFocus());
		assert(id != 0);

		if (id == IDD_MAX_EDIT)
			PostMessage(hwnd, WM_NEXTDLGCTL,
				GetDlgItem(hwnd, IDD_MIN_EDIT), MAKELONG(1, 0));
		else
			PostMessage(hwnd, WM_NEXTDLGCTL, 0, 0);

        return TRUE;

	case IDD_LOGIN:
		if (isblocking)
			return TRUE;

		GetDlgItemText(hwnd, IDD_LOGIN_NAME, name, sizeof(name));
		trim(name);
		GetDlgItemText(hwnd, IDD_LOGIN_REALM, realm, sizeof(realm));
		trim(realm);
		GetDlgItemText(hwnd, IDD_LOGIN_PASSWORD, password, sizeof(password));
		trim(password);

        #ifdef KRB4
    		GetDlgItemText(hwnd, IDD_LOGIN_INSTANCE, instance, sizeof(instance));
	    	trim(instance);
        #endif

		hcursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
		lifetime = GetPrivateProfileInt(INI_OPTIONS, INI_DURATION,
			DEFAULT_TKT_LIFE * 5, KERBEROS_INI);
		start_blocking_hook(BLOCK_MAX_SEC);

		#ifdef KRB4
			lifetime = (lifetime + 4) / 5;
			krc = krb_get_pw_in_tkt(name, instance, realm, "krbtgt", realm,
				lifetime, password);
		#endif

		#ifdef KRB5
            do {
                principal = server = NULL;
	    		memset(&creds, 0, sizeof(creds));

                sprintf (menuitem, "%s@%s", name, realm);
                code = krb5_parse_name(k5_context, menuitem, &principal);
                if (code) break;

	    		code = krb5_cc_initialize(k5_context, k5_ccache, principal);
                if (code) break;

    			code = krb5_build_principal_ext(k5_context, &server,
	    			krb5_princ_realm(k5_context, principal)->length,
		    		krb5_princ_realm(k5_context, principal)->data,
                    KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
				    krb5_princ_realm(k5_context, principal)->length,
    				krb5_princ_realm(k5_context, principal)->data, 0);
                if (code) break;

		    	creds.client = principal;
	    		creds.server = server;

                code = krb5_us_timeofday(k5_context, &sec, &usec);
                if (code) break;
                creds.times.starttime = 0;
		creds.times.endtime = sec + 60L * lifetime;
		creds.times.renew_till = 0;
		
		/*
		 * XXX whether or not the credentials should be
		 * forwardable should be a configurable option in the
		 * UI.
		 */
		code = krb5_get_in_tkt_with_password(k5_context,
			     KDC_OPT_FORWARDABLE, NULL, NULL, NULL,
			     password, k5_ccache, &creds, 0);
            } while (0);

            if (principal)
                krb5_free_principal(k5_context, principal);
            if (server) 
    			krb5_free_principal(k5_context, server);

		#endif  /* KRB5 */

		end_blocking_hook();
		SetCursor(hcursor);
		kwin_set_default_focus(hwnd);

		#ifdef KRB4
			if (krc != KSUCCESS) {
				MessageBox(hwnd, krb_get_err_text(krc),	"",
					MB_OK | MB_ICONEXCLAMATION);

				return TRUE;
			}
		#endif

		#ifdef KRB5
			if (code) {
            	if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
                    MessageBox (hwnd, "Password incorrect", NULL, 
    					MB_OK | MB_ICONEXCLAMATION);
                else 
    				com_err (NULL, code, "while logging in");
				return TRUE;
			}
		#endif

		SetDlgItemText(hwnd, IDD_LOGIN_PASSWORD, "");
		kwin_save_name(hwnd);
		alerted = FALSE;

		switch (action) {
		case LOGIN_AND_EXIT:
			SendMessage(hwnd, WM_COMMAND, IDM_EXIT, 0);
			break;

		case LOGIN_AND_MINIMIZE:
			ShowWindow(hwnd, SW_MINIMIZE);
			break;
		}

		return TRUE;

	case IDD_TICKET_DELETE:
		if (isblocking)
			return TRUE;

		#ifdef KRB4
	    	krc = dest_tkt();
			if (krc != KSUCCESS)
				MessageBox(hwnd, krb_get_err_text(krc),	"",
					MB_OK | MB_ICONEXCLAMATION);
		#endif

		#ifdef KRB5
            code = k5_dest_tkt ();
		#endif

		kwin_set_default_focus(hwnd);
		alerted = FALSE;

		return TRUE;

	case IDD_CHANGE_PASSWORD:
		if (isblocking)
			return TRUE;
		password_dialog(hwnd);
		kwin_set_default_focus(hwnd);

		return TRUE;

	case IDM_OPTIONS:
		if (isblocking)
			return TRUE;
		opts_dialog(hwnd);

		return TRUE;

	case IDM_HELP_INDEX:
		WinHelp(hwnd, KERBEROS_HLP, HELP_INDEX, 0);

		return TRUE;

	case IDM_ABOUT:
    	ticket_init_list(GetDlgItem(hwnd, IDD_TICKET_LIST));
		if (isblocking)
			return TRUE;

        #ifdef KRB4
    		strcpy(copyright, "        Kerberos 4 for Windows\n");
        #endif
        #ifdef KRB5
    		strcpy(copyright, "        Kerberos 5 for Windows\n");
        #endif
		strcat(copyright, "\n                Version 1.00\n\n");
#ifdef CYGNUS
		strcat(copyright, "          For support, contact:\n");
		strcat(copyright, ORGANIZATION);
		strcat(copyright, " - (415) 903-1400");
#endif
		MessageBox(hwnd, copyright, "Kerberos", MB_OK);

		return TRUE;
	}

	return FALSE;

} /* kwin_command */


/*+
 * Function: Process WM_SYSCOMMAND messages by setting
 *	the focus to the password or name on restore.
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - the syscommand option.
 *
 *	lparam -
 *
 * Returns: 0
 */
static LONG
kwin_syscommand (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	if ((wparam & 0xFFF0) == SC_RESTORE)
		kwin_set_default_focus(hwnd);

	if ((wparam & 0xFFF0) == SC_CLOSE) {
		SendMessage(hwnd, WM_COMMAND, IDM_EXIT, 0);

		return 0;
	}

	return DefDlgProc(hwnd, WM_SYSCOMMAND, wparam, lparam);

} /* kwin_syscommand */


/*+
 * Function: Process WM_PAINT messages by displaying an
 *	informative icon when we are iconic.
 *
 * Parameters:
 *	hwnd - the window recieving the message.
 *
 *	wparam - none
 *
 *	lparam - none
 *
 * Returns: 0
 */
static LONG
kwin_paint (
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam)
{
	HDC hdc;
	PAINTSTRUCT ps;
	HICON hicon;
	time_t expiration = 0;
	time_t dt;
	char buf[20];
	RECT r;
	#ifdef KRB4
		int i;
		int ncred;
		char service[ANAME_SZ];
		char instance[INST_SZ];
		char realm[REALM_SZ];
		CREDENTIALS c;
	#endif
	#ifdef KRB5
        krb5_error_code code;
        krb5_cc_cursor cursor;
        krb5_creds c;
        int n;
        char *service;
	#endif

	if (!IsIconic(hwnd))
		return DefDlgProc(hwnd, WM_PAINT, wparam, lparam);

	#ifdef KRB4
		ncred = krb_get_num_cred();

		for (i = 1; i <= ncred; i++) {
			krb_get_nth_cred(service, instance, realm, i);
			krb_get_cred(service, instance, realm, &c);
			if (_stricmp(c.service, "krbtgt") == 0) {
				expiration = c.issue_date - kwin_get_epoch() + (long) c.lifetime * 5L * 60L;
				break;
			}
		}
	#endif

	#ifdef KRB5
        code = krb5_cc_start_seq_get (k5_context, k5_ccache, &cursor);

        while (code == 0) {
            code = krb5_cc_next_cred(k5_context, k5_ccache, &cursor, &c);
            if (code)
                break;
            n = krb5_princ_component(k5_context, c.server, 0)->length;
            service = krb5_princ_component(k5_context, c.server, 0)->data;
            if (n != KRB5_TGS_NAME_SIZE)
                continue;
            if (memcmp (KRB5_TGS_NAME, service, KRB5_TGS_NAME_SIZE))
                continue;
            expiration = c.times.endtime;
            break;
                
        }
        if (code == 0 || code == KRB5_CC_END)
            krb5_cc_end_seq_get(k5_context, k5_ccache, &cursor);
	#endif

	hdc = BeginPaint(hwnd, &ps);
	GetClientRect(hwnd, &r);
	DefWindowProc(hwnd, WM_ICONERASEBKGND, hdc, 0);

	if (expiration == 0) {
		strcpy(buf, KWIN_DIALOG_NAME);
		hicon = LoadIcon(hinstance, MAKEINTRESOURCE(IDI_KWIN));
	}
	else {
		hicon = kwin_get_icon(expiration);
		dt = (expiration - time(NULL)) / 60;

		if (dt <= 0)
			sprintf(buf, "%s - %s", KWIN_DIALOG_NAME, "Expired");
		else if (dt < 60) {
			dt %= 60;
			sprintf(buf, "%s - %ld min", KWIN_DIALOG_NAME, dt);
		}
		else {
			dt /= 60;
			sprintf(buf, "%s - %ld hr", KWIN_DIALOG_NAME, dt);
		}

		if (dt > 1)
			strcat(buf, "s");
	}

	DrawIcon(hdc, r.left, r.top, hicon);
	EndPaint(hwnd, &ps);
	SetWindowText(hwnd, buf);

	return 0;

} /* kwin_paint */


/*+
 * Function: Window proceedure for the Kerberos control panel dialog.
 *
 * Parameters:
 *	hwnd - the window receiving the message.
 *
 *	message - the message to process.
 *
 *	wparam - wparam of the message.
 *
 *	lparam - lparam of the message.
 *
 * Returns: message dependent value.
 */
LRESULT __export CALLBACK
kwin_wnd_proc (
	HWND hwnd,
	UINT message,
	WPARAM wparam,
	LPARAM lparam)
{
	LRESULT rc;
    int n;

	if (message == wm_kerberos_changed) {       /* Message from the ccache */
		n = ticket_init_list(GetDlgItem(hwnd, IDD_TICKET_LIST));
        EnableWindow(GetDlgItem(hwnd, IDD_TICKET_DELETE), n > 0);

		return 0;
	}

	switch (message) {
	case WM_GETMINMAXINFO:
		rc = kwin_getminmaxinfo(hwnd, wparam, lparam);
		return rc;

	case WM_DESTROY:
		rc = kwin_destroy(hwnd, wparam, lparam);
		return rc;

	case WM_MEASUREITEM:
		if (wparam == IDD_TICKET_LIST) {
			rc = ticket_measureitem(hwnd, wparam, lparam);
			return rc;
		}
		break;

	case WM_DRAWITEM:
		if (wparam == IDD_TICKET_LIST) {
			rc = ticket_drawitem(hwnd, wparam, lparam);
			return rc;
		}
		break;

	case WM_SETCURSOR:
		if (isblocking) {
			SetCursor(LoadCursor(NULL, IDC_WAIT));
			return TRUE;
		}
		break;

	case WM_SIZE:
		rc = kwin_size(hwnd, wparam, lparam);
		return rc;

	case WM_SYSCOMMAND:
		rc = kwin_syscommand(hwnd, wparam, lparam);
		return rc;

	case WM_TIMER:
		rc = kwin_timer(hwnd, wparam, lparam);
		return 0;

	case WM_PAINT:
		rc = kwin_paint(hwnd, wparam, lparam);
		return rc;

	case WM_ERASEBKGND:
		if (!IsIconic(hwnd))
			break;
		return 0;

	case WM_KWIN_SETNAME:
		kwin_init_name(hwnd, (char *) lparam);
	}

	return DefDlgProc(hwnd, message, wparam, lparam);

} /* kwin_wnd_proc */


/*+
 * Function: Dialog procedure called by the dialog manager
 *	to process dialog specific messages.
 *
 * Parameters:
 *	hwnd - the dialog receiving the message.
 *
 *	message - the message to process.
 *
 *	wparam - wparam of the message.
 *
 *	lparam - lparam of the message.
 *
 * Returns: TRUE if message handled locally, FALSE otherwise.
 */
static BOOL CALLBACK
kwin_dlg_proc (
	HWND hwnd,
	UINT message,
	WPARAM wparam,
	LPARAM lparam)
{
	LRESULT rc;

	switch (message) {
	case WM_INITDIALOG:
		return kwin_initdialog(hwnd, wparam, lparam);

	case WM_COMMAND:
		rc = kwin_command(hwnd, wparam, lparam);
		return TRUE;
	}

	return FALSE;

} /* kwin_dlg_proc */


/*+
 * Function: Initialize the kwin dialog class.
 *
 * Parameters:
 *	hinstance - the instance to initialize
 *
 * Returns: TRUE if dialog class registration is sucessfully, false otherwise.
 */
static BOOL
kwin_init (
	HINSTANCE hinstance)
{
	WNDCLASS class;
	ATOM rc;

	class.style = CS_HREDRAW | CS_VREDRAW;
	class.lpfnWndProc = (WNDPROC) kwin_wnd_proc;
	class.cbClsExtra = 0;
	class.cbWndExtra = DLGWINDOWEXTRA;
	class.hInstance = hinstance;
	class.hIcon = NULL;
//		LoadIcon(hinstance, MAKEINTRESOURCE(IDI_KWIN));
	class.hCursor = NULL;
	class.hbrBackground = NULL;
	class.lpszMenuName = NULL;
	class.lpszClassName = KWIN_DIALOG_CLASS;

	rc = RegisterClass (&class);
	assert(rc);

	return rc;

} /* kwin_init */


/*+
 * Function: Initialize the KWIN application.  This routine should
 *	only be called if no previous instance of the application
 *	exists.  Currently it only registers a class for the kwin
 *	dialog type.
 *
 * Parameters:
 *	hinstance - the instance to initialize
 *
 * Returns: TRUE if initialized sucessfully, false otherwise.
 */
static BOOL
init_application (
	HINSTANCE hinstance)
{
	BOOL rc;

	#ifdef KRB4
		wm_kerberos_changed = krb_get_notification_message();
	#endif

	#ifdef KRB5
		wm_kerberos_changed = krb5_get_notification_message();
	#endif

	rc = kwin_init(hinstance);

	return rc;

} /* init_application */


/*+
 * Function: Quits the KWIN application.  This routine should
 *	be called when the last application instance exits.
 *
 * Parameters:
 *	hinstance - the instance which is quitting.
 *
 * Returns: TRUE if initialized sucessfully, false otherwise.
 */
static BOOL
quit_application (
	HINSTANCE hinstance)
{
	return TRUE;
} /* quit_application */


/*+
 * Function: Initialize the current instance of the KWIN application.
 *
 * Parameters:
 *	hinstance - the instance to initialize
 *
 *	ncmdshow - show flag to indicate wheather to come up minimized
 *		or not.
 *
 * Returns: TRUE if initialized sucessfully, false otherwise.
 */
static BOOL
init_instance (
	HINSTANCE hinstance,
	int ncmdshow)
{
    WORD versionrequested;
    WSADATA wsadata;
    int rc;
	char buf[20];
	int i;

	versionrequested = 0x0101;			/* We need version 1.1 */
	rc = WSAStartup(versionrequested, &wsadata);
    if (rc != 0) {
		MessageBox(NULL, "Couldn't initialize Winsock library", "", MB_OK | MB_ICONSTOP);

		return FALSE;
	}

    if (versionrequested != wsadata.wVersion) {
		WSACleanup();
		MessageBox(NULL, "Winsock version 1.1 not available", "", MB_OK | MB_ICONSTOP);

		return FALSE;
    }

	/*
	 * Set up expiration action
	 */
	GetPrivateProfileString(INI_EXPIRATION, INI_ALERT, "No",
		buf, sizeof(buf), KERBEROS_INI);
	alert = _stricmp(buf, "Yes") == 0;
	GetPrivateProfileString(INI_EXPIRATION, INI_BEEP, "No",
		buf, sizeof(buf), KERBEROS_INI);
	beep = _stricmp(buf, "Yes") == 0;

	/*
	 * Load clock icons
	 */
	for (i = IDI_FIRST_CLOCK; i <= IDI_LAST_CLOCK; i++)
		kwin_icons[i - IDI_FIRST_CLOCK] = LoadIcon(hinstance, MAKEINTRESOURCE(i));

	#ifdef KRB4
	    krb_start_session(NULL);
	#endif

	#ifdef KRB5
        {
            krb5_error_code code;

    		code = krb5_init_context(&k5_context);
            if (! code) {
        		krb5_init_ets(k5_context);
        		code = k5_init_ccache (&k5_ccache);
            }
            if (code) {
                com_err (NULL, code, "while initializing program");
                return FALSE;
            }
            k5_name_from_ccache (k5_ccache);
        }
	#endif

	return TRUE;

} /* init_instance */


/*+
 * Function: Quits the current instance of the KWIN application.
 *
 * Parameters:
 *	hinstance - the instance to quit.
 *
 * Returns: TRUE if termination was sucessfully, false otherwise.
 */
static BOOL
quit_instance (
	HINSTANCE hinstance)
{
	int i;

	#ifdef KRB4
	    krb_end_session((char *) NULL);
	#endif

    #ifdef KRB5     /* FIXME */
        krb5_cc_close (k5_context, k5_ccache);
    #endif

	WSACleanup();

	/*
	 * Unload clock icons
	 */
	for (i = IDI_FIRST_CLOCK; i <= IDI_LAST_CLOCK; i++)
		DestroyIcon(kwin_icons[i - IDI_FIRST_CLOCK]);

	return TRUE;

} /* quit_instance */


/*+
 * Function: Main routine called on program invocation.
 *
 * Parameters:
 *	hinstance - the current instance
 *
 *	hprevinstance - previous instance if one exists or NULL.
 *
 *	cmdline - the command line string passed by Windows.
 *
 *	ncmdshow - show flag to indicate wheather to come up minimized
 *		or not.
 *
 * Returns: TRUE if initialized sucessfully, false otherwise.
 */
int PASCAL
WinMain (
	HINSTANCE hinst,
	HINSTANCE hprevinstance,
	LPSTR cmdline,
	int ncmdshow)
{
	DLGPROC dlgproc;
	HWND hwnd;
	HACCEL haccel;
	MSG msg;
	char *p;
	char buf[MAX_K_NAME_SZ + 9];
	char name[MAX_K_NAME_SZ];

	strcpy(buf, cmdline);
	action = LOGIN_AND_RUN;
	name[0] = 0;
	p = strtok(buf, " ,");

	while (p != NULL) {
	 	if (_stricmp(p, "/exit") == 0)
	 		action = LOGIN_AND_EXIT;
	 	else if (_stricmp(p, "/minimize") == 0)
	 		action = LOGIN_AND_MINIMIZE;
		else
			strcpy(name, p);

		p = strtok(NULL, " ,");
	}

	dlgncmdshow = ncmdshow;
	hinstance = hinst;

	/*
	 * If a previous instance of this application exits, bring it
	 * to the front and exit.
	 */
	if (hprevinstance != NULL) {
		hwnd = FindWindow(KWIN_DIALOG_CLASS, NULL);

		if (IsWindow(hwnd) && IsWindowVisible(hwnd)) {
			if (GetWindowWord(hwnd, GWW_HINSTANCE) == hprevinstance) {
				if (name[0])
					SendMessage(hwnd, WM_KWIN_SETNAME, 0, (LONG) name);

                ShowWindow(hwnd, ncmdshow);
				SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0,
					SWP_SHOWWINDOW | SWP_NOMOVE | SWP_NOSIZE);

				return FALSE;
			}
		}
	}

	if (hprevinstance == NULL)
		if (!init_application(hinstance))
			return FALSE;

	if (!init_instance(hinstance, ncmdshow))
		return FALSE;

	dlgproc = (FARPROC) MakeProcInstance(kwin_dlg_proc, hinstance);
	assert(dlgproc != NULL);

	if (dlgproc == NULL)
		return 1;

	hwnd = CreateDialogParam(hinstance, MAKEINTRESOURCE (ID_KWIN),
				HWND_DESKTOP, dlgproc, (LONG) name);
	assert(hwnd != NULL);

	if (hwnd == NULL)
		return 1;
	haccel = LoadAccelerators(hinstance, MAKEINTRESOURCE(IDA_KWIN));
	assert(hwnd != NULL);

    while (GetMessage(&msg, NULL, 0, 0)) {
		if (!TranslateAccelerator(hwnd, haccel, &msg) &&
			!IsDialogMessage(hwnd, &msg)) {
    		TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	DestroyWindow(hwnd);
	FreeProcInstance((FARPROC) dlgproc);

	return 0;

} /* WinMain */


#if 0

	#define WM_ASYNC_COMPLETED (WM_USER + 1)
	#define GETHOSTBYNAME_CLASS "krb_gethostbyname"
	static HTASK htaskasync;			/* Asynchronos call in progress */
	static BOOL iscompleted;			/* True when async call is completed */

	/*
 	* This routine is called to cancel a blocking hook call within
 	* the Kerberos library.  The need for this routine arises due
 	* to bugs which exist in existing WINSOCK implementations.  We
 	* blocking gethostbyname with WSAASyncGetHostByName.  In order
 	* to cancel such an operation, this routine must be called.
 	* Applications may call this routine in addition to calls to
 	* WSACancelBlockingCall to get any sucy Async calls canceled.
 	* Return values are as they would be for WSACancelAsyncRequest.
 	*/
	int
	krb_cancel_blocking_call(void)
	{
		if (htaskasync == NULL)
			return 0;
		iscompleted = TRUE;

		return WSACancelAsyncRequest(htask);

	} /* krb_cancel_blocking_call */


	/*
 	* Window proceedure for temporary Windows created in
 	* krb_gethostbyname.  Fields completion messages.
 	*/
	LRESULT __export CALLBACK krb_gethostbyname_wnd_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam)
	{
		if (message == WM_ASYNC_COMPLETED) {
			iscompleted = TRUE;
			return 0;
		}

		return DefWindowProc(hwnd, message, wparam, lparam);

	} /* krb_gethostbyname_wnd_proc */


	/*
 	* The WINSOCK routine gethostbyname has a bug in both FTP and NetManage
 	* implementations which causes the blocking hook, if any, not to be
 	* called.  This routine attempts to work around the problem by using
 	* the async routines to emulate the functionality of the synchronous
 	* routines
 	*/
	struct hostent FAR *PASCAL FAR
	krb_gethostbyname(
		const char FAR *name)
	{
		HWND hwnd;
		char buf[MAXGETHOSTSTRUCT];
		BOOL FARPROC blockinghook;
		WNDCLASS wc;
		static BOOL isregistered;

		blockinghook = WSASetBlockingHook(NULL);
		WSASetBlockingHook(blockinghook);

		if (blockinghook == NULL)
			return gethostbyname(name);

		if (RegisterWndClass() == NULL)
			return gethostbyname(name);

		if (!isregistered) {
			wc.style = 0;
			wc.lpfnWndProc = gethostbyname_wnd_proc;
			wc.cbClsExtra = 0;
			wc.cbWndExtra = 0;
			wc.hInstance = hlibinstance;
			wc.hIcon = NULL;
			wc.hCursor = NULL;
			wc.hbrBackground = NULL;
			wc.lpszMenuName  = NULL;
			wc.lpszClassName = GETHOSTBYNAME_CLASS;

			if (!RegisterClass(&wc))
				return gethostbyname(name);

			isregistered = TRUE;
		}

		hwnd = CreateWindow(GETHOSTBYNAME_CLASS, "", WS_OVERLAPPED,
			-100, -100, 0, 0, HWND_DESKTOP, NULL, hlibinstance, NULL);
		if (hwnd == NULL)
			return gethostbyname(name);

		htaskasync =
			WSAAsyncGetHostByName(hwnd, WM_ASYNC_COMPLETED, name, buf, sizeof(buf));
		b = blockinghook(NULL);

	} /* krb_gethostbyname */

#endif

#ifdef KRB5

/*+
 * Function: destroys all tickets in a k5 ccache
 *
 * Parameters:
 *  none
 *
 * Returns: K5 error code (0 == success)
 */
static krb5_error_code
k5_dest_tkt (void) {
    krb5_error_code code;
    krb5_principal princ;

    if (code = krb5_cc_get_principal(k5_context, k5_ccache, &princ)) {
        com_err (NULL, code, "while retrieving principal name");
        return code;
    }

    code = krb5_cc_initialize (k5_context, k5_ccache, princ);
    if (code != 0) {
        com_err (NULL, code, "when re-initializing cache");
        krb5_free_principal (k5_context, princ);
        return code;
    }

    krb5_free_principal (k5_context, princ);
    return code;
}

/*+
 * 
 * k5_get_num_cred
 * 
 * Returns: number of creds in the credential cache, -1 on error
 * 
 */
static int
k5_get_num_cred (int verbose) {
    krb5_error_code code;
    krb5_cc_cursor cursor;
    krb5_creds c;
    int ncreds = 0;

    /* Turn off OPENCLOSE and leave open while we use ccache */
    if (code = krb5_cc_set_flags(k5_context, k5_ccache, 0)) {
        if (code == KRB5_FCC_NOFILE)
            return 0;
        if (verbose)
            com_err (NULL, code,
                "while setting cache flags (ticket cache %s)",
                krb5_cc_get_name(k5_context, k5_ccache));
        return -1;
    }

    if (code = krb5_cc_start_seq_get(k5_context, k5_ccache, &cursor)) {
        if (verbose)
            com_err (NULL, code, "while starting to retrieve tickets.");
        return -1;
    }

    while (1) {                                 /* Loop and get creds */
        code = krb5_cc_next_cred(k5_context, k5_ccache, &cursor, &c);
        if (code)
            break;
        ++ncreds;
    }

    if (code != KRB5_CC_END) {                  /* Error while looping??? */
        if (verbose)
            com_err (NULL, code, "while retrieving a ticket.");
        return -1;
    }

    if (code = krb5_cc_end_seq_get(k5_context, k5_ccache, &cursor)) {
        if (verbose)
            com_err (NULL, code, "while closing ccache.");
    } else if (code = krb5_cc_set_flags(k5_context, k5_ccache, KRB5_TC_OPENCLOSE)) {
        if (verbose)
            com_err(NULL, code, "while closing ccache.");
    }

    return ncreds;
}

static int
k5_get_num_cred2 () {
    krb5_error_code code;
    krb5_cc_cursor cursor;
    krb5_creds c;
    int ncreds = 0;

    code = krb5_cc_start_seq_get (k5_context, k5_ccache, &cursor);
    if (code == KRB5_FCC_NOFILE)
        return 0;

    while (1) {
        code = krb5_cc_next_cred(k5_context, k5_ccache, &cursor, &c);
        if (code)
            break;
        ++ncreds;
    }
    if (code == KRB5_CC_END)
        krb5_cc_end_seq_get(k5_context, k5_ccache, &cursor);

    return ncreds;
}

/*+
 * Function: Parses fullname into name, instance and realm
 *
 * Parameters:
 *  name - buffer filled with name of user
 *
 *  realm - buffer filled with realm of user
 *
 *  fullname - string in form name.instance@realm
 *
 * Returns: 0
 */
static int
k5_kname_parse (char *name, char *realm, char *fullname) {
    char *ptr;                                  /* For parsing */

    ptr = strchr (fullname, '@');               /* Name, realm separator */

    if (ptr != NULL)                            /* Get realm */
        strcpy (realm, ptr + 1);
    else
        *realm = '\0';

    if (ptr != NULL) {                          /* Get the name */
        strncpy (name, fullname, ptr - fullname);
        name[ptr - fullname] = '\0';
    } else
        strcpy (name, fullname);

    ptr = strchr (name, '.');                   /* K4 compatability */
    if (ptr != NULL)
        *ptr = '\0';

    return 0;
}
/*+
 * Function: Initializes ccache and catches illegal caches such as
 *  bad format or no permissions.
 *
 * Parameters:
 *  ccache - credential cache structure to use
 *
 * Returns: krb5_error_code
 */
static krb5_error_code
k5_init_ccache (krb5_ccache *ccache) {
    krb5_error_code code;
    krb5_principal princ;
    FILE *fp;

    code = krb5_cc_default (k5_context, ccache); // Initialize the ccache
    if (code)
        return code;

    code = krb5_cc_get_principal (k5_context, *ccache, &princ);
    if (code == KRB5_FCC_NOFILE) {              // Doesn't exist yet
        fp = fopen (krb5_cc_get_name(k5_context, *ccache), "w");
        if (fp == NULL)                         // Can't open it
            return KRB5_FCC_PERM;
        fclose (fp);
    }

    if (code) {                                 // Bad, delete and try again
        remove (krb5_cc_get_name(k5_context, *ccache));
        code = krb5_cc_get_principal (k5_context, *ccache, &princ);
        if (code == KRB5_FCC_NOFILE)            // Doesn't exist yet
            return 0;
        if (code)
            return code;
    }

    krb5_free_principal (k5_context, princ);
    return 0;
}
/*+
 * 
 * Function: Reads the name and realm out of the ccache.
 * 
 * Parameters:
 *  ccache - credentials cache to get info from
 * 
 *  name - buffer to hold user name
 * 
 *  realm - buffer to hold the realm
 * 
 * 
 * Returns: TRUE if read names, FALSE if not
 * 
 */
static int
k5_name_from_ccache (krb5_ccache k5_ccache) {
    krb5_error_code code;
    krb5_principal princ;
	char name[ANAME_SZ];
	char realm[REALM_SZ];
    char *defname;

    if (code = krb5_cc_get_principal(k5_context, k5_ccache, &princ))
        return FALSE;

    code = krb5_unparse_name(k5_context, princ, &defname);
    if (code) {
        krb5_free_principal (k5_context, princ);
        return FALSE;
    }

    k5_kname_parse(name, realm, defname);       // Extract the components
    WritePrivateProfileString(INI_DEFAULTS, INI_USER, name, KERBEROS_INI);
	WritePrivateProfileString(INI_DEFAULTS, INI_REALM, realm, KERBEROS_INI);

    krb5_free_principal(k5_context, princ);
    free (defname);

    return TRUE;
}
#endif /* KRB5 */
