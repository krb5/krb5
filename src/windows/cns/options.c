/*
 * Copyright 1994 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

/*
 * functions to tweak the options dialog
 */

#include <windows.h>
#include <windowsx.h>

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <ctype.h>
#include <time.h>

#include "cns.h"

char confname[FILENAME_MAX];
char ccname[FILENAME_MAX];

/*
 * Function: Process WM_INITDIALOG messages for the options dialog.
 * 	Set up all initial dialog values from the KERBEROS_INI file.
 *
 * Returns: TRUE if we didn't set the focus here,
 * 	    FALSE if we did.
 */
BOOL
opts_initdialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
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
  strcat(wdir, "\\");

  /* krb.conf file */
  strcpy(defname, wdir);
  strcat(defname, DEF_KRB_CONF);
  GetPrivateProfileString(INI_FILES, INI_KRB_CONF, defname,
			  confname, sizeof(confname), KERBEROS_INI);
#ifndef _WIN32
  _strupr(confname);
#endif
  SetDlgItemText(hwnd, IDD_CONF, confname);
	
#ifdef KRB4
  /* krb.realms file */
  strcpy(defname, wdir);
  strcat(defname, DEF_KRB_REALMS);
  GetPrivateProfileString(INI_FILES, INI_KRB_REALMS, defname,
			  newname, sizeof(newname), KERBEROS_INI);
#ifndef _WIN32
  _strupr(newname);
#endif
  SetDlgItemText(hwnd, IDD_REALMS, newname);
#endif /* KRB4 */

#ifdef KRB5
  /* Credential cache file */
  strcpy(defname, wdir);
  strcat(defname, INI_KRB_CCACHE);
  GetPrivateProfileString(INI_FILES, INI_KRB_CCACHE, defname,
			  ccname, sizeof(ccname), KERBEROS_INI);
#ifndef _WIN32
  _strupr(ccname);
#endif
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

#ifdef KRB5
  GetPrivateProfileString(INI_TICKETOPTS, INI_FORWARDABLE, "No",
			  defname, sizeof(defname), KERBEROS_INI);
  forwardable = _stricmp(defname, "Yes") == 0;
  SendDlgItemMessage(hwnd, IDD_FORWARDABLE, BM_SETCHECK, forwardable, 0);
#endif

  return TRUE;
}


/*
 * Function: Process WM_COMMAND messages for the options dialog.
 */
void
opts_command(HWND hwnd, int cid, HWND hwndCtl, UINT codeNotify)
{
  char wdir[FILENAME_MAX];
  char defname[FILENAME_MAX];
  char newname[FILENAME_MAX];
  char *p;
  BOOL b;
  int lifetime;
  int rc;

  switch (cid) {
  case IDOK:
    rc = GetWindowsDirectory(wdir, sizeof(wdir));
    assert(rc > 0);
    strcat(wdir, "\\");

    /* Ticket duration */
    lifetime = GetDlgItemInt(hwnd, IDD_LIFETIME, &b, FALSE);

    if (!b) {
      MessageBox(hwnd, "Lifetime must be a number!", "",
		 MB_OK | MB_ICONEXCLAMATION);
      return; /* TRUE */
    }

    _itoa(lifetime, defname, 10);
    b = WritePrivateProfileString(INI_OPTIONS, INI_DURATION,
				  defname, KERBEROS_INI);
    assert(b);

    /* krb.conf file */
    GetDlgItemText(hwnd, IDD_CONF, newname, sizeof(newname));
    trim(newname);
    if (_stricmp(newname, confname)) {  /* file name changed */
      MessageBox(NULL,
		 "Change to configuration file location requires a restart"
		 "of KerbNet.\n"
		 "Please exit this application and restart this application",
		 "", MB_OK | MB_ICONEXCLAMATION);
    }
    strcpy(defname, wdir);
    strcat(defname, DEF_KRB_CONF);
    p = (*newname && _stricmp(newname, defname)) ? newname : NULL;
    if (p)
      strcpy(confname, p);
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
    if (*newname == '\0')		/* For detecting name change */
      strcpy(newname, defname);
    p = (*newname && _stricmp(newname, defname)) ? newname : NULL;
    b = WritePrivateProfileString(INI_FILES, INI_KRB_CCACHE, p, KERBEROS_INI);
    assert(b);

    if (_stricmp(ccname, newname)) {     /* Did we change ccache file? */
      krb5_error_code code;
      krb5_ccache cctemp;

      code = k5_init_ccache(&cctemp);
      if (code) {                     /* Problem opening new one? */
	com_err(NULL, code, 
		"while changing ccache.\r\nRestoring old ccache.");
	b = WritePrivateProfileString(INI_FILES, INI_KRB_CCACHE,
				      ccname, KERBEROS_INI);
      } else {
	code = krb5_cc_close(k5_context, k5_ccache);
	k5_ccache = cctemp;         /* Copy new into old */
	if (k5_name_from_ccache(k5_ccache)) {
	  kwin_init_name(GetParent(hwnd), "");
	  kwin_set_default_focus(GetParent(hwnd));
	}
	ticket_init_list(GetDlgItem (GetParent(hwnd),
				     IDD_TICKET_LIST));
      }
    }
#endif /* KRB5 */

    /* Expiration action */
    alert = (BOOL)SendDlgItemMessage(hwnd, IDD_ALERT, BM_GETCHECK, 0, 0);
    p = (alert) ? "Yes" : "No";
    b = WritePrivateProfileString(INI_EXPIRATION, INI_ALERT, p, KERBEROS_INI);
    assert(b);

    beep = (BOOL)SendDlgItemMessage(hwnd, IDD_BEEP, BM_GETCHECK, 0, 0);
    p = (beep) ? "Yes" : "No";
    b = WritePrivateProfileString(INI_EXPIRATION, INI_BEEP, p, KERBEROS_INI);
    assert(b);

#ifdef KRB5
    forwardable = (BOOL)SendDlgItemMessage(hwnd, IDD_FORWARDABLE,
					   BM_GETCHECK, 0, 0);
    p = (forwardable) ? "Yes" : "No";
    b = WritePrivateProfileString(INI_TICKETOPTS, INI_FORWARDABLE,
				  p, KERBEROS_INI);
    assert(b);
#endif

    EndDialog(hwnd, IDOK);

    return; /* TRUE */

  case IDCANCEL:
    EndDialog(hwnd, IDCANCEL);

    return; /* TRUE */
  }

  return; /* FALSE */
}


/*
 * Function: Process dialog specific messages for the opts dialog.
 */
BOOL CALLBACK
opts_dlg_proc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
  switch (message) {
    HANDLE_MSG(hwnd, WM_INITDIALOG, opts_initdialog);

    HANDLE_MSG(hwnd, WM_COMMAND, opts_command);
  }

  return FALSE;
}


/*
 * Function: Display and process the options dialog.
 *
 * Parameters:
 *	hwnd - the parent window for the dialog
 *
 * Returns: TRUE if the dialog completed successfully, FALSE otherwise.
 */
BOOL
opts_dialog(HWND hwnd)
{
  DLGPROC dlgproc;
  int rc;

#ifdef _WIN32
  dlgproc = opts_dlg_proc;
#else
  dlgproc = (FARPROC)MakeProcInstance(opts_dlg_proc, hinstance);
  assert(dlgproc != NULL);

  if (dlgproc == NULL)
    return FALSE;
#endif

  rc = DialogBox(hinstance, MAKEINTRESOURCE(ID_OPTS), hwnd, dlgproc);
  assert(rc != -1);

#ifndef _WIN32
  FreeProcInstance((FARPROC)dlgproc);
#endif

  return rc == IDOK;
}
