/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#include<shlwapi.h>
#include<khmapp.h>
#include<assert.h>

typedef struct tag_cfg_data {
    BOOL auto_init;
    BOOL auto_start;
    BOOL auto_import;
    BOOL keep_running;
    BOOL auto_detect_net;
    BOOL log_to_file;
    BOOL destroy_creds;
    khm_int32 notif_action;
} cfg_data;

typedef struct tag_dlg_data {
    khui_config_node node;
    cfg_data saved;
    cfg_data work;
} dlg_data;

static void
read_params(dlg_data * dd) {
    cfg_data * d;
    khm_handle csp_cw;
    khm_int32 t;

    d = &dd->saved;

    if (KHM_FAILED(khc_open_space(NULL, L"CredWindow", KHM_PERM_READ,
                                  &csp_cw))) {
#ifdef DEBUG
        assert(FALSE);
#endif
        return;
    }

    khc_read_int32(csp_cw, L"AutoInit", &t);
    d->auto_init = !!t;

    khc_read_int32(csp_cw, L"AutoStart", &t);
    d->auto_start = !!t;

    khc_read_int32(csp_cw, L"AutoImport", &t);
    d->auto_import = !!t;

    khc_read_int32(csp_cw, L"KeepRunning", &t);
    d->keep_running = !!t;

    khc_read_int32(csp_cw, L"AutoDetectNet", &t);
    d->auto_detect_net = !!t;

    khc_read_int32(csp_cw, L"LogToFile", &t);
    d->log_to_file = !!t;

    khc_read_int32(csp_cw, L"DestroyCredsOnExit", &t);
    d->destroy_creds = !!t;

    khc_read_int32(csp_cw, L"NotificationAction", &t);
    d->notif_action = t;

    khc_close_space(csp_cw);

    dd->work = *d;
}

static void
write_params(dlg_data * dd) {
    cfg_data * d, * s;
    khm_handle csp_cw;
    BOOL applied = FALSE;

    d = &dd->work;
    s = &dd->saved;

    if (KHM_FAILED(khc_open_space(NULL, L"CredWindow", KHM_PERM_WRITE,
                                  &csp_cw))) {
#ifdef DEBUG
        assert(FALSE);
#endif
        return;
    }

    if (!!d->auto_init != !!s->auto_init) {
        khc_write_int32(csp_cw, L"AutoInit", d->auto_init);
        applied = TRUE;
    }

    if (!!d->auto_start != !!s->auto_start) {
        khc_write_int32(csp_cw, L"AutoStart", d->auto_start);
        applied = TRUE;
    }

    if (!!d->auto_import != !!s->auto_import) {
        khc_write_int32(csp_cw, L"AutoImport", d->auto_import);
        applied = TRUE;
    }

    if (!!d->keep_running != !!s->keep_running) {
        khc_write_int32(csp_cw, L"KeepRunning", d->keep_running);
        applied = TRUE;
    }

    if (!!d->auto_detect_net != !!s->auto_detect_net) {
        khc_write_int32(csp_cw, L"AutoDetectNet", d->auto_detect_net);
        applied = TRUE;
    }

    if (!!d->log_to_file != !!s->log_to_file) {
	khc_write_int32(csp_cw, L"LogToFile", d->log_to_file);
	applied = TRUE;

	if (d->log_to_file) {
	    khm_start_file_log();
	} else {
	    khm_stop_file_log();
	}
    }

    if (!!d->destroy_creds != !!s->destroy_creds) {
        khc_write_int32(csp_cw, L"DestroyCredsOnExit", d->destroy_creds);
        applied = TRUE;
    }

    if (d->notif_action != s->notif_action) {
        khc_write_int32(csp_cw, L"NotificationAction", d->notif_action);
        applied = TRUE;
    }

    khc_close_space(csp_cw);

    khui_cfg_set_flags(dd->node,
                       (applied) ? KHUI_CNFLAG_APPLIED : 0,
                       KHUI_CNFLAG_APPLIED | KHUI_CNFLAG_MODIFIED);

    *s = *d;
}

static void
check_for_modification(dlg_data * dd) {
    cfg_data * d, * s;
    d = &dd->work;
    s = &dd->saved;

    if (!!d->auto_init != !!s->auto_init ||
        !!d->auto_start != !!s->auto_start ||
        !!d->auto_import != !!s->auto_import ||
        !!d->keep_running != !!s->keep_running ||
        !!d->auto_detect_net != !!s->auto_detect_net ||
	!!d->log_to_file != !!s->log_to_file ||
        !!d->destroy_creds != !!s->destroy_creds ||
        d->notif_action != s->notif_action) {

        khui_cfg_set_flags(dd->node,
                           KHUI_CNFLAG_MODIFIED,
                           KHUI_CNFLAG_MODIFIED);

    } else {

        khui_cfg_set_flags(dd->node,
                           0,
                           KHUI_CNFLAG_MODIFIED);

    }
}


static void
strip_ampersands(wchar_t * str) {
    wchar_t *f, *t;

    for(f = t = str; *f; f++)
        if (*f != L'&')
            *t++ = *f;

    *t = L'\0';
}

static void
refresh_view(HWND hwnd, dlg_data * d) {
    wchar_t buf[512];
    khm_size i;

    CheckDlgButton(hwnd, IDC_CFG_AUTOINIT,
                   (d->work.auto_init?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_CFG_AUTOSTART,
                   (d->work.auto_start?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_CFG_AUTOIMPORT,
                   (d->work.auto_import?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_CFG_KEEPRUNNING,
                   (d->work.keep_running?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_CFG_NETDETECT,
                   (d->work.auto_detect_net?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_CFG_LOGTOFILE,
		   (d->work.log_to_file?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_CFG_DESTROYALL,
                   (d->work.destroy_creds?BST_CHECKED:BST_UNCHECKED));

    /* we need populate the notification action combo box control and
       set the current selection to match the default action. */

    if (n_khm_notifier_actions != (khm_size) SendDlgItemMessage(hwnd, IDC_CFG_NOTACTION,
                                                                CB_GETCOUNT, 0, 0)) {

        for (i=0; i < n_khm_notifier_actions; i++) {
            int idx;

            khm_get_action_caption(khm_notifier_actions[i],
                                   buf, sizeof(buf));

            strip_ampersands(buf);

            idx = (int) SendDlgItemMessage(hwnd, IDC_CFG_NOTACTION,
                                           CB_INSERTSTRING, i,
                                           (LPARAM) buf);

#ifdef DEBUG
            if (idx != (int) i) {
                assert(FALSE);
            }
#endif
        }
    }

    for (i=0; i < n_khm_notifier_actions; i++) {
        if (khm_notifier_actions[i] == d->work.notif_action)
            break;
    }

    if (i >= n_khm_notifier_actions) {
        d->work.notif_action = khm_notifier_actions[0];
        i = 0;
    }

    SendDlgItemMessage(hwnd, IDC_CFG_NOTACTION, CB_SETCURSEL, i, 0);

    /* in addition, we correct the label on the trace log control to
       reflect the actual path that is going to get used */
    if (GetDlgItemText(hwnd, IDC_CFG_LOGPATH, buf,
		       ARRAYLENGTH(buf)) == 0) {

	khm_get_file_log_path(sizeof(buf), buf);

	SetDlgItemText(hwnd, IDC_CFG_LOGPATH, buf);
    }
}

static void
refresh_data(HWND hwnd, dlg_data * d) {
    int idx;

    d->work.auto_init = (IsDlgButtonChecked(hwnd, IDC_CFG_AUTOINIT)
                         == BST_CHECKED);
    d->work.auto_start = (IsDlgButtonChecked(hwnd, IDC_CFG_AUTOSTART)
                          == BST_CHECKED);
    d->work.auto_import = (IsDlgButtonChecked(hwnd, IDC_CFG_AUTOIMPORT)
                           == BST_CHECKED);
    d->work.keep_running = (IsDlgButtonChecked(hwnd, IDC_CFG_KEEPRUNNING)
                            == BST_CHECKED);
    d->work.auto_detect_net = (IsDlgButtonChecked(hwnd, IDC_CFG_NETDETECT)
                               == BST_CHECKED);
    d->work.log_to_file = (IsDlgButtonChecked(hwnd, IDC_CFG_LOGTOFILE)
			   == BST_CHECKED);
    d->work.destroy_creds = (IsDlgButtonChecked(hwnd, IDC_CFG_DESTROYALL)
                             == BST_CHECKED);

    idx = (int) SendDlgItemMessage(hwnd, IDC_CFG_NOTACTION, CB_GETCURSEL, 0, 0);
    if (idx < 0)
        idx = 0;
    else if (idx >= (int) n_khm_notifier_actions)
        idx = (int) n_khm_notifier_actions - 1;

    d->work.notif_action = khm_notifier_actions[idx];
}

INT_PTR CALLBACK
khm_cfg_general_proc(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam) {
    dlg_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        d = PMALLOC(sizeof(*d));
#ifdef DEBUG
        assert(d != NULL);
#endif

#pragma warning(push)
#pragma warning(disable: 4244)
        SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

        ZeroMemory(d, sizeof(*d));

        d->node = (khui_config_node) lParam;

        read_params(d);

        refresh_view(hwnd, d);

        return FALSE;

    case WM_DESTROY:
        d = (dlg_data *) (DWORD_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
        if (d) {
            PFREE(d);
            SetWindowLongPtr(hwnd, DWLP_USER, 0);
        }
        return TRUE;

    case WM_COMMAND:
        d = (dlg_data *) (DWORD_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            return FALSE;

        if (HIWORD(wParam) == BN_CLICKED) {
            if (LOWORD(wParam) == IDC_CFG_SHOWLOG) {
                /* we need to display the logfile */
                wchar_t buf[512];

                buf[0] = L'\0';
                khm_get_file_log_path(sizeof(buf), buf);

                if (!buf[0] ||
                    !PathFileExists(buf)) {

                    wchar_t title[256];
                    wchar_t msg[550];
                    wchar_t fmt[256];

                    LoadString(khm_hInstance, IDS_CFG_LOGF_CS,
                               title, ARRAYLENGTH(title));
                    LoadString(khm_hInstance, IDS_CFG_LOGF_CSR,
                               fmt, ARRAYLENGTH(fmt));

                    StringCbPrintf(msg, sizeof(msg), fmt, buf);

                    MessageBox(hwnd, title, msg, MB_OK);

                } else {
                    wchar_t cmdline[550];
                    STARTUPINFO si;
                    PROCESS_INFORMATION pi;

                    StringCbCopy(cmdline, sizeof(cmdline), L"notepad.exe ");
                    StringCbCat(cmdline, sizeof(cmdline), L"\"");
                    StringCbCat(cmdline, sizeof(cmdline), buf);
                    StringCbCat(cmdline, sizeof(cmdline), L"\"");

                    ZeroMemory(&si, sizeof(si));
                    si.cb = sizeof(si);
                    ZeroMemory(&pi, sizeof(pi));

                    CreateProcess(NULL,
                                  cmdline,
                                  NULL, NULL,
                                  FALSE,
                                  0, NULL, NULL,
                                  &si,
                                  &pi);

                    if (pi.hProcess)
                        CloseHandle(pi.hProcess);
                    if (pi.hThread)
                        CloseHandle(pi.hThread);

                }
            } else {
                refresh_data(hwnd, d);
                check_for_modification(d);
            }
        } else if (HIWORD(wParam) == CBN_SELCHANGE) {
            refresh_data(hwnd, d);
            check_for_modification(d);
        }

        khm_set_dialog_result(hwnd, 0);

        return TRUE;

    case KHUI_WM_CFG_NOTIFY:
        d = (dlg_data *) (DWORD_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            return FALSE;

        if (HIWORD(wParam) == WMCFG_APPLY) {
            write_params(d);
        }

        khm_set_dialog_result(hwnd, 0);

        return TRUE;
    }

    return FALSE;
}
