/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 * Copyright (c) 2007 Secure Endpoints Inc.
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

/* Include the OEMRESOURCE constants for locating standard icon
   resources. */
#define OEMRESOURCE

#include<khmapp.h>
#if _WIN32_WINNT >= 0x0501
#include<uxtheme.h>
#endif
#include<assert.h>

ATOM khui_newcredwnd_cls;

/* forward dcl */
static void
nc_position_credtext(khui_nc_wnd_data * d);

/* Common dialog procedure used by the main credential panel
   (IDD_NC_NEWCRED) and the button bar (IDC_NC_BBAR). */

static void
nc_layout_main_panel(khui_nc_wnd_data * d);

static void
nc_layout_new_cred_window(khui_nc_wnd_data * d);

static INT_PTR CALLBACK 
nc_common_dlg_proc(HWND hwnd,
                   UINT uMsg,
                   WPARAM wParam,
                   LPARAM lParam)
{
    switch(uMsg) {
    case WM_INITDIALOG:
        {
            khui_nc_wnd_data * d;

            d = (khui_nc_wnd_data *) lParam;

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, lParam);
#pragma warning(pop)

            if (d->nc->subtype == KMSG_CRED_PASSWORD) {
                ShowWindow(GetDlgItem(hwnd, IDC_NC_ADVANCED),
                           SW_HIDE);
            }
        }
        return TRUE;

    case WM_COMMAND:
        {
            int ctrl_id;

            ctrl_id = LOWORD(wParam);
            if (ctrl_id < KHUI_CW_ID_MIN ||
                ctrl_id > KHUI_CW_ID_MAX) {
                /* pump it to the parent */
                PostMessage(GetParent(hwnd), WM_COMMAND, wParam, lParam);
                return TRUE;
            } /* else we allow the message to fall through and get
                 passed into the identity provider's message
                 handler. */
        }
        break;

    case KHUI_WM_NC_NOTIFY:
        {
            khui_nc_wnd_data * d;
            d = (khui_nc_wnd_data *)(LONG_PTR) 
                GetWindowLongPtr(hwnd, DWLP_USER);
            if (d == NULL)
                break;

            /* message sent by parent to notify us of something */
            switch(HIWORD(wParam)) {
            case WMNC_DIALOG_EXPAND:
                /* fallthrough */
            case WMNC_UPDATE_LAYOUT:
                if(hwnd == d->dlg_main) {

                    nc_layout_main_panel(d);

                    return TRUE;
                }
                break;          /* nop */
            }
        }
        return TRUE;
    }

    /* check if we have a wnd_data, and if so pass the message on to
       the identity provider callback. */
    {
        khui_nc_wnd_data * d;

        d = (khui_nc_wnd_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        /* TODO: filter out and forward only the messages that
           originated or pertain to the identity selection
           controls. */
        if (d && d->nc && d->nc->ident_cb) {
            return d->nc->ident_cb(d->nc, WMNC_IDENT_WMSG, hwnd, uMsg, 
                                   wParam, lParam);
        }
    }

    return FALSE;
}

static void
nc_notify_clear(khui_nc_wnd_data * d) {

    if (d->notif_type == NC_NOTIFY_NONE)
        /* there are no notifications anyway. */
        return;

    if (d->hwnd_notif_label)
        DestroyWindow(d->hwnd_notif_label);

    if (d->hwnd_notif_aux)
        DestroyWindow(d->hwnd_notif_aux);

    d->hwnd_notif_label = NULL;
    d->hwnd_notif_aux = NULL;

    SetRectEmpty(&d->r_notif);

    d->notif_type = NC_NOTIFY_NONE;

    /* Note that we must call nc_layout_main_panel() after calling
       this to adjust the layout of the main panel.  However we aren't
       calling it here since we might want to add another set of
       notifications or make other changes to the main panel content
       before calling nc_layout_main_panel(). */
}

static void
nc_notify_marquee(khui_nc_wnd_data * d, const wchar_t * label) {

#if (_WIN32_IE >= 0x0600)
    HDC hdc;
    size_t length;
    SIZE label_size;
#endif

    RECT r_label;
    RECT r_mq;
    RECT r_row;
    HFONT hfont;
    HWND hwnd;
    HDWP hdefer;

    /* Clear the notification area.  We only support one notification
       at a time. */
    nc_notify_clear(d);

#ifdef DEBUG
    assert(d->dlg_main);
#endif

#if (_WIN32_IE >= 0x0600)

    /* We can only show the marquee control if the comctl32 DLL is
       version 6.0 or later.  Otherwise we only show the label. */

    if (FAILED(StringCchLength(label, KHUI_MAXCCH_SHORT_DESC, &length))) {
#ifdef DEBUG
        assert(FALSE);
#endif
        length = KHUI_MAXCCH_SHORT_DESC;
    }

    /* See how big the notification control needs to be. */

    hdc = GetDC(d->dlg_main);
#ifdef DEBUG
    assert(hdc != NULL);
#endif

    GetTextExtentPoint32(hdc, label, (int) length, &label_size);

    ReleaseDC(d->dlg_main, hdc);

    CopyRect(&r_row, &d->r_row);

    if (label_size.cx > d->r_e_label.right - d->r_e_label.left) {
        /* using an entire row */
        CopyRect(&r_label, &d->r_row);
        CopyRect(&r_mq, &d->r_n_input);
        OffsetRect(&r_mq, 0, r_row.bottom - r_row.top);
        r_row.bottom += r_row.bottom - r_row.top;
    } else if (label_size.cx > d->r_n_label.right - d->r_n_label.left) {
        /* using large labels */
        CopyRect(&r_label, &d->r_e_label);
        CopyRect(&r_mq, &d->r_e_input);
    } else {
        /* normal labels */
        CopyRect(&r_label, &d->r_n_label);
        CopyRect(&r_mq, &d->r_n_input);
    }

    InflateRect(&r_mq, 0, - ((r_mq.bottom - r_mq.top) / 4));

#else  /* _WIN32_IE < 0x0600 */

    /* We are just showing the label */
    CopyRect(&r_row, &d->r_row);
    CopyRect(&r_label, &r_row);
    SetRectEmpty(&r_mq);

#endif /* _WIN32_IE >= 0x0600 */

    {
        long y;

        if (IsRectEmpty(&d->r_custprompt)) {
            y = d->r_idspec.bottom;
        } else {
            y = d->r_custprompt.bottom;
        }

        OffsetRect(&r_row, d->r_area.left, y);
        OffsetRect(&r_label, r_row.left, r_row.top);
        OffsetRect(&r_mq, r_row.left, r_row.top);
    }

    hfont = (HFONT) SendMessage(d->dlg_main, WM_GETFONT, 0, 0);

    hdefer = BeginDeferWindowPos(2);

    /* the label */
    hwnd = CreateWindowEx(0,
                          L"STATIC",
                          label,
                          WS_CHILD | SS_ENDELLIPSIS,
                          r_label.left, r_label.top,
                          r_label.right - r_label.left,
                          r_label.bottom - r_label.top,
                          d->dlg_main,
                          NULL, NULL, NULL);
#ifdef DEBUG
    assert(hwnd != NULL);
#endif
    SendMessage(hwnd, WM_SETFONT, (WPARAM) hfont, (LPARAM) TRUE);

    DeferWindowPos(hdefer, hwnd, NULL,
                   0, 0, 0, 0,
                   SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER |
                   SWP_NOSIZE | SWP_SHOWWINDOW);

    d->hwnd_notif_label = hwnd;

    /* and the marquee */

#if (_WIN32_IE >= 0x0600)

    /* unfortunately, the marquee is only available on comctl32
       version 6.0 or later.  On previous versions, we only display
       the message label. */

    hwnd = CreateWindowEx(0,
                          PROGRESS_CLASS,
                          L"",
                          WS_CHILD | PBS_MARQUEE,
                          r_mq.left, r_mq.top,
                          r_mq.right - r_mq.left,
                          r_mq.bottom - r_mq.top,
                          d->dlg_main,
                          NULL, NULL, NULL);
#ifdef DEBUG
    assert(hwnd != NULL);
#endif

    SendMessage(hwnd, PBM_SETMARQUEE, TRUE, 100);

    DeferWindowPos(hdefer, hwnd, NULL,
                   0, 0, 0, 0,
                   SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER |
                   SWP_NOSIZE | SWP_SHOWWINDOW);

    d->hwnd_notif_aux = hwnd;

#endif /* _WIN32_IE >= 0x0600 */

    EndDeferWindowPos(hdefer);

    CopyRect(&d->r_notif, &r_row);

    d->notif_type = NC_NOTIFY_MARQUEE;

    /* Note that we must call nc_layout_main_panel() after calling
       this to adjust the layout of the main panel.  However we aren't
       calling it here since we might want to add another set of
       notifications or make other changes to the main panel content
       before calling nc_layout_main_panel(). */
}

static void
nc_notify_message(khui_nc_wnd_data * d,
                  kherr_severity severity,
                  const wchar_t * message) {

    SIZE icon_size;
    LPCTSTR icon_res;
    HICON h_icon;
    HWND hwnd;
    HFONT hfont;
    HDWP hdefer;

    RECT r_row;
    RECT r_label;
    RECT r_icon;

    nc_notify_clear(d);

    icon_size.cx = GetSystemMetrics(SM_CXSMICON);
    icon_size.cy = GetSystemMetrics(SM_CYSMICON);

    switch(severity) {
    case KHERR_INFO:
        icon_res = MAKEINTRESOURCE(OIC_INFORMATION);
        break;

    case KHERR_WARNING:
        icon_res = MAKEINTRESOURCE(OIC_WARNING);
        break;

    case KHERR_ERROR:
        icon_res = MAKEINTRESOURCE(OIC_ERROR);
        break;

    default:
        icon_res = NULL;
    }

    if (icon_res != NULL) {
        h_icon = (HICON) LoadImage(NULL,
                                   icon_res,
                                   IMAGE_ICON,
                                   icon_size.cx,
                                   icon_size.cy,
                                   LR_DEFAULTCOLOR | LR_SHARED);
    } else {
        h_icon = NULL;
    }

    CopyRect(&r_row, &d->r_row);

#define CENTERVALUE(w,v) ((w)/2 - (v)/2)

    SetRect(&r_icon,
            0, CENTERVALUE(r_row.bottom - r_row.top, icon_size.cy),
            icon_size.cx,
            CENTERVALUE(r_row.bottom - r_row.top, icon_size.cy) + icon_size.cy);

#undef CENTERVALUE

    CopyRect(&r_label, &r_row);
    OffsetRect(&r_label, -r_label.left, -r_label.top);
    r_label.left += (icon_size.cx * 3) / 2;

    {
        long y;

        if (IsRectEmpty(&d->r_custprompt)) {
            y = d->r_idspec.bottom;
        } else {
            y = d->r_custprompt.bottom;
        }

        OffsetRect(&r_row, d->r_area.left, y);
        OffsetRect(&r_label, r_row.left, r_row.top);
        OffsetRect(&r_icon, r_row.left, r_row.top);
    }

    hfont = (HFONT) SendMessage(d->dlg_main, WM_GETFONT, 0, 0);

    hdefer = BeginDeferWindowPos(2);

    hwnd = CreateWindowEx(0,
                          L"STATIC",
                          message,
                          WS_CHILD | SS_ENDELLIPSIS | SS_CENTER,
                          r_label.left, r_label.top,
                          r_label.right - r_label.left,
                          r_label.bottom - r_label.top,
                          d->dlg_main,
                          NULL, NULL, NULL);
#ifdef DEBUG
    assert(hwnd != NULL);
#endif
    SendMessage(hwnd, WM_SETFONT, (WPARAM) hfont, (LPARAM) TRUE);

    DeferWindowPos(hdefer, hwnd, NULL,
                   0, 0, 0, 0,
                   SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER |
                   SWP_NOSIZE | SWP_SHOWWINDOW);

    d->hwnd_notif_label = hwnd;

    hwnd = CreateWindowEx(0,
                          L"STATIC",
                          NULL,
                          WS_CHILD | SS_ICON |
#if (_WIN32_IE >= 0x0600)
                          SS_REALSIZECONTROL
#else
                          0
#endif
                          ,
                          r_icon.left, r_icon.top,
                          r_icon.right - r_icon.left,
                          r_icon.bottom - r_icon.top,
                          d->dlg_main,
                          NULL, NULL, NULL);
#ifdef DEBUG
    assert(hwnd != NULL);
#endif

    if (h_icon && hwnd)
        SendMessage(hwnd, STM_SETICON, (WPARAM) h_icon, 0);

    DeferWindowPos(hdefer, hwnd, NULL,
                   0, 0, 0, 0,
                   SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER |
                   SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOZORDER);

    d->hwnd_notif_aux = hwnd;

    EndDeferWindowPos(hdefer);

    CopyRect(&d->r_notif, &r_row);

    d->notif_type = NC_NOTIFY_MESSAGE;

    /* Note that we must call nc_layout_main_panel() after calling
       this to adjust the layout of the main panel.  However we aren't
       calling it here since we might want to add another set of
       notifications or make other changes to the main panel content
       before calling nc_layout_main_panel(). */
}

static void
nc_layout_main_panel(khui_nc_wnd_data * d)
{
    RECT r_main;
    HWND hw_ct;
    HWND hw_ct_label;
    HDWP hdwp;
    RECT r_used;                /* extent used by identity specifiers,
                                   custom prompts and notificaiton
                                   controls. */

    RECT r_wmain;              /* extents of the main window in screen
                                  coordinates. */

    r_main.left = 0;
    r_main.top = 0;
    r_main.bottom = NCDLG_HEIGHT;
    r_main.right = NCDLG_WIDTH;

    MapDialogRect(d->dlg_main, &r_main);

    CopyRect(&r_used, &d->r_idspec);

    GetWindowRect(d->dlg_main, &r_wmain);

    hdwp = BeginDeferWindowPos(7);

    /* check if the notification area and the custom prompt area are
       overlapping. */

    if (d->notif_type != NC_NOTIFY_NONE) {
        long delta_y = 0;
        RECT r;

        CopyRect(&r, &d->r_custprompt);

        if (IsRectEmpty(&d->r_custprompt)) {
            /* if there are no custom prompts, then the notification
               area should be immediately below the identitify
               specifers. */

            delta_y = d->r_idspec.bottom - d->r_notif.top;
        } else {
            /* otherwise, the notification area should be immediately
               below the custom prompt area */

            delta_y = d->r_custprompt.bottom - d->r_notif.top;
        }

        if (delta_y != 0) {
            RECT r_lbl;
            RECT r_aux;

            if (d->hwnd_notif_label) {
                GetWindowRect(d->hwnd_notif_label, &r_lbl);
                OffsetRect(&r_lbl, -r_wmain.left, delta_y - r_wmain.top);

                DeferWindowPos(hdwp, d->hwnd_notif_label, NULL,
                               r_lbl.left, r_lbl.top, 0, 0,
                               SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                               SWP_NOZORDER | SWP_NOSIZE);
            }

            if (d->hwnd_notif_aux) {
                GetWindowRect(d->hwnd_notif_aux, &r_aux);
                OffsetRect(&r_aux, -r_wmain.left, delta_y - r_wmain.top);

                DeferWindowPos(hdwp, d->hwnd_notif_aux, NULL,
                               r_aux.left, r_aux.top, 0, 0,
                               SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                               SWP_NOZORDER | SWP_NOSIZE);
            }

            OffsetRect(&d->r_notif, 0, delta_y);
        }
    }

    if (!IsRectEmpty(&d->r_custprompt)) {
        r_used.bottom = max(d->r_custprompt.bottom,
                            r_used.bottom);
    }

    if (!IsRectEmpty(&d->r_notif)) {
        r_used.bottom = max(d->r_notif.bottom,
                            r_used.bottom);
    }

    if (d->nc->mode == KHUI_NC_MODE_MINI) {
        RECT r_ok;
        RECT r_cancel;
        RECT r_advanced;
        HWND hw;

        hw = GetDlgItem(d->dlg_main, IDOK);
#ifdef DEBUG
        assert(hw != NULL);
#endif
        GetWindowRect(hw, &r_ok);
        OffsetRect(&r_ok, -r_wmain.left, -r_ok.top + r_used.bottom);

        DeferWindowPos(hdwp, hw, NULL,
                       r_ok.left, r_ok.top, 0, 0,
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                       SWP_NOZORDER | SWP_NOSIZE | SWP_SHOWWINDOW);

        hw = GetDlgItem(d->dlg_main, IDCANCEL);
#ifdef DEBUG
        assert(hw != NULL);
#endif
        GetWindowRect(hw, &r_cancel);
        OffsetRect(&r_cancel, -r_wmain.left, -r_cancel.top + r_used.bottom);

        DeferWindowPos(hdwp, hw, NULL,
                       r_cancel.left, r_cancel.top, 0, 0,
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                       SWP_NOZORDER | SWP_NOSIZE | SWP_SHOWWINDOW);

        hw = GetDlgItem(d->dlg_main, IDC_NC_ADVANCED);
#ifdef DEBUG
        assert(hw != NULL);
#endif
        GetWindowRect(hw, &r_advanced);
        OffsetRect(&r_advanced, -r_wmain.left, -r_advanced.top + r_used.bottom);

        DeferWindowPos(hdwp, hw, NULL,
                       r_advanced.left, r_advanced.top, 0, 0,
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                       SWP_NOZORDER | SWP_NOSIZE | SWP_SHOWWINDOW);

        /* and now update the extents of the main panel */
        r_main.bottom = r_used.bottom + (r_ok.bottom - r_ok.top) + d->r_area.top;

        CopyRect(&d->r_main, &r_main);

    } else {

        HWND hw;

        hw = GetDlgItem(d->dlg_main, IDOK);
#ifdef DEBUG
        assert(hw != NULL);
#endif
        if (IsWindowVisible(hw))
            DeferWindowPos(hdwp, hw, NULL,
                           0, 0, 0, 0,
                           SWP_HIDEWINDOW | SWP_NOMOVE | SWP_NOSIZE |
                           SWP_NOOWNERZORDER | SWP_NOZORDER);

        hw = GetDlgItem(d->dlg_main, IDCANCEL);
#ifdef DEBUG
        assert(hw != NULL);
#endif
        if (IsWindowVisible(hw))
            DeferWindowPos(hdwp, hw, NULL,
                           0, 0, 0, 0,
                           SWP_HIDEWINDOW | SWP_NOMOVE | SWP_NOSIZE |
                           SWP_NOOWNERZORDER | SWP_NOZORDER);

        hw = GetDlgItem(d->dlg_main, IDC_NC_ADVANCED);
#ifdef DEBUG
        assert(hw != NULL);
#endif
        if (IsWindowVisible(hw))
            DeferWindowPos(hdwp, hw, NULL,
                           0, 0, 0, 0,
                           SWP_HIDEWINDOW | SWP_NOMOVE | SWP_NOSIZE |
                           SWP_NOOWNERZORDER | SWP_NOZORDER);

        d->r_credtext.top = r_used.bottom;

        CopyRect(&d->r_main, &r_main);
    }

    /* now update the layout of the credentials text window */

    hw_ct = GetDlgItem(d->dlg_main, IDC_NC_CREDTEXT);
    hw_ct_label = GetDlgItem(d->dlg_main, IDC_NC_CREDTEXT_LABEL);
#ifdef DEBUG
    assert(hw_ct != NULL);
    assert(hw_ct_label != NULL);
#endif

    if (d->nc->mode == KHUI_NC_MODE_MINI ||
        d->r_credtext.bottom < d->r_credtext.top + d->r_row.bottom * 2) {

        /* either we aren't supposed to show the credentials text
           window, or we don't have enough room. */
        if (IsWindowVisible(hw_ct) || IsWindowVisible(hw_ct_label)) {

            DeferWindowPos(hdwp, hw_ct, NULL,
                           0, 0, 0, 0,
                           SWP_HIDEWINDOW | SWP_NOOWNERZORDER |
                           SWP_NOZORDER | SWP_NOMOVE | SWP_NOSIZE);

            DeferWindowPos(hdwp, hw_ct_label, NULL,
                           0, 0, 0, 0,
                           SWP_HIDEWINDOW | SWP_NOOWNERZORDER |
                           SWP_NOZORDER | SWP_NOMOVE | SWP_NOSIZE);

        }

    } else {

        DeferWindowPos(hdwp,
                       hw_ct, NULL,
                       d->r_credtext.left + d->r_n_input.left, /* x */
                       d->r_credtext.top, /* y */
                       d->r_n_input.right - d->r_n_input.left, /* width */
                       d->r_credtext.bottom - d->r_credtext.top, /* height */
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER | 
                       SWP_NOZORDER | SWP_SHOWWINDOW);

        DeferWindowPos(hdwp,
                       hw_ct_label, NULL,
                       d->r_credtext.left + d->r_n_label.left, /* x */
                       d->r_credtext.top, /* y */
                       d->r_n_label.right - d->r_n_label.left, /* width */
                       d->r_n_label.bottom - d->r_n_label.top, /* height */
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                       SWP_NOZORDER | SWP_SHOWWINDOW);
    }

    EndDeferWindowPos(hdwp);

    /* NOTE: although we updated d->r_main, if the new credentials
       window is in mini mode, we must call
       nc_layout_new_cred_window() to adjust the size of the new
       credentials window to fit the main panel.  We don't do it here
       because we need to keep these two operations separate. */
}

/* Credential type panel comparison function.  Tabs are sorted based
   on the following criteria:

   1) By ordinal - Panels with ordinal -1 will be ranked after panels
      whose ordinal is not -1.

   2) By name - Case insensitive comparison of the name.  If the panel
      does not have a name (i.e. the ->name member is NULL, it will be
      ranked after panels which have a name.
 */
static int __cdecl
nc_tab_sort_func(const void * v1, const void * v2)
{
    /* v1 and v2 and of type : khui_new_creds_by_type ** */
    khui_new_creds_by_type *t1, *t2;

    t1 = *((khui_new_creds_by_type **) v1);
    t2 = *((khui_new_creds_by_type **) v2);

    if(t1->ordinal !=  -1) {
        if(t2->ordinal != -1) {
            if(t1->ordinal == t2->ordinal) {
                if (t1->name && t2->name)
                    return _wcsicmp(t1->name, t2->name);
                else if (t1->name)
                    return -1;
                else if (t2->name)
                    return 1;
                else
                    return 0;
            } else {
                /* safe to convert to an int here */
                return (int) (t1->ordinal - t2->ordinal);
            }
        } else
            return -1;
    } else {
        if(t2->ordinal != -1)
            return 1;
        else if (t1->name && t2->name)
            return wcscmp(t1->name, t2->name);
        else if (t1->name)
            return -1;
        else if (t2->name)
            return 1;
        else
            return 0;
    }
}

static void 
nc_notify_types(khui_new_creds * c, UINT uMsg,
                WPARAM wParam, LPARAM lParam, BOOL sync)
{
    khm_size i;

    for(i=0; i<c->n_types; i++) {

        if (c->types[i]->hwnd_panel == NULL)
            continue;

        if (sync)
            SendMessage(c->types[i]->hwnd_panel, uMsg, wParam, lParam);
        else
            PostMessage(c->types[i]->hwnd_panel, uMsg, wParam, lParam);
    }
}

static void
nc_clear_password_fields(khui_nc_wnd_data * d)
{
    khm_size i;
    khm_boolean need_sync = FALSE;

    khui_cw_lock_nc(d->nc);

    for (i=0; i < d->nc->n_prompts; i++) {
        if ((d->nc->prompts[i]->flags & KHUI_NCPROMPT_FLAG_HIDDEN) &&
            d->nc->prompts[i]->hwnd_edit) {
            SetWindowText(d->nc->prompts[i]->hwnd_edit,
                          L"");
            need_sync = TRUE;
        }
    }

    khui_cw_unlock_nc(d->nc);

    if (need_sync) {
        khui_cw_sync_prompt_values(d->nc);
    }
}

/* used by nc_enable_controls */

struct nc_enum_wnd_data {
    khui_nc_wnd_data * d;
    khm_boolean enable;
};

static
BOOL CALLBACK
nc_enum_wnd_proc(HWND hwnd,
                 LPARAM lParam)
{
    struct nc_enum_wnd_data * wd;

    wd = (struct nc_enum_wnd_data *) lParam;

    EnableWindow(hwnd, wd->enable);

    return TRUE;
}

static void
nc_enable_controls(khui_nc_wnd_data * d, khm_boolean enable)
{
    struct nc_enum_wnd_data wd;

    ZeroMemory(&wd, sizeof(wd));

    wd.d = d;
    wd.enable = enable;

    EnumChildWindows(d->dlg_main, nc_enum_wnd_proc, (LPARAM) &wd);
}

#define NC_MAXCCH_CREDTEXT 16384
#define NC_MAXCB_CREDTEXT (NC_MAXCCH_CREDTEXT * sizeof(wchar_t))

static void 
nc_update_credtext(khui_nc_wnd_data * d) 
{
    wchar_t * ctbuf = NULL;
    wchar_t * buf;
    BOOL okEnable = FALSE;
    BOOL validId = FALSE;
    HWND hw = NULL;
    size_t cch = 0;

    ctbuf = PMALLOC(NC_MAXCB_CREDTEXT);

    assert(ctbuf != NULL);

    LoadString(khm_hInstance, IDS_NC_CREDTEXT_TABS, ctbuf, NC_MAXCCH_CREDTEXT);
    StringCchLength(ctbuf, NC_MAXCCH_CREDTEXT, &cch);
    buf = ctbuf + cch;
    nc_notify_types(d->nc, KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0, WMNC_UPDATE_CREDTEXT), (LPARAM) d->nc, TRUE);

    /* hopefully all the types have updated their credential texts */

    /* if the dialog is in the mini mode, we have to display
       exceptions using a notification. */
    if (d->nc->mode == KHUI_NC_MODE_MINI) {
        BOOL need_layout = FALSE;
        if (d->nc->n_identities == 0) {

            /* There are no identities selected. We don't show any
               notifications here. */
            if (d->notif_type != NC_NOTIFY_NONE) {
                nc_notify_clear(d);
                need_layout = TRUE;
            }

        } else {

            wchar_t id_name[KCDB_IDENT_MAXCCH_NAME];
            wchar_t format[256];
            wchar_t msg[ARRAYLENGTH(format) + ARRAYLENGTH(id_name)];
            khm_size cbbuf;
            khm_int32 flags;

            kcdb_identity_get_flags(d->nc->identities[0], &flags);

            cbbuf = sizeof(id_name);
            kcdb_identity_get_name(d->nc->identities[0], id_name, &cbbuf);

            if (flags & KCDB_IDENT_FLAG_INVALID) {

                /* identity is invalid */
                LoadString(khm_hInstance, IDS_NCN_IDENT_INVALID,
                           format, ARRAYLENGTH(format));
                StringCbPrintf(msg, sizeof(msg), format, id_name);

                nc_notify_message(d, KHERR_ERROR, msg);

                need_layout = TRUE;

            } else if ((flags & KCDB_IDENT_FLAG_VALID) ||
                       d->nc->subtype == KMSG_CRED_PASSWORD) {
                /* special case: If we are going to change the
                   password, we don't expect the identity provider to
                   validate the identity in real time.  As such, we
                   assume that the identity is valid. */
 
               /* identity is valid */
                if (d->notif_type != NC_NOTIFY_NONE) {
                    nc_notify_clear(d);
                    need_layout = TRUE;
                }

            } else if (flags & KCDB_IDENT_FLAG_UNKNOWN) {

                /* unknown state */
                LoadString(khm_hInstance, IDS_NCN_IDENT_UNKNOWN,
                           format, ARRAYLENGTH(format));
                StringCbPrintf(msg, sizeof(msg), format, id_name);

                nc_notify_message(d, KHERR_WARNING, msg);

                need_layout = TRUE;

            } else {

                /* still checking */
                LoadString(khm_hInstance, IDS_NCN_IDENT_CHECKING,
                           format, ARRAYLENGTH(format));
                StringCbPrintf(msg, sizeof(msg), format, id_name);

                nc_notify_marquee(d, msg);

                need_layout = TRUE;

            }
        }

        if (need_layout) {
            nc_layout_main_panel(d);
            nc_layout_new_cred_window(d);
        }
    }

    if(d->nc->n_identities == 1) {
        wchar_t main_fmt[256];
        wchar_t id_fmt[256];
        wchar_t id_name[KCDB_IDENT_MAXCCH_NAME];
        wchar_t id_string[KCDB_IDENT_MAXCCH_NAME + 256];
        khm_size cbbuf;
        khm_int32 flags;

        LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_ONE, 
                   main_fmt, (int) ARRAYLENGTH(main_fmt));

        cbbuf = sizeof(id_name);
        kcdb_identity_get_name(d->nc->identities[0], id_name, &cbbuf);

        kcdb_identity_get_flags(d->nc->identities[0], &flags);

        if (flags & KCDB_IDENT_FLAG_INVALID) {
            LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_INVALID, 
                       id_fmt, (int) ARRAYLENGTH(id_fmt));
        } else if(flags & KCDB_IDENT_FLAG_VALID) {
            LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_VALID, 
                       id_fmt, (int) ARRAYLENGTH(id_fmt));
        } else if(flags & KCDB_IDENT_FLAG_UNKNOWN) {
            LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_UNCHECKED,
                       id_fmt, (int) ARRAYLENGTH(id_fmt));
        } else if(d->nc->subtype == KMSG_CRED_NEW_CREDS) {
            LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_CHECKING, 
                       id_fmt, (int) ARRAYLENGTH(id_fmt));
        } else {
            LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_UNCHECKED, 
                       id_fmt, (int) ARRAYLENGTH(id_fmt));
        }

        StringCbPrintf(id_string, sizeof(id_string), id_fmt, id_name);

        StringCbPrintf(buf, NC_MAXCB_CREDTEXT - cch*sizeof(wchar_t), 
                       main_fmt, id_string);

        if (flags & KCDB_IDENT_FLAG_VALID) {
            if (flags & KCDB_IDENT_FLAG_DEFAULT)
                LoadString(khm_hInstance, IDS_NC_ID_DEF,
                           id_string, ARRAYLENGTH(id_string));
            else if (d->nc->set_default)
                LoadString(khm_hInstance, IDS_NC_ID_WDEF,
                           id_string, ARRAYLENGTH(id_string));
            else
                LoadString(khm_hInstance, IDS_NC_ID_NDEF,
                           id_string, ARRAYLENGTH(id_string));

            StringCbCat(buf, NC_MAXCB_CREDTEXT - cch * sizeof(wchar_t),
                        id_string);
        }

    } else if(d->nc->n_identities > 1) {
        wchar_t *ids_string;
        khm_size cb_ids_string;

        wchar_t id_name[KCDB_IDENT_MAXCCH_NAME];
        wchar_t id_fmt[256];
        wchar_t id_string[KCDB_IDENT_MAXCCH_NAME + 256];

        wchar_t main_fmt[256];
        khm_size cbbuf;

        LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_MANY, 
                   main_fmt, (int) ARRAYLENGTH(main_fmt));

        /* we are going to concatenate all the identity names into
           a comma separated string */

        /* d->nc->n_identities is at least 2 */
        ids_string = PMALLOC((KCDB_IDENT_MAXCB_NAME + sizeof(id_fmt)) * 
                            (d->nc->n_identities - 1));
        cb_ids_string = 
            (KCDB_IDENT_MAXCB_NAME + sizeof(id_fmt)) * 
            (d->nc->n_identities - 1);

        assert(ids_string != NULL);

        ids_string[0] = 0;

        {
            khm_size i;
            khm_int32 flags;

            for(i=1; i<d->nc->n_identities; i++) {
                if(i>1) {
                    StringCbCat(ids_string, cb_ids_string, L",");
                }

                flags = 0;

                cbbuf = sizeof(id_name);
                kcdb_identity_get_name(d->nc->identities[i], id_name, &cbbuf);
                kcdb_identity_get_flags(d->nc->identities[i], &flags);
                if(flags & KCDB_IDENT_FLAG_INVALID) {
                    LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_INVALID, 
                               id_fmt, (int) ARRAYLENGTH(id_fmt));
                } else if(flags & KCDB_IDENT_FLAG_VALID) {
                    LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_VALID, 
                               id_fmt, (int) ARRAYLENGTH(id_fmt));
                } else {
                    LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_UNCHECKED, 
                               id_fmt, (int) ARRAYLENGTH(id_fmt));
                }

                StringCbPrintf(id_string, sizeof(id_string), id_fmt, id_name);
                StringCbCat(ids_string, cb_ids_string, id_string);
            }

            cbbuf = sizeof(id_name);
            kcdb_identity_get_name(d->nc->identities[0], id_name, &cbbuf);
            kcdb_identity_get_flags(d->nc->identities[0], &flags);
            if(flags & KCDB_IDENT_FLAG_INVALID) {
                LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_INVALID, 
                           id_fmt, (int) ARRAYLENGTH(id_fmt));
            } else if(flags & KCDB_IDENT_FLAG_VALID) {
                LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_VALID, 
                           id_fmt, (int) ARRAYLENGTH(id_fmt));
            } else {
                LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_UNCHECKED, 
                           id_fmt, (int) ARRAYLENGTH(id_fmt));
            }
            StringCbPrintf(id_string, sizeof(id_string), id_fmt, id_name);

            StringCbPrintf(buf, NC_MAXCB_CREDTEXT - cch*sizeof(wchar_t), 
                           main_fmt, id_string, ids_string);

            PFREE(ids_string);
        }
    } else {
        LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_NONE, 
                   buf, (int)(NC_MAXCCH_CREDTEXT - cch));
    }

    /* now, append the credtext string from each of the cred types */
    {
        khm_size i;
        size_t cb;
        wchar_t * buf;

        cb = NC_MAXCB_CREDTEXT;
        buf = ctbuf;

        for(i=0; i<d->nc->n_types; i++) {
            if(d->nc->types[i]->credtext != NULL) {
                StringCbCatEx(buf, cb, 
                              d->nc->types[i]->credtext,
                              &buf, &cb,
                              0);
            }
        }
    }

    SetDlgItemText(d->dlg_main, IDC_NC_CREDTEXT, ctbuf);

    PFREE(ctbuf);

    /* so depending on whether the primary identity was found to be
       invalid, we need to disable the Ok button and set the title to
       reflect this */

    if(d->nc->n_identities > 0) {
        khm_int32 flags = 0;

        if(KHM_SUCCEEDED(kcdb_identity_get_flags(d->nc->identities[0], 
                                               &flags)) &&
           (flags & KCDB_IDENT_FLAG_VALID)) {
            validId = TRUE;
        }
    }

    if (d->nc->window_title == NULL) {
        if(validId) {
            wchar_t wpostfix[256];
            wchar_t wtitle[KCDB_IDENT_MAXCCH_NAME + 256];
            khm_size cbsize;

            cbsize = sizeof(wtitle);
            kcdb_identity_get_name(d->nc->identities[0], wtitle, &cbsize);

            if (d->nc->subtype == KMSG_CRED_PASSWORD)
                LoadString(khm_hInstance, IDS_WTPOST_PASSWORD,
                           wpostfix, (int) ARRAYLENGTH(wpostfix));
            else
                LoadString(khm_hInstance, IDS_WTPOST_NEW_CREDS, 
                           wpostfix, (int) ARRAYLENGTH(wpostfix));

            StringCbCat(wtitle, sizeof(wtitle), wpostfix);

            SetWindowText(d->nc->hwnd, wtitle);
        } else {
            wchar_t wtitle[256];

            if (d->nc->subtype == KMSG_CRED_PASSWORD)
                LoadString(khm_hInstance, IDS_WT_PASSWORD,
                           wtitle, (int) ARRAYLENGTH(wtitle));
            else
                LoadString(khm_hInstance, IDS_WT_NEW_CREDS, 
                           wtitle, (int) ARRAYLENGTH(wtitle));

            SetWindowText(d->nc->hwnd, wtitle);
        }
    }

    if (!(d->nc->response & KHUI_NC_RESPONSE_PROCESSING)) {
        if(validId ||
           d->nc->subtype == KMSG_CRED_PASSWORD) {
            /* TODO: check if all the required fields have valid values
               before enabling the Ok button */
            okEnable = TRUE;
        }

        hw = GetDlgItem(d->dlg_main, IDOK);
        EnableWindow(hw, okEnable);
        hw = GetDlgItem(d->dlg_bb, IDOK);
        EnableWindow(hw, okEnable);
    }
}

static void
nc_layout_new_cred_window(khui_nc_wnd_data * ncd) {
    khui_new_creds * c;
    RECT r_main;
    RECT r_ncdialog;
    HDWP hdefer;

    c = ncd->nc;

    r_main.left = 0;
    r_main.top = 0;
    r_main.right = NCDLG_WIDTH;
    r_main.bottom = NCDLG_HEIGHT;

    MapDialogRect(ncd->dlg_main, &r_main);

    hdefer = BeginDeferWindowPos(5);

    if (c->mode == KHUI_NC_MODE_MINI) {

        if (IsWindowVisible(ncd->tab_wnd)) {
            DeferWindowPos(hdefer,
                           ncd->tab_wnd, NULL,
                           0, 0, 0, 0,
                           SWP_HIDEWINDOW |
                           SWP_NOMOVE | SWP_NOOWNERZORDER |
                           SWP_NOSIZE | SWP_NOZORDER);
        }

        if (IsWindowVisible(ncd->dlg_bb)) {
            DeferWindowPos(hdefer,
                           ncd->dlg_bb, NULL,
                           0, 0, 0, 0,
                           SWP_HIDEWINDOW |
                           SWP_NOMOVE | SWP_NOOWNERZORDER |
                           SWP_NOSIZE | SWP_NOZORDER);
        }

        DeferWindowPos(hdefer, ncd->dlg_main, NULL,
                       r_main.left, r_main.top,
                       r_main.right - r_main.left,
                       r_main.bottom - r_main.top,
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                       SWP_NOZORDER | SWP_SHOWWINDOW);

        /* note that the ncd->r_main.bottom may not be the same as
           r_main.bottom because ncd->r_main.bottom is set dynamically
           depending on custom controls. ncd->r_main is valid only
           once nc_layout_main_panel() is called.*/
        CopyRect(&ncd->r_required, &ncd->r_main);

    } else {
        RECT r_tabctrl;
        RECT r_displayarea;
        RECT r_bbar;
        khm_size i;

        /* calculate the size of the tab control so that it fits
           snugly around the expanded main panel. */
        CopyRect(&r_tabctrl, &r_main);
        TabCtrl_AdjustRect(ncd->tab_wnd, TRUE, &r_tabctrl);

        if (r_tabctrl.left < 0 ||
            r_tabctrl.top < 0) {

            OffsetRect(&r_tabctrl,
                       (r_tabctrl.left < 0)? -r_tabctrl.left : 0,
                       (r_tabctrl.top < 0)? -r_tabctrl.top : 0);

        }

#ifdef DEBUG
        assert(r_tabctrl.left == 0);
        assert(r_tabctrl.top == 0);
#endif

        OffsetRect(&r_tabctrl, 0, ncd->r_area.top);

        /* and now calculate the rectangle where the main panel should
           be inside the tab control. */
        CopyRect(&r_displayarea, &r_tabctrl);
        TabCtrl_AdjustRect(ncd->tab_wnd, FALSE, &r_displayarea);

        DeferWindowPos(hdefer,
                       ncd->tab_wnd, HWND_BOTTOM,
                       r_tabctrl.left, r_tabctrl.top,
                       r_tabctrl.right - r_tabctrl.left,
                       r_tabctrl.bottom - r_tabctrl.top,
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                       SWP_SHOWWINDOW);

        /* we have to place the button bar just to the right of the
           tab panel. */
        r_bbar.left = 0;
        r_bbar.top = 0;
        r_bbar.right = NCDLG_BBAR_WIDTH;
        r_bbar.bottom = NCDLG_BBAR_HEIGHT;

        MapDialogRect(ncd->dlg_main, &r_bbar);

        OffsetRect(&r_bbar, r_tabctrl.right, 0);

        DeferWindowPos(hdefer,
                       ncd->dlg_bb, NULL,
                       r_bbar.left, r_bbar.top,
                       r_bbar.right - r_bbar.left,
                       r_bbar.bottom - r_bbar.top,
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                       SWP_NOZORDER | SWP_SHOWWINDOW);

        /* move the main panel inside the tab control... */
        DeferWindowPos(hdefer,
                       ncd->dlg_main, NULL,
                       r_displayarea.left, r_displayarea.top,
                       r_displayarea.right - r_displayarea.left,
                       r_displayarea.bottom - r_displayarea.top,
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                       SWP_NOZORDER |
                       (ncd->current_panel == 0 ? SWP_SHOWWINDOW : SWP_HIDEWINDOW));

        /* and also move all the credential type panels (if they have
           been created) inside the tab control too. */
        khui_cw_lock_nc(c);

        for (i=0; i < c->n_types; i++) {
            if (c->types[i]->hwnd_panel != NULL) {
                DeferWindowPos(hdefer,
                               c->types[i]->hwnd_panel, NULL,
                               r_displayarea.left, r_displayarea.top,
                               r_displayarea.right - r_displayarea.left,
                               r_displayarea.bottom - r_displayarea.top,
                               SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                               SWP_NOZORDER |
                               (ncd->current_panel == c->types[i]->ordinal ?
                                SWP_SHOWWINDOW : SWP_HIDEWINDOW));
            }
        }

        khui_cw_unlock_nc(c);

        /* then update the required size of the new credentials
           dialog. */
        ncd->r_required.left = 0;
        ncd->r_required.top = 0;
        ncd->r_required.right = r_bbar.right;
        ncd->r_required.bottom = max(r_tabctrl.bottom, r_bbar.bottom) + ncd->r_area.top;
    }

    /* commit all the window moves, resizes and hides/shows we did*/
    EndDeferWindowPos(hdefer);

    /* now we have to see if the client area of the new credentials
       window is the right size. */

    GetClientRect(c->hwnd, &r_ncdialog);

    if (

        ((r_ncdialog.right - r_ncdialog.left !=
          ncd->r_required.right - ncd->r_required.left)

         ||

         (r_ncdialog.bottom - r_ncdialog.top !=
          ncd->r_required.bottom - ncd->r_required.top))

        &&

        /* we don't bother if the new creds window is already in the
           process of changing the size. */
        !ncd->size_changing) {

        /* if not, notify the window that the size needs adjusting. */
        if (IsWindowVisible(c->hwnd))
            PostMessage(c->hwnd, KHUI_WM_NC_NOTIFY,
                        MAKEWPARAM(0, WMNC_UPDATE_LAYOUT), 0);
        else
            SendMessage(c->hwnd, KHUI_WM_NC_NOTIFY,
                        MAKEWPARAM(0, WMNC_UPDATE_LAYOUT), 0);
    }
}

#define CW_PARAM DWLP_USER

static LRESULT 
nc_handle_wm_create(HWND hwnd,
                    UINT uMsg,
                    WPARAM wParam,
                    LPARAM lParam)
{
    LPCREATESTRUCT lpc;
    khui_new_creds * c;
    khui_nc_wnd_data * ncd;
    int x, y;
    int width, height;
    RECT r;
    HFONT hf_main;

    lpc = (LPCREATESTRUCT) lParam;

    ncd = PMALLOC(sizeof(*ncd));
    ZeroMemory(ncd, sizeof(*ncd));

    c = (khui_new_creds *) lpc->lpCreateParams;
    ncd->nc = c;
    c->hwnd = hwnd;

#ifdef DEBUG
    assert(c->subtype == KMSG_CRED_NEW_CREDS ||
           c->subtype == KMSG_CRED_PASSWORD);
#endif

#pragma warning(push)
#pragma warning(disable: 4244)
    SetWindowLongPtr(hwnd, CW_PARAM, (LONG_PTR) ncd);
#pragma warning(pop)

    /* first, create the tab control that will house the main dialog
       panel as well as the plug-in specific panels */
    ncd->tab_wnd = CreateWindowEx(0, /* extended style */
                                  WC_TABCONTROL,
                                  L"TabControloxxrz", /* window name */
                                  TCS_HOTTRACK | TCS_RAGGEDRIGHT |
                                  TCS_SINGLELINE | TCS_TABS |
                                  WS_CHILD | WS_TABSTOP | WS_CLIPSIBLINGS,
                                  0, 0, 100, 100, /* x,y,width height.
                                                     We'll be changing
                                                     these later
                                                     anyway. */
                                  hwnd,
                                  (HMENU) IDC_NC_TABS,
                                  NULL,
                                  0);

#ifdef DEBUG
    assert(ncd->tab_wnd != NULL);
#endif

    /* try to create the main dialog panel */

    ncd->dlg_main = CreateDialogParam(khm_hInstance,
                                      MAKEINTRESOURCE(IDD_NC_NEWCRED),
                                      hwnd,
                                      nc_common_dlg_proc,
                                      (LPARAM) ncd);
#ifdef DEBUG
    assert(ncd->dlg_main != NULL);
#endif

    hf_main = (HFONT) SendMessage(ncd->dlg_main, WM_GETFONT, 0, 0);
    if (hf_main)
        SendMessage(ncd->tab_wnd, WM_SETFONT, (WPARAM) hf_main, FALSE);

#if _WIN32_WINNT >= 0x0501
    EnableThemeDialogTexture(ncd->dlg_main,
                             ETDT_ENABLETAB);
#endif

    {
        RECT r_main;
        RECT r_area;
        RECT r_row;
        HWND hw;
            
        /* During the operation of the new credentials window, we will
           need to dynamically change the layout of the controls as a
           result of custom prompting from credentials providers and
           identity selectors from identity providers.  In order to
           guide the dynamic layout, we pick out a few metrics from
           the dialog template for the main panel. The metrics come
           from hidden STATIC controls in the dialog template. */

        GetWindowRect(ncd->dlg_main, &r_main);

        /* IDC_NC_TPL_PANEL spans the full extent of the dialog that
           we can populate with custom controls. */
        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_PANEL);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r_area);
        OffsetRect(&r_area,-r_main.left, -r_main.top);
        CopyRect(&ncd->r_area, &r_area);

        /* IDC_NC_TPL_ROW spans the extent of a row of normal sized
           custom controls.  A row of custom controls typicall consist
           of a text label and an input control. */
        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_ROW);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        CopyRect(&r_row, &r);
        OffsetRect(&r,-r.left, -r.top);
        CopyRect(&ncd->r_row, &r);

        /* IDC_NC_TPL_LABEL spans the extent that a normal sized
           label.  The control overlaps IDC_NC_TPL_ROW so we can get
           coordinates relative to the row extents. */
        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_LABEL);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r,-r_row.left, -r_row.top);
        CopyRect(&ncd->r_n_label, &r);

        /* IDC_NC_TPL_INPUT spans the extent of a normal sized input
           control in a custom control row.  The control overlaps
           IDC_NC_TPL_ROW so we can get relative coordinates. */
        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_INPUT);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r, -r_row.left, -r_row.top);
        CopyRect(&ncd->r_n_input, &r);

        /* IDC_NC_TPL_ROW_LG spans the extent of a row of large sized
           controls. */
        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_ROW_LG);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r_row);

        /* IDC_NC_TPL_LABEL_LG is a large sized label.  The control
           overlaps IDC_NC_TPL_ROW_LG. */
        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_LABEL_LG);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r, -r_row.left, -r_row.top);
        CopyRect(&ncd->r_e_label, &r);

        /* IDC_NC_TPL_INPUT_LG is a large sized input control.
           Overlaps IDC_NC_TPL_ROW_LG. */
        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_INPUT_LG);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r, -r_row.left, -r_row.top);
        CopyRect(&ncd->r_e_input, &r);

        CopyRect(&ncd->r_credtext, &ncd->r_area);
        CopyRect(&ncd->r_idspec, &ncd->r_area);

        ncd->r_idspec.bottom = ncd->r_idspec.top;

        /* And finally the credential text window.  The only metric we
           take from here is the Y coordinate of the bottom of the
           control since the actual size and position of the
           credentials window will change depending on the custom
           controls being displayed. */
        hw = GetDlgItem(ncd->dlg_main, IDC_NC_CREDTEXT);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r, -r_main.left, -r_main.top);
        ncd->r_credtext.bottom = r.bottom;
    }

    /* if the mode is 'mini'*/
    r.left = 0;
    r.top = 0;

    if(c->mode == KHUI_NC_MODE_MINI) {
        r.right = NCDLG_WIDTH;
        r.bottom = NCDLG_HEIGHT;
    } else {
        r.right = NCDLG_WIDTH + NCDLG_BBAR_WIDTH;
        r.bottom = NCDLG_BBAR_HEIGHT;
    }

    MapDialogRect(ncd->dlg_main, &r);

    /* position the new credentials dialog */
    width = r.right - r.left;
    height = r.bottom - r.top;

    /* adjust width and height to accomodate NC area */
    {
        RECT wr,cr;

        GetWindowRect(hwnd, &wr);
        GetClientRect(hwnd, &cr);

        /* the non-client and client areas have already been calculated
           at this point.  We just use the difference to adjust the width
           and height */
        width += (wr.right - wr.left) - (cr.right - cr.left);
        height += (wr.bottom - wr.top) - (cr.bottom - cr.top);
    }

    /* if the parent window is visible, we center the new credentials
       dialog over the parent.  Otherwise, we center it on the primary
       display. */

    if (IsWindowVisible(lpc->hwndParent)) {
        GetWindowRect(lpc->hwndParent, &r);
    } else {
        if(!SystemParametersInfo(SPI_GETWORKAREA, 0, (PVOID) &r, 0)) {
            /* failover to the window coordinates */
            GetWindowRect(lpc->hwndParent, &r);
        }
    }
    x = (r.right + r.left)/2 - width / 2;
    y = (r.top + r.bottom)/2 - height / 2;

    /* we want to check if the entire rect is visible on the screen.
       If the main window is visible and in basic mode, we might end
       up with a rect that is partially outside the screen. */
    {
        RECT r;

        SetRect(&r, x, y, x + width, y + height);
        khm_adjust_window_dimensions_for_display(&r, 0);

        x = r.left;
        y = r.top;
        width = r.right - r.left;
        height = r.bottom - r.top;
    }

    MoveWindow(hwnd, x, y, width, height, FALSE);

    ncd->dlg_bb = CreateDialogParam(khm_hInstance,
                                    MAKEINTRESOURCE(IDD_NC_BBAR),
                                    hwnd,
                                    nc_common_dlg_proc,
                                    (LPARAM) ncd);

#ifdef DEBUG
    assert(ncd->dlg_bb);
#endif

    /* Call the identity provider callback to set the identity
       selector controls.  These controls need to be there before we
       layout the main panel. */
    c->ident_cb(c, WMNC_IDENT_INIT, NULL, 0, 0, (LPARAM) ncd->dlg_main);

    if (c->mode == KHUI_NC_MODE_EXPANDED) {
        SendMessage(ncd->dlg_main, KHUI_WM_NC_NOTIFY,
                    MAKEWPARAM(0, WMNC_DIALOG_EXPAND), 0);
    } else {
        /* we don't call nc_layout_main_panel() if the dialog is
           expanded because posting WMNC_DIALOG_EXPAND to the main
           panel results in it getting called anyway. */
        nc_layout_main_panel(ncd);
    }

    nc_layout_new_cred_window(ncd);

    /* add this to the dialog chain */
    khm_add_dialog(hwnd);

    return TRUE;
}

/* add a control row supplied by an identity provider */
static void
nc_add_control_row(khui_nc_wnd_data * d, 
                   HWND label,
                   HWND input,
                   khui_control_size size)
{
    RECT r_row;
    RECT r_label;
    RECT r_input;
    HFONT hf;
    HDWP hdefer;

    hf = (HFONT) SendMessage(d->dlg_main, WM_GETFONT, 0, 0);
    SendMessage(label, WM_SETFONT, (WPARAM) hf, FALSE);
    SendMessage(input, WM_SETFONT, (WPARAM) hf, FALSE);

    CopyRect(&r_row, &d->r_row);
    OffsetRect(&r_row, d->r_idspec.left, d->r_idspec.bottom);

    if (size == KHUI_CTRLSIZE_SMALL) {
        CopyRect(&r_label, &d->r_n_label);
        CopyRect(&r_input, &d->r_n_input);
        OffsetRect(&r_label, r_row.left, r_row.top);
        OffsetRect(&r_input, r_row.left, r_row.top);
    } else if (size == KHUI_CTRLSIZE_HALF) {
        CopyRect(&r_label, &d->r_e_label);
        CopyRect(&r_input, &d->r_e_input);
        OffsetRect(&r_label, r_row.left, r_row.top);
        OffsetRect(&r_input, r_row.left, r_row.top);
    } else if (size == KHUI_CTRLSIZE_FULL) {
        CopyRect(&r_label, &d->r_n_label);
        r_label.right = d->r_row.right;
        CopyRect(&r_input, &d->r_n_input);
        OffsetRect(&r_input, r_row.left, r_row.top);
        OffsetRect(&r_input, 0, r_input.bottom);
        r_row.bottom += r_input.bottom;
        OffsetRect(&r_label, r_row.left, r_row.top);
    } else {
        SetRectEmpty(&r_label);
        SetRectEmpty(&r_input);
#ifdef DEBUG
        assert(FALSE);
#endif
        return;
    }

    hdefer = BeginDeferWindowPos(2);

    if (label)
        DeferWindowPos(hdefer, label,
                       ((d->hwnd_last_idspec != NULL)?
                        d->hwnd_last_idspec:
                        HWND_TOP),
                       r_label.left, r_label.top,
                       r_label.right - r_label.left,
                       r_label.bottom - r_label.top,
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER);

    if (input)
        DeferWindowPos(hdefer, input,
                       (label ? label : ((d->hwnd_last_idspec != NULL)?
                                         d->hwnd_last_idspec:
                                         HWND_TOP)),
                       r_input.left, r_input.top,
                       r_input.right - r_input.left,
                       r_input.bottom - r_input.top,
                       SWP_NOACTIVATE | SWP_NOOWNERZORDER);

    EndDeferWindowPos(hdefer);

    d->hwnd_last_idspec = (input ? input : label);

    d->r_idspec.bottom = r_row.bottom;

    /* we don't update the layout of the main panel yet, since these
       control additions happen before the main panel is displayed.  A
       call to nc_layout_main_panel() will be made before the main
       panel is shown anyway. */

}


static LRESULT 
nc_handle_wm_destroy(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam)
{
    khui_nc_wnd_data * d;

    /* remove self from dialog chain */
    khm_del_dialog(hwnd);

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);
    if (d == NULL)
        return TRUE;

    d->nc->ident_cb(d->nc, WMNC_IDENT_EXIT, NULL, 0, 0, 0);

    if (d->hwnd_notif_label)
        DestroyWindow(d->hwnd_notif_label);
    if (d->hwnd_notif_aux)
        DestroyWindow(d->hwnd_notif_aux);

    if(d->dlg_bb)
        DestroyWindow(d->dlg_bb);
    if(d->dlg_main)
        DestroyWindow(d->dlg_main);

    d->dlg_bb = NULL;
    d->dlg_main = NULL;

    PFREE(d);
    SetWindowLongPtr(hwnd, CW_PARAM, 0);

    return TRUE;
}

static LRESULT 
nc_handle_wm_command(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam)
{
    khui_nc_wnd_data * d;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);
    if (d == NULL)
        return 0;

    switch(HIWORD(wParam)) {
    case BN_CLICKED:
        switch(LOWORD(wParam)) {

        case IDOK:
            d->nc->result = KHUI_NC_RESULT_PROCESS;

            /* fallthrough */

        case IDCANCEL:
            /* the default value for d->nc->result is set to
               KHUI_NC_RESULT_CANCEL */
            d->nc->response = KHUI_NC_RESPONSE_PROCESSING;

            nc_enable_controls(d, FALSE);

            nc_notify_types(d->nc, 
                            KHUI_WM_NC_NOTIFY, 
                            MAKEWPARAM(0,WMNC_DIALOG_PREPROCESS), 
                            (LPARAM) d->nc,
                            TRUE);

            khui_cw_sync_prompt_values(d->nc);

            khm_cred_dispatch_process_message(d->nc);

            /* we won't know whether to abort or not until we get
               feedback from the plugins, even if the command was
               to cancel */
            {
                HWND hw;

                hw = GetDlgItem(d->dlg_main, IDOK);
                EnableWindow(hw, FALSE);
                hw = GetDlgItem(d->dlg_main, IDCANCEL);
                EnableWindow(hw, FALSE);
                hw = GetDlgItem(d->dlg_main, IDC_NC_ADVANCED);
                EnableWindow(hw, FALSE);
                hw = GetDlgItem(d->dlg_bb, IDOK);
                EnableWindow(hw, FALSE);
                hw = GetDlgItem(d->dlg_bb, IDCANCEL);
                EnableWindow(hw, FALSE);
            }
            return FALSE;

        case IDC_NC_HELP:
            khm_html_help(hwnd, NULL, HH_HELP_CONTEXT, IDH_ACTION_NEW_ID);
            return FALSE;

        case IDC_NC_BASIC:
        case IDC_NC_ADVANCED: 
            /* the Options button in the main window was clicked.  we
               respond by expanding the dialog. */
            PostMessage(hwnd, KHUI_WM_NC_NOTIFY, 
                        MAKEWPARAM(0, WMNC_DIALOG_EXPAND), 0);
            return FALSE;

        case IDC_NC_CREDTEXT: /* credtext link activated */
            {
                khui_htwnd_link * l;
                wchar_t sid[KHUI_MAXCCH_HTLINK_FIELD];
                wchar_t sparam[KHUI_MAXCCH_HTLINK_FIELD];
                wchar_t * colon;

                l = (khui_htwnd_link *) lParam;

                /* do we have a valid link? */
                if(l->id == NULL || l->id_len >= ARRAYLENGTH(sid))
                    return TRUE; /* nope */

                StringCchCopyN(sid, ARRAYLENGTH(sid), l->id, l->id_len);
                sid[l->id_len] = L'\0'; /* just make sure */

                if(l->param != NULL && 
                   l->param_len < ARRAYLENGTH(sparam) &&
                   l->param_len > 0) {

                    StringCchCopyN(sparam, ARRAYLENGTH(sparam),
                                   l->param, l->param_len);
                    sparam[l->param_len] = L'\0';

                } else {
                    sparam[0] = L'\0';
                }

                /* If the ID is of the form '<credtype>:<link_tag>'
                   and <credtype> is a valid name of a credentials
                   type that is participating in the credentials
                   acquisition process, then we forward the message to
                   the panel that is providing the UI for that cred
                   type.  We also switch to that panel first, unless
                   the link is of the form '<credtype>:!<link_tag>'. */

                colon = wcschr(sid, L':');
                if (colon != NULL) {
                    khm_int32 credtype;
                    khui_new_creds_by_type * t;

                    *colon = L'\0';
                    if (KHM_SUCCEEDED(kcdb_credtype_get_id(sid, &credtype)) &&
                        KHM_SUCCEEDED(khui_cw_find_type(d->nc, credtype, &t))){
                        *colon = L':';

                        if (t->ordinal != d->current_panel &&
                            *(colon + 1) != L'!')
                            PostMessage(hwnd,
                                        KHUI_WM_NC_NOTIFY,
                                        MAKEWPARAM(t->ordinal,
                                                   WMNC_DIALOG_SWITCH_PANEL),
                                        0);

                        return SendMessage(t->hwnd_panel,
                                           KHUI_WM_NC_NOTIFY,
                                           MAKEWPARAM(0, WMNC_CREDTEXT_LINK),
                                           lParam);
                    } else {
                        *colon = L':';
                    }
                }

                /* if it was for us, then we need to process the message */
                if(!_wcsicmp(sid, CTLINKID_SWITCH_PANEL)) {
                    khm_int32 credtype;
                    khui_new_creds_by_type * t;

                    if (KHM_SUCCEEDED(kcdb_credtype_get_id(sparam, 
                                                           &credtype)) &&
                        KHM_SUCCEEDED(khui_cw_find_type(d->nc,
                                                        credtype, &t))) {
                        if (t->ordinal != d->current_panel)
                            PostMessage(hwnd,
                                        KHUI_WM_NC_NOTIFY,
                                        MAKEWPARAM(t->ordinal,
                                                   WMNC_DIALOG_SWITCH_PANEL),
                                        0);
                    }
                } else if (!_wcsicmp(sid, L"NotDef")) {
                    d->nc->set_default = FALSE;
                    nc_update_credtext(d);
                } else if (!_wcsicmp(sid, L"MakeDef")) {
                    d->nc->set_default = TRUE;
                    nc_update_credtext(d);
                }
            }
            return FALSE;

#if 0
        case NC_BN_SET_DEF_ID:
            {
                d->nc->set_default =
                    (IsDlgButtonChecked(d->dlg_main, NC_BN_SET_DEF_ID)
                     == BST_CHECKED);
            }
            return FALSE;
#endif
        }
        break;
    }

    return TRUE;
}

static LRESULT nc_handle_wm_moving(HWND hwnd,
                                   UINT uMsg,
                                   WPARAM wParam,
                                   LPARAM lParam)
{
    khui_nc_wnd_data * d;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);
    if (d == NULL)
        return FALSE;

    nc_notify_types(d->nc, KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0, WMNC_DIALOG_MOVE), (LPARAM) d->nc, TRUE);

    return FALSE;
}

static LRESULT nc_handle_wm_nc_notify(HWND hwnd,
                               UINT uMsg,
                               WPARAM wParam,
                               LPARAM lParam)
{
    khui_nc_wnd_data * d;
    int id;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);
    if (d == NULL)
        return FALSE;

    switch(HIWORD(wParam)) {

    case WMNC_DIALOG_SWITCH_PANEL:
        id = LOWORD(wParam);
        if(id >= 0 && id <= (int) d->nc->n_types) {
            /* one of the tab buttons were pressed */
            if(d->current_panel == id) {
                return TRUE; /* nothing to do */
            }

            d->current_panel = id;

            TabCtrl_SetCurSel(d->tab_wnd, id);
        }

        if(d->nc->mode == KHUI_NC_MODE_EXPANDED) {
            nc_layout_new_cred_window(d);
            return TRUE;
        }
        /*else*/
        /* fallthrough */

    case WMNC_DIALOG_EXPAND:
        /* we are switching from basic to advanced or vice versa */

        if (d->nc->mode == KHUI_NC_MODE_EXPANDED) {

            if (d->current_panel != 0) {
                d->current_panel = 0;
                TabCtrl_SetCurSel(d->tab_wnd, 0);
                nc_layout_new_cred_window(d);
            }

            d->nc->mode = KHUI_NC_MODE_MINI;
        } else {
            d->nc->mode = KHUI_NC_MODE_EXPANDED;
        }

        /* if we are switching to the advanced mode, we clear any
           notifications because we now have a credential text area
           for that. */
        if (d->nc->mode == KHUI_NC_MODE_EXPANDED)
            nc_notify_clear(d);

        nc_layout_main_panel(d);

        nc_layout_new_cred_window(d);

        break;

    case WMNC_DIALOG_SETUP:

        if(d->nc->n_types > 0) {
            khm_size i;
            for(i=0; i < d->nc->n_types;i++) {

                if (d->nc->types[i]->dlg_proc == NULL) {
                    d->nc->types[i]->hwnd_panel = NULL;
                } else {
                    /* Create the dialog panel */
                    d->nc->types[i]->hwnd_panel = 
                        CreateDialogParam(d->nc->types[i]->h_module,
                                          d->nc->types[i]->dlg_template,
                                          d->nc->hwnd,
                                          d->nc->types[i]->dlg_proc,
                                          (LPARAM) d->nc);

#ifdef DEBUG
                    assert(d->nc->types[i]->hwnd_panel);
#endif
#if _WIN32_WINNT >= 0x0501
                    if (d->nc->types[i]->hwnd_panel) {
                        EnableThemeDialogTexture(d->nc->types[i]->hwnd_panel,
                                                 ETDT_ENABLETAB);
                    }
#endif
                }
            }
        }

        break;

    case WMNC_DIALOG_ACTIVATE:
        {
            wchar_t wname[KCDB_MAXCCH_NAME];
            TCITEM tabitem;
            khm_int32 t;

            /* About to activate the window. We should add all the
               panels to the tab control.  */

#ifdef DEBUG
            assert(d->tab_wnd != NULL);
#endif

            ZeroMemory(&tabitem, sizeof(tabitem));

            tabitem.mask = TCIF_PARAM | TCIF_TEXT;

            LoadString(khm_hInstance, IDS_NC_IDENTITY, 
                       wname, ARRAYLENGTH(wname));

            tabitem.pszText = wname;
            tabitem.lParam = 0; /* ordinal */

            TabCtrl_InsertItem(d->tab_wnd, 0, &tabitem);

            khui_cw_lock_nc(d->nc);

            if(d->nc->n_types > 0) {
                khm_size i;

                /* We should sort the tabs first.  See
                   nc_tab_sort_func() for sort criteria. */
                qsort(d->nc->types, 
                      d->nc->n_types, 
                      sizeof(*(d->nc->types)), 
                      nc_tab_sort_func);

                for(i=0; i < d->nc->n_types;i++) {

                    d->nc->types[i]->ordinal = i + 1;

                    if(d->nc->types[i]->name)
                        tabitem.pszText = d->nc->types[i]->name;
                    else {
                        khm_size cbsize;

                        cbsize = sizeof(wname);

                        if(KHM_FAILED
                           (kcdb_credtype_describe
                            (d->nc->types[i]->type, 
                             wname, 
                             &cbsize, 
                             KCDB_TS_SHORT))) {

#ifdef DEBUG
                            assert(FALSE);
#endif
                            wname[0] = L'\0';

                        }

                        tabitem.pszText = wname;

                    }

                    tabitem.lParam = d->nc->types[i]->ordinal;

                    TabCtrl_InsertItem(d->tab_wnd, d->nc->types[i]->ordinal,
                                       &tabitem);
                }
            }

            khui_cw_unlock_nc(d->nc);

            nc_update_credtext(d);

            TabCtrl_SetCurSel(d->tab_wnd, 0); /* the first selected
                                                 tab is the main
                                                 panel. */

            /* we don't enable animations until a specific timeout
               elapses after showing the window.  We don't need to
               animate any size changes if the user has barely had a
               chance to notice the original size. This prevents the
               new cred window from appearing in an animated state. */
            SetTimer(hwnd, NC_TIMER_ENABLEANIMATE, ENABLEANIMATE_TIMEOUT, NULL);

            ShowWindow(hwnd, SW_SHOWNORMAL);

            /* bring the window to the top, if necessary */
            if (KHM_SUCCEEDED(khc_read_int32(NULL,
                                             L"CredWindow\\Windows\\NewCred\\ForceToTop",
                                             &t)) &&

                t != 0) {

                BOOL sfw = FALSE;

                /* it used to be that the above condition also called
                   !khm_is_dialog_active() to find out whether there
                   was a dialog active.  If there was, we wouldn't try
                   to bring the new cred window to the foreground. But
                   that was not the behavior we want. */

                /* if the main window is not visible, then the SetWindowPos()
                   call is sufficient to bring the new creds window to the
                   top.  However, if the main window is visible but not
                   active, the main window needs to be activated before a
                   child window can be activated. */

                SetActiveWindow(hwnd);

                sfw = SetForegroundWindow(hwnd);

                if (!sfw) {
                    FLASHWINFO fi;

                    ZeroMemory(&fi, sizeof(fi));

                    fi.cbSize = sizeof(fi);
                    fi.hwnd = hwnd;
                    fi.dwFlags = FLASHW_ALL;
                    fi.uCount = 3;
                    fi.dwTimeout = 0; /* use the default cursor blink rate */

                    FlashWindowEx(&fi);

                    d->flashing_enabled = TRUE;
                }

            } else {
                SetFocus(hwnd);
            }

            if (d->nc->n_identities == 0)
                break;
            /* else */
            /*   fallthrough */
        }

    case WMNC_IDENTITY_CHANGE:
        {
            BOOL okEnable = FALSE;

            nc_notify_types(d->nc, KHUI_WM_NC_NOTIFY,
                            MAKEWPARAM(0, WMNC_IDENTITY_CHANGE), (LPARAM) d->nc,
                            TRUE);

            if (d->nc->subtype == KMSG_CRED_NEW_CREDS &&
                d->nc->n_identities > 0 &&
                d->nc->identities[0]) {
                khm_int32 f = 0;

                kcdb_identity_get_flags(d->nc->identities[0], &f);

                if (!(f & KCDB_IDENT_FLAG_DEFAULT)) {
                    d->nc->set_default = FALSE;
                }
            }

            nc_update_credtext(d);

        }
        break;

    case WMNC_TYPE_STATE:
        /* fallthrough */
    case WMNC_UPDATE_CREDTEXT:
        nc_update_credtext(d);
        break;

    case WMNC_CLEAR_PROMPTS:
        {
            khm_size i;

            khui_cw_lock_nc(d->nc);

            if(d->hwnd_banner != NULL) {
                DestroyWindow(d->hwnd_banner);
                d->hwnd_banner = NULL;
            }

            if(d->hwnd_name != NULL) {
                DestroyWindow(d->hwnd_name);
                d->hwnd_name = NULL;
            }

            for(i=0;i<d->nc->n_prompts;i++) {
                if(!(d->nc->prompts[i]->flags & 
                     KHUI_NCPROMPT_FLAG_STOCK)) {
                    if(d->nc->prompts[i]->hwnd_static != NULL)
                        DestroyWindow(d->nc->prompts[i]->hwnd_static);

                    if(d->nc->prompts[i]->hwnd_edit != NULL)
                        DestroyWindow(d->nc->prompts[i]->hwnd_edit);
                }

                d->nc->prompts[i]->hwnd_static = NULL;
                d->nc->prompts[i]->hwnd_edit = NULL;
            }

            khui_cw_unlock_nc(d->nc);

            SetRectEmpty(&d->r_custprompt);

            nc_layout_main_panel(d);

            nc_layout_new_cred_window(d);
        }
        break;

    case WMNC_SET_PROMPTS:
        {
            khm_size i;
            int  y;
            HWND hw, hw_prev;
            HFONT hf, hfold;
            HDC hdc;
            BOOL use_large_lables = FALSE;

            /* we assume that WMNC_CLEAR_PROMPTS has already been
               received */

#ifdef DEBUG
            assert(IsRectEmpty(&d->r_custprompt));
#endif

            khui_cw_lock_nc(d->nc);

#if 0
            /* special case, we have one prompt and it is a password
               prompt.  very common */
            if(d->nc->n_prompts == 1 && 
               d->nc->prompts[0]->type == KHUI_NCPROMPT_TYPE_PASSWORD) {

                hw = GetDlgItem(d->dlg_main, IDC_NC_PASSWORD);
                EnableWindow(hw, TRUE);

                d->nc->prompts[0]->flags |= KHUI_NCPROMPT_FLAG_STOCK;
                d->nc->prompts[0]->hwnd_edit = hw;
                d->nc->prompts[0]->hwnd_static = NULL; /* don't care */

                khui_cw_unlock_nc(d->nc);
                break;
            }
#endif
            /* for everything else */

            y = d->r_idspec.bottom;

            d->r_custprompt.left = d->r_area.left;
            d->r_custprompt.right = d->r_area.right;
            d->r_custprompt.top = y;

            hf = (HFONT) SendMessage(d->dlg_main, WM_GETFONT, 0, 0);

            if (d->nc->pname != NULL) {
                hw =
                    CreateWindowEx
                    (0,
                     L"STATIC",
                     d->nc->pname,
                     SS_SUNKEN | WS_CHILD,
                     d->r_area.left, y,
                     d->r_row.right, 
                     d->r_n_label.bottom - d->r_n_label.top,
                     d->dlg_main,
                     NULL,
                     khm_hInstance,
                     NULL);

#ifdef DEBUG
                assert(hw);
#endif
                d->hwnd_name = hw;
                SendMessage(hw, WM_SETFONT, (WPARAM)hf, (LPARAM) TRUE);
                ShowWindow(hw, SW_SHOW);

                y += d->r_n_label.bottom - d->r_n_label.top;
            }

            if (d->nc->banner != NULL) {
                hw = 
                    CreateWindowEx
                    (0,
                     L"STATIC",
                     d->nc->banner,
                     WS_CHILD,
                     d->r_area.left, y,
                     d->r_row.right, d->r_row.bottom,
                     d->dlg_main,
                     NULL,
                     khm_hInstance,
                     NULL);
#ifdef DEBUG
                assert(hw);
#endif
                d->hwnd_banner = hw;
                SendMessage(hw, WM_SETFONT, (WPARAM)hf, (LPARAM)TRUE);
                ShowWindow(hw, SW_SHOW);
                y += d->r_row.bottom;
            }

            hw_prev = d->hwnd_last_idspec;

            hdc = GetWindowDC(d->dlg_main);
            hfold = SelectObject(hdc,hf);

            /* first do a trial run and see if we should use the
               larger text labels or not.  This is so that all the
               labels and input controls align properly. */
            for (i=0; i < d->nc->n_prompts; i++) {
                if (d->nc->prompts[i]->prompt != NULL) {
                    SIZE s;

                    GetTextExtentPoint32(hdc, 
                                         d->nc->prompts[i]->prompt, 
                                         (int) wcslen(d->nc->prompts[i]->prompt),
                                         &s);

                    if(s.cx >= d->r_n_label.right - d->r_n_label.left) {
                        use_large_lables = TRUE;
                        break;
                    }
                }
            }

            for(i=0; i<d->nc->n_prompts; i++) {
                RECT pr, er;
                SIZE s;
                int dy;

                if(d->nc->prompts[i]->prompt != NULL) {
                    GetTextExtentPoint32(hdc, 
                                         d->nc->prompts[i]->prompt, 
                                         (int) wcslen(d->nc->prompts[i]->prompt),
                                         &s);
                    if(s.cx < d->r_n_label.right - d->r_n_label.left &&
                       !use_large_lables) {
                        CopyRect(&pr, &d->r_n_label);
                        CopyRect(&er, &d->r_n_input);
                        dy = d->r_row.bottom;
                    } else if(s.cx <
                              d->r_e_label.right - d->r_e_label.left) {
                        CopyRect(&pr, &d->r_e_label);
                        CopyRect(&er, &d->r_e_input);
                        dy = d->r_row.bottom;
                    } else {
                        /* oops. the prompt doesn't fit in our
                           controls.  we need to use up two lines */
                        pr.left = 0;
                        pr.right = d->r_row.right;
                        pr.top = 0;
                        pr.bottom = d->r_n_label.bottom - 
                            d->r_n_label.top;
                        CopyRect(&er, &d->r_n_input);
                        OffsetRect(&er, 0, pr.bottom);
                        dy = er.bottom + (d->r_row.bottom - 
                                          d->r_n_input.bottom);
                    }
                } else {
                    SetRectEmpty(&pr);
                    CopyRect(&er, &d->r_n_input);
                    dy = d->r_row.bottom;
                }

                if(IsRectEmpty(&pr)) {
                    d->nc->prompts[i]->hwnd_static = NULL;
                } else {
                    OffsetRect(&pr, d->r_area.left, y);

                    hw = CreateWindowEx
                        (0,
                         L"STATIC",
                         d->nc->prompts[i]->prompt,
                         WS_CHILD,
                         pr.left, pr.top,
                         pr.right - pr.left, pr.bottom - pr.top,
                         d->dlg_main,
                         NULL,
                         khm_hInstance,
                         NULL);
#ifdef DEBUG
                    assert(hw);
#endif

                    SendMessage(hw, WM_SETFONT, 
                                (WPARAM) hf, (LPARAM) TRUE);

                    SetWindowPos(hw, hw_prev,
                                 0, 0, 0, 0,
                                 SWP_NOACTIVATE | SWP_NOMOVE |
                                 SWP_NOOWNERZORDER | SWP_NOSIZE |
                                 SWP_SHOWWINDOW);

                    d->nc->prompts[i]->hwnd_static = hw;
                    hw_prev = hw;
                }

                OffsetRect(&er, d->r_area.left, y);

                hw = CreateWindowEx
                    (0,
                     L"EDIT",
                     (d->nc->prompts[i]->def ? 
                      d->nc->prompts[i]->def : L""),
                     WS_CHILD | WS_TABSTOP |
                     WS_BORDER | ES_AUTOHSCROLL |
                     ((d->nc->prompts[i]->flags & 
                       KHUI_NCPROMPT_FLAG_HIDDEN)? ES_PASSWORD:0),
                     er.left, er.top,
                     er.right - er.left, er.bottom - er.top,
                     d->dlg_main,
                     NULL,
                     khm_hInstance,
                     NULL);

#ifdef DEBUG
                assert(hw);
#endif

                SendMessage(hw, WM_SETFONT, 
                            (WPARAM) hf, (LPARAM) TRUE);

                SetWindowPos(hw, hw_prev,
                             0, 0, 0, 0, 
                             SWP_NOACTIVATE | SWP_NOMOVE | 
                             SWP_NOOWNERZORDER | SWP_NOSIZE | 
                             SWP_SHOWWINDOW);

                SendMessage(hw, EM_SETLIMITTEXT,
                            KHUI_MAXCCH_PROMPT_VALUE -1,
                            0);

                d->nc->prompts[i]->hwnd_edit = hw;

                hw_prev = hw;

                y += dy;
            }

            if (d->nc->n_prompts > 0 &&
                d->nc->prompts[0]->hwnd_edit) {

                PostMessage(d->dlg_main, WM_NEXTDLGCTL,
                            (WPARAM) d->nc->prompts[0]->hwnd_edit,
                            MAKELPARAM(TRUE, 0));

            }

            SelectObject(hdc, hfold);
            ReleaseDC(d->dlg_main, hdc);

            khui_cw_unlock_nc(d->nc);

            d->r_custprompt.bottom = y;

            if (d->r_custprompt.bottom == d->r_custprompt.top)
                SetRectEmpty(&d->r_custprompt);

            nc_layout_main_panel(d);

            nc_layout_new_cred_window(d);
        }
        break;

    case WMNC_DIALOG_PROCESS_COMPLETE:
        {
            khui_new_creds * nc;

            nc = d->nc;

            nc->response &= ~KHUI_NC_RESPONSE_PROCESSING;

            if(nc->response & KHUI_NC_RESPONSE_NOEXIT) {
                HWND hw;

                nc_enable_controls(d, TRUE);

                /* reset state */
                nc->result = KHUI_NC_RESULT_CANCEL;

                hw = GetDlgItem(d->dlg_main, IDOK);
                EnableWindow(hw, TRUE);
                hw = GetDlgItem(d->dlg_main, IDCANCEL);
                EnableWindow(hw, TRUE);
                hw = GetDlgItem(d->dlg_main, IDC_NC_ADVANCED);
                EnableWindow(hw, TRUE);
                hw = GetDlgItem(d->dlg_bb, IDOK);
                EnableWindow(hw, TRUE);
                hw = GetDlgItem(d->dlg_bb, IDCANCEL);
                EnableWindow(hw, TRUE);

                nc_clear_password_fields(d);

                return TRUE;
            }

            DestroyWindow(hwnd);

            kmq_post_message(KMSG_CRED, KMSG_CRED_END, 0, (void *) nc);
        }
        break;

        /* MUST be called with SendMessage */
    case WMNC_ADD_CONTROL_ROW:
        {
            khui_control_row * row;

            row = (khui_control_row *) lParam;

#ifdef DEBUG
            assert(row->label);
            assert(row->input);
#endif

            nc_add_control_row(d, row->label, row->input, row->size);
        }
        break;

    case WMNC_UPDATE_LAYOUT:
        {

            RECT r_client;
            khm_int32 animate;
            khm_int32 steps;
            khm_int32 timeout;

            /* We are already adjusting the size of the window.  The
               next time the timer fires, it will notice if the target
               size has changed. */
            if (d->size_changing)
                return TRUE;

            GetClientRect(hwnd, &r_client);

            if ((r_client.right - r_client.left ==
                 d->r_required.right - d->r_required.left) &&
                (r_client.bottom - r_client.top ==
                 d->r_required.bottom - d->r_required.top)) {

                /* the window is already at the right size */
                return TRUE;

            }

            if (!IsWindowVisible(hwnd)) {
                /* The window is not visible yet.  There's no need to
                   animate anything. */

                animate = FALSE;

            } else if (KHM_FAILED(khc_read_int32(NULL,
                                                 L"CredWindow\\Windows\\NewCred\\AnimateSizeChanges",
                                                 &animate))) {
#ifdef DEBUG
                assert(FALSE);
#endif
                animate = TRUE;
            }

            /* if we aren't animating the window resize, then we just
               do it in one call. */
            if (!animate || !d->animation_enabled) {
                RECT r_window;

                CopyRect(&r_window, &d->r_required);
                AdjustWindowRectEx(&r_window, NC_WINDOW_STYLES, FALSE,
                                   NC_WINDOW_EX_STYLES);

                SetWindowPos(hwnd, NULL, 0, 0,
                             r_window.right - r_window.left,
                             r_window.bottom - r_window.top,
                             SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER |
                             SWP_NOZORDER);

                return TRUE;
            }

            if (KHM_FAILED(khc_read_int32(NULL,
                                          L"CredWindow\\Windows\\NewCred\\AnimationSteps",
                                          &steps))) {
#ifdef DEBUG
                assert(FALSE);
#endif
                steps = NC_SZ_STEPS_DEF;
            } else {

                if (steps < NC_SZ_STEPS_MIN)
                    steps = NC_SZ_STEPS_MIN;
                else if (steps > NC_SZ_STEPS_MAX)
                    steps = NC_SZ_STEPS_MAX;

            }

            if (KHM_FAILED(khc_read_int32(NULL,
                                          L"CredWindow\\Windows\\NewCred\\AnimationStepTimeout",
                                          &timeout))) {
#ifdef DEBUG
                assert(FALSE);
#endif
                timeout = NC_SZ_TIMEOUT_DEF;
            } else {

                if (timeout < NC_SZ_TIMEOUT_MIN)
                    timeout = NC_SZ_TIMEOUT_MIN;
                else if (timeout > NC_SZ_TIMEOUT_MAX)
                    timeout = NC_SZ_TIMEOUT_MAX;

            }

            CopyRect(&d->sz_ch_source, &r_client);
            OffsetRect(&d->sz_ch_source, -d->sz_ch_source.left, -d->sz_ch_source.top);
            CopyRect(&d->sz_ch_target, &d->r_required);
            OffsetRect(&d->sz_ch_target, -d->sz_ch_target.left, -d->sz_ch_target.top);
            d->sz_ch_increment = 0;
            d->sz_ch_max = steps;
            d->sz_ch_timeout = timeout;
            d->size_changing = TRUE;

            SetTimer(hwnd, NC_TIMER_SIZER, timeout, NULL);
        }
        break;
    } /* switch(HIWORD(wParam)) */

    return TRUE;
}

static LRESULT nc_handle_wm_timer(HWND hwnd,
                                  UINT uMsg,
                                  WPARAM wParam,
                                  LPARAM lParam) {
    khui_nc_wnd_data * d;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);
    if (d == NULL)
        return FALSE;

    if (wParam == NC_TIMER_SIZER) {

        RECT r_now;

        /* are we done with this sizing operation? */
        if (!d->size_changing ||
            d->sz_ch_increment >= d->sz_ch_max) {

            d->size_changing = FALSE;
            KillTimer(hwnd, NC_TIMER_SIZER);
            return 0;
        }

        /* have the requirements changed while we were processing the
           sizing operation? */
        if ((d->r_required.right - d->r_required.left !=
             d->sz_ch_target.right)

            ||

            (d->r_required.bottom - d->r_required.top !=
             d->sz_ch_target.bottom)) {

            /* the target size has changed.  we need to restart the
               sizing operation. */

            RECT r_client;

            GetClientRect(hwnd, &r_client);

            CopyRect(&d->sz_ch_source, &r_client);
            OffsetRect(&d->sz_ch_source, -d->sz_ch_source.left, -d->sz_ch_source.top);
            CopyRect(&d->sz_ch_target, &d->r_required);
            OffsetRect(&d->sz_ch_target, -d->sz_ch_target.left, -d->sz_ch_target.top);
            d->sz_ch_increment = 0;

            /* leave the other fields alone */

#ifdef DEBUG
            assert(d->sz_ch_max >= NC_SZ_STEPS_MIN);
            assert(d->sz_ch_max <= NC_SZ_STEPS_MAX);
            assert(d->sz_ch_timeout >= NC_SZ_TIMEOUT_MIN);
            assert(d->sz_ch_timeout <= NC_SZ_TIMEOUT_MAX);
            assert(d->size_changing);
#endif
        }

        /* we are going to do the next increment */
        d->sz_ch_increment ++;

        /* now, figure out the size of the client area for this
           step */

        r_now.left = 0;
        r_now.top = 0;

#define PROPORTION(v1, v2, i, s) (((v1) * ((s) - (i)) + (v2) * (i)) / (s))

        r_now.right = PROPORTION(d->sz_ch_source.right, d->sz_ch_target.right,
                                 d->sz_ch_increment, d->sz_ch_max);

        r_now.bottom = PROPORTION(d->sz_ch_source.bottom, d->sz_ch_target.bottom,
                                  d->sz_ch_increment, d->sz_ch_max);

#undef  PROPORTION

#ifdef DEBUG
        {
            long dx = ((r_now.right - r_now.left) - d->sz_ch_target.right) *
                (d->sz_ch_source.right - d->sz_ch_target.right);

            long dy = ((r_now.bottom - r_now.top) - d->sz_ch_target.bottom) *
                (d->sz_ch_source.bottom - d->sz_ch_target.bottom);

            if (dx < 0 || dy < 0) {
                KillTimer(hwnd, NC_TIMER_SIZER);
                assert(dx >= 0);
                assert(dy >= 0);
                SetTimer(hwnd, NC_TIMER_SIZER, d->sz_ch_timeout, NULL);
            }
        }
#endif

        AdjustWindowRectEx(&r_now, NC_WINDOW_STYLES, FALSE,
                           NC_WINDOW_EX_STYLES);

        {
            RECT r;

            GetWindowRect(hwnd, &r);
            OffsetRect(&r_now, r.left - r_now.left, r.top - r_now.top);
        }

        khm_adjust_window_dimensions_for_display(&r_now, 0);

        SetWindowPos(hwnd, NULL,
                     r_now.left, r_now.top,
                     r_now.right - r_now.left,
                     r_now.bottom - r_now.top,
                     SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                     SWP_NOZORDER);

        /* and now we wait for the next timer message */

        return 0;
    } else if (wParam == NC_TIMER_ENABLEANIMATE) {

        d->animation_enabled = TRUE;
        KillTimer(hwnd, NC_TIMER_ENABLEANIMATE);
    }

    return 0;
}

static LRESULT nc_handle_wm_notify(HWND hwnd,
                                   UINT uMsg,
                                   WPARAM wParam,
                                   LPARAM lParam) {

    LPNMHDR nmhdr;
    khui_nc_wnd_data * d;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);
    if (d == NULL)
        return FALSE;

    nmhdr = (LPNMHDR) lParam;

    if (nmhdr->code == TCN_SELCHANGE) {
        /* the current tab has changed. */
        int idx;
        TCITEM tcitem;

        idx = TabCtrl_GetCurSel(d->tab_wnd);
        ZeroMemory(&tcitem, sizeof(tcitem));

        tcitem.mask = TCIF_PARAM;
        TabCtrl_GetItem(d->tab_wnd, idx, &tcitem);

        d->current_panel = (int) tcitem.lParam;

        nc_layout_new_cred_window(d);

        return TRUE;
    }

    return FALSE;
}

static LRESULT nc_handle_wm_help(HWND hwnd,
                                 UINT uMsg,
                                 WPARAM wParam,
                                 LPARAM lParam) {
    static DWORD ctxids[] = {
        NC_TS_CTRL_ID_MIN, IDH_NC_TABMAIN,
        NC_TS_CTRL_ID_MIN + 1, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 2, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 3, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 4, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 5, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 6, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 7, IDH_NC_TABBUTTON,
        IDOK, IDH_NC_OK,
        IDCANCEL, IDH_NC_CANCEL,
        IDC_NC_HELP, IDH_NC_HELP,
        IDC_NC_ADVANCED, IDH_NC_ADVANCED,
        IDC_NC_CREDTEXT, IDH_NC_CREDWND,
        0
    };

    HELPINFO * hlp;
    HWND hw = NULL;
    HWND hw_ctrl;
    khui_nc_wnd_data * d;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);
    if (d == NULL)
        return FALSE;

    hlp = (HELPINFO *) lParam;

    if (d->nc->subtype != KMSG_CRED_NEW_CREDS &&
        d->nc->subtype != KMSG_CRED_PASSWORD)
        return TRUE;

    if (hlp->iContextType != HELPINFO_WINDOW)
        return TRUE;

    if (hlp->hItemHandle != NULL &&
        hlp->hItemHandle != hwnd) {
        DWORD id;
        int i;

        hw_ctrl =hlp->hItemHandle;

        id = GetWindowLong(hw_ctrl, GWL_ID);
        for (i=0; ctxids[i] != 0; i += 2)
            if (ctxids[i] == id)
                break;

        if (ctxids[i] != 0)
            hw = khm_html_help(hw_ctrl,
                               ((d->nc->subtype == KMSG_CRED_NEW_CREDS)?
                                L"::popups_newcreds.txt":
                                L"::popups_password.txt"),
                               HH_TP_HELP_WM_HELP,
                               (DWORD_PTR) ctxids);
    }

    if (hw == NULL) {
        khm_html_help(hwnd, NULL, HH_HELP_CONTEXT,
                      ((d->nc->subtype == KMSG_CRED_NEW_CREDS)?
                       IDH_ACTION_NEW_ID: IDH_ACTION_PASSWD_ID));
    }

    return TRUE;
}

static LRESULT nc_handle_wm_activate(HWND hwnd,
                                     UINT uMsg,
                                     WPARAM wParam,
                                     LPARAM lParam) {
    if (uMsg == WM_MOUSEACTIVATE ||
        wParam == WA_ACTIVE || wParam == WA_CLICKACTIVE) {

        FLASHWINFO fi;
        khui_nc_wnd_data * d;
        DWORD_PTR ex_style;

        d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);

        if (d && d->flashing_enabled) {
            ZeroMemory(&fi, sizeof(fi));

            fi.cbSize = sizeof(fi);
            fi.hwnd = hwnd;
            fi.dwFlags = FLASHW_STOP;

            FlashWindowEx(&fi);

            d->flashing_enabled = FALSE;
        }

        ex_style = GetWindowLongPtr(hwnd, GWL_EXSTYLE);

        if (ex_style & WS_EX_TOPMOST) {
            SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        }
    }

    return (uMsg == WM_MOUSEACTIVATE)? MA_ACTIVATE : 0;
}

static LRESULT CALLBACK nc_window_proc(HWND hwnd,
                                       UINT uMsg,
                                       WPARAM wParam,
                                       LPARAM lParam)
{
    switch(uMsg) {
    case WM_MOUSEACTIVATE:
    case WM_ACTIVATE:
        return nc_handle_wm_activate(hwnd, uMsg, wParam, lParam);

    case WM_CREATE:
        return nc_handle_wm_create(hwnd, uMsg, wParam, lParam);

    case WM_DESTROY:
        return nc_handle_wm_destroy(hwnd, uMsg, wParam, lParam);

    case WM_COMMAND:
        return nc_handle_wm_command(hwnd, uMsg, wParam, lParam);

    case WM_NOTIFY:
        return nc_handle_wm_notify(hwnd, uMsg, wParam, lParam);

    case WM_MOVE:
    case WM_MOVING:
        return nc_handle_wm_moving(hwnd, uMsg, wParam, lParam);

    case WM_TIMER:
        return nc_handle_wm_timer(hwnd, uMsg, wParam, lParam);

    case WM_HELP:
        return nc_handle_wm_help(hwnd, uMsg, wParam, lParam);

    case KHUI_WM_NC_NOTIFY:
        return nc_handle_wm_nc_notify(hwnd, uMsg, wParam, lParam);
    }

    /* Note that this is technically a dialog box */
    return DefDlgProc(hwnd, uMsg, wParam, lParam);
}

void khm_register_newcredwnd_class(void)
{
    WNDCLASSEX wcx;

    wcx.cbSize = sizeof(wcx);
    wcx.style = CS_DBLCLKS | CS_OWNDC;
    wcx.lpfnWndProc = nc_window_proc;
    wcx.cbClsExtra = 0;
    wcx.cbWndExtra = DLGWINDOWEXTRA + sizeof(LONG_PTR);
    wcx.hInstance = khm_hInstance;
    wcx.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(IDI_MAIN_APP));
    wcx.hCursor = LoadCursor((HINSTANCE) NULL, IDC_ARROW);
    wcx.hbrBackground = (HBRUSH) (COLOR_BTNFACE + 1);
    wcx.lpszMenuName = NULL;
    wcx.lpszClassName = KHUI_NEWCREDWND_CLASS;
    wcx.hIconSm = NULL;

    khui_newcredwnd_cls = RegisterClassEx(&wcx);
}

void khm_unregister_newcredwnd_class(void)
{
    UnregisterClass(MAKEINTATOM(khui_newcredwnd_cls), khm_hInstance);
}

HWND khm_create_newcredwnd(HWND parent, khui_new_creds * c)
{
    wchar_t wtitle[256];
    HWND hwnd;
    khm_int32 force_topmost = 0;

    if (c->window_title == NULL) {
        if (c->subtype == KMSG_CRED_PASSWORD)
            LoadString(khm_hInstance, 
                       IDS_WT_PASSWORD,
                       wtitle,
                       ARRAYLENGTH(wtitle));
        else
            LoadString(khm_hInstance, 
                       IDS_WT_NEW_CREDS,
                       wtitle,
                       ARRAYLENGTH(wtitle));
    }

    khc_read_int32(NULL, L"CredWindow\\Windows\\NewCred\\ForceToTop", &force_topmost);

    hwnd = CreateWindowEx(NC_WINDOW_EX_STYLES | (force_topmost ? WS_EX_TOPMOST : 0),
                          MAKEINTATOM(khui_newcredwnd_cls),
                          ((c->window_title)?c->window_title: wtitle),
                          NC_WINDOW_STYLES,
                          0,0,400,400,    /* bogus values.  the window
                                             is going to resize and
                                             reposition itself
                                             anyway */
                          parent,
                          NULL,
                          khm_hInstance,
                          (LPVOID) c);

#ifdef DEBUG
    assert(hwnd != NULL);
#endif

    /* note that the window is not visible yet.  That's because, at
       this point we don't know what the panels are */

    return hwnd;
}

void khm_prep_newcredwnd(HWND hwnd)
{
    SendMessage(hwnd, KHUI_WM_NC_NOTIFY, 
                MAKEWPARAM(0, WMNC_DIALOG_SETUP), 0);
}

void khm_show_newcredwnd(HWND hwnd)
{
    /* add all the panels in and prep UI */
    PostMessage(hwnd, KHUI_WM_NC_NOTIFY, 
                MAKEWPARAM(0, WMNC_DIALOG_ACTIVATE), 0);
}
