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

#include<khmapp.h>
#include<assert.h>

typedef struct tag_notif_data {
    khui_config_node node;

    BOOL modified;

    BOOL monitor;
    BOOL renew;
    BOOL halflife;
    BOOL warn1;
    BOOL warn2;

    khui_tracker tc_renew;
    khui_tracker tc_warn1;
    khui_tracker tc_warn2;
} notif_data;

static void
read_params(notif_data * d) {
    khm_handle csp_cw;
    khm_int32 rv;
    khm_int32 t;

    rv = khc_open_space(NULL, L"CredWindow", KHM_PERM_READ, &csp_cw);
    assert(KHM_SUCCEEDED(rv));

    rv = khc_read_int32(csp_cw, L"Monitor", &t);
    assert(KHM_SUCCEEDED(rv));
    d->monitor = !!t;

    rv = khc_read_int32(csp_cw, L"AllowAutoRenew", &t);
    assert(KHM_SUCCEEDED(rv));
    d->renew = !!t;

    rv = khc_read_int32(csp_cw, L"RenewAtHalfLife", &t);
    assert(KHM_SUCCEEDED(rv));
    d->halflife = !!t;

    rv = khc_read_int32(csp_cw, L"AllowWarn", &t);
    assert(KHM_SUCCEEDED(rv));
    d->warn1 = !!t;

    rv = khc_read_int32(csp_cw, L"AllowCritical", &t);
    assert(KHM_SUCCEEDED(rv));
    d->warn2 = !!t;

    rv = khc_read_int32(csp_cw, L"AutoRenewThreshold", &t);
    assert(KHM_SUCCEEDED(rv));
    d->tc_renew.current = t;

    rv = khc_read_int32(csp_cw, L"WarnThreshold", &t);
    assert(KHM_SUCCEEDED(rv));
    d->tc_warn1.current = t;

    rv = khc_read_int32(csp_cw, L"CriticalThreshold", &t);
    assert(KHM_SUCCEEDED(rv));
    d->tc_warn2.current = t;

    rv = khc_read_int32(csp_cw, L"MaxThreshold", &t);
    assert(KHM_SUCCEEDED(rv));
    d->tc_renew.max = t;
    d->tc_warn1.max = t;
    d->tc_warn2.max = t;

    rv = khc_read_int32(csp_cw, L"MinThreshold", &t);
    assert(KHM_SUCCEEDED(rv));
    d->tc_renew.min = t;
    d->tc_warn1.min = t;
    d->tc_warn2.min = t;

    khc_close_space(csp_cw);

    d->modified = FALSE;
}

static void
check_for_modification(notif_data * d) {
    notif_data t;

    ZeroMemory(&t, sizeof(t));

    read_params(&t);

    if ((!!d->monitor) != (!!t.monitor) ||
        (!!d->renew) != (!!t.renew) ||
        (!!d->halflife) != (!!t.halflife) ||
        (!!d->warn1) != (!!t.warn1) ||
        (!!d->warn2) != (!!t.warn2) ||
        d->tc_renew.current != t.tc_renew.current ||
        d->tc_warn1.current != t.tc_warn1.current ||
        d->tc_warn2.current != t.tc_warn2.current) {

        khui_cfg_set_flags(d->node,
                           KHUI_CNFLAG_MODIFIED,
                           KHUI_CNFLAG_MODIFIED);

        d->modified = TRUE;

    } else {
        khui_cfg_set_flags(d->node,
                           0,
                           KHUI_CNFLAG_MODIFIED);

        d->modified = FALSE;
    }
}

static void
write_params(notif_data * d) {
    khm_handle csp_cw;
    khm_int32 rv;

    if (!d->modified)
        return;

    rv = khc_open_space(NULL, L"CredWindow", KHM_PERM_WRITE, &csp_cw);
    assert(KHM_SUCCEEDED(rv));

    rv = khc_write_int32(csp_cw, L"Monitor", d->monitor);
    assert(KHM_SUCCEEDED(rv));

    rv = khc_write_int32(csp_cw, L"AllowAutoRenew", d->renew);
    assert(KHM_SUCCEEDED(rv));

    rv = khc_write_int32(csp_cw, L"RenewAtHalfLife", d->halflife);
    assert(KHM_SUCCEEDED(rv));

    rv = khc_write_int32(csp_cw, L"AllowWarn", d->warn1);
    assert(KHM_SUCCEEDED(rv));

    rv = khc_write_int32(csp_cw, L"AllowCritical", d->warn2);
    assert(KHM_SUCCEEDED(rv));


    rv = khc_write_int32(csp_cw, L"AutoRenewThreshold",
                         (khm_int32) d->tc_renew.current);
    assert(KHM_SUCCEEDED(rv));

    rv = khc_write_int32(csp_cw, L"WarnThreshold",
                         (khm_int32) d->tc_warn1.current);
    assert(KHM_SUCCEEDED(rv));

    rv = khc_write_int32(csp_cw, L"CriticalThreshold",
                         (khm_int32) d->tc_warn2.current);
    assert(KHM_SUCCEEDED(rv));

    khc_close_space(csp_cw);

    khui_cfg_set_flags(d->node,
                       KHUI_CNFLAG_APPLIED,
                       KHUI_CNFLAG_APPLIED | KHUI_CNFLAG_MODIFIED);

    khm_timer_refresh(hwnd_notifier);
}

static void
refresh_view(HWND hwnd, notif_data * d) {
    CheckDlgButton(hwnd, IDC_NOTIF_MONITOR,
                   (d->monitor?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_NOTIF_RENEW,
                   (d->renew?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_NOTIF_HALFLIFE,
                   (d->halflife?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_NOTIF_WARN1,
                   (d->warn1?BST_CHECKED:BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_NOTIF_WARN2,
                   (d->warn2?BST_CHECKED:BST_UNCHECKED));
    khui_tracker_refresh(&d->tc_renew);
    khui_tracker_refresh(&d->tc_warn1);
    khui_tracker_refresh(&d->tc_warn2);
    if (!d->monitor) {
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_RENEW), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_HALFLIFE), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_WARN1), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_WARN2), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_RENEW_THR), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_WARN1_THR), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_WARN2_THR), FALSE);
    } else {
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_RENEW), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_HALFLIFE), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_WARN1), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_WARN2), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_RENEW_THR), !!(d->renew));
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_WARN1_THR), !!(d->warn1));
        EnableWindow(GetDlgItem(hwnd, IDC_NOTIF_WARN2_THR), !!(d->warn2));
    }
}

static void
refresh_data(HWND hwnd, notif_data * d) {
    d->monitor = (IsDlgButtonChecked(hwnd, IDC_NOTIF_MONITOR)
                  == BST_CHECKED);
    d->renew   = (IsDlgButtonChecked(hwnd, IDC_NOTIF_RENEW)
                  == BST_CHECKED);
    d->halflife = (IsDlgButtonChecked(hwnd, IDC_NOTIF_HALFLIFE)
                   == BST_CHECKED);
    d->warn1   = (IsDlgButtonChecked(hwnd, IDC_NOTIF_WARN1)
                  == BST_CHECKED);
    d->warn2   = (IsDlgButtonChecked(hwnd, IDC_NOTIF_WARN2)
                  == BST_CHECKED);

    check_for_modification(d);
}

INT_PTR CALLBACK
khm_cfg_notifications_proc(HWND hwnd,
                           UINT uMsg,
                           WPARAM wParam,
                           LPARAM lParam) {

    notif_data * d;

    switch(uMsg) {
    case WM_INITDIALOG: {
        HWND hw;

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

        khui_tracker_initialize(&d->tc_renew);
        khui_tracker_initialize(&d->tc_warn1);
        khui_tracker_initialize(&d->tc_warn2);

        read_params(d);

        hw = GetDlgItem(hwnd, IDC_NOTIF_RENEW_THR);
        khui_tracker_install(hw, &d->tc_renew);

        hw = GetDlgItem(hwnd, IDC_NOTIF_WARN1_THR);
        khui_tracker_install(hw, &d->tc_warn1);

        hw = GetDlgItem(hwnd, IDC_NOTIF_WARN2_THR);
        khui_tracker_install(hw, &d->tc_warn2);

        refresh_view(hwnd, d);

        /* normally we should return TRUE, but in this case we return
           FALSE since we don't want to inadvertently steal the focus
           from the treeview. */
        return FALSE;
    }

    case WM_COMMAND: {
        d = (notif_data *) (DWORD_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            return FALSE;

        if (HIWORD(wParam) == BN_CLICKED) {
            refresh_data(hwnd, d);
            refresh_view(hwnd, d);

            check_for_modification(d);
        } else if (HIWORD(wParam) == EN_CHANGE) {
            SetTimer(hwnd, 1, 500, NULL);
        }

        khm_set_dialog_result(hwnd, 0);

        return TRUE;
    }

    case WM_TIMER: {
        d = (notif_data *) (DWORD_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            return FALSE;

        KillTimer(hwnd, 1);
        check_for_modification(d);

        khm_set_dialog_result(hwnd, 0);

        return TRUE;
    }

    case WM_DESTROY: {
        d = (notif_data *) (DWORD_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            return FALSE;

        khui_tracker_kill_controls(&d->tc_renew);
        khui_tracker_kill_controls(&d->tc_warn1);
        khui_tracker_kill_controls(&d->tc_warn2);

        PFREE(d);

        SetWindowLongPtr(hwnd, DWLP_USER, 0);

        khm_set_dialog_result(hwnd, 0);

        return TRUE;
    }

    case KHUI_WM_CFG_NOTIFY: {
        d = (notif_data *) (DWORD_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            return FALSE;

        if (HIWORD(wParam) == WMCFG_APPLY) {
            write_params(d);
        }

        khm_set_dialog_result(hwnd, 0);

        return TRUE;
    }

    }

    return FALSE;
}
