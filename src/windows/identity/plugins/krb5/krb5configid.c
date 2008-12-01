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

#include<krbcred.h>
#include<krb5.h>
#include<assert.h>
#include<lm.h>
#include<commctrl.h>
#include<shlwapi.h>

#include<strsafe.h>

typedef struct tag_k5_id_dlg_data {
    khui_config_init_data cfg;

    khm_handle   ident;

    khui_tracker tc_life;
    khui_tracker tc_renew;

    wchar_t ccache[KRB5_MAXCCH_CCNAME];

    khm_boolean renewable;
    khm_boolean forwardable;
    khm_boolean proxiable;
    khm_boolean addressless;

    DWORD public_ip;

    time_t life;
    time_t renew_life;
} k5_id_dlg_data;

static void
k5_id_read_params(k5_id_dlg_data * d) {

    wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
    khm_size cb;
    khm_int32 rv;
    khm_int32 t;
    khm_handle csp_ident = NULL;

    cb = sizeof(idname);
    rv = khui_cfg_get_name(d->cfg.ctx_node, idname, &cb);
#ifdef DEBUG
    assert(KHM_SUCCEEDED(rv));
#endif

    rv = kcdb_identity_create(idname, 0, &d->ident);
#ifdef DEBUG
    assert(KHM_SUCCEEDED(rv));
#endif

    khm_krb5_get_identity_config(d->ident, 0, &csp_ident);

    rv = khc_read_int32(csp_ident, L"DefaultLifetime",  &t);
    if (KHM_SUCCEEDED(rv))
        d->life = t;
    else
        d->life = 36000;

    rv = khc_read_int32(csp_ident, L"DefaultRenewLifetime", &t);
    if (KHM_SUCCEEDED(rv))
        d->renew_life = t;
    else
        d->renew_life = 604800;

    rv = khc_read_int32(csp_ident, L"Renewable", &t);
    if (KHM_SUCCEEDED(rv))
        d->renewable = !!t;
    else
        d->renewable = TRUE;

    rv = khc_read_int32(csp_ident, L"Forwardable", &t);
    if (KHM_SUCCEEDED(rv))
        d->forwardable = !!t;
    else
        d->forwardable = FALSE;

    rv = khc_read_int32(csp_ident, L"Proxiable", &t);
    if (KHM_SUCCEEDED(rv))
        d->proxiable = !!t;
    else
        d->proxiable = FALSE;

    rv = khc_read_int32(csp_ident, L"Addressless", &t);
    if (KHM_SUCCEEDED(rv))
        d->addressless = !!t;
    else
        d->addressless = TRUE;

    rv = khc_read_int32(csp_ident, L"PublicIP", &t);
    if (KHM_SUCCEEDED(rv))
        d->public_ip = (khm_ui_4) t;
    else
        d->public_ip = 0;

    cb = sizeof(d->ccache);
    rv = khm_krb5_get_identity_default_ccache(d->ident, d->ccache, &cb);

#ifdef DEBUG
    assert(KHM_SUCCEEDED(rv));
#endif

    khui_tracker_initialize(&d->tc_life);
    d->tc_life.current = d->life;
    d->tc_life.min = 0;
    d->tc_life.max = 3600 * 24 * 7;

    khui_tracker_initialize(&d->tc_renew);
    d->tc_renew.current = d->renew_life;
    d->tc_renew.min = 0;
    d->tc_renew.max = 3600 * 24 * 30;

    if (csp_ident)
        khc_close_space(csp_ident);
}

static khm_boolean
k5_id_is_mod(HWND hw, k5_id_dlg_data * d) {
    wchar_t ccache[KRB5_MAXCCH_CCNAME];
    DWORD dwaddress = 0;

    GetDlgItemText(hw, IDC_CFG_CCACHE, ccache, ARRAYLENGTH(ccache));

    SendDlgItemMessage(hw, IDC_CFG_PUBLICIP, IPM_GETADDRESS,
                       0, (LPARAM) &dwaddress);

    if (_wcsicmp(ccache, d->ccache) ||

        d->tc_renew.current != d->renew_life ||

        d->tc_life.current != d->life ||

        (IsDlgButtonChecked(hw, IDC_CFG_RENEW) == BST_CHECKED) != d->renewable ||

        (IsDlgButtonChecked(hw, IDC_CFG_FORWARD) == BST_CHECKED) != d->forwardable ||

        (IsDlgButtonChecked(hw, IDC_CFG_ADDRESSLESS) == BST_CHECKED)
        != d->addressless ||

        dwaddress != d->public_ip)

        return TRUE;

    return FALSE;
}

static void
k5_id_check_mod(HWND hw, k5_id_dlg_data * d) {
    BOOL modified = k5_id_is_mod(hw, d);

    khui_cfg_set_flags_inst(&d->cfg,
                            (modified)?KHUI_CNFLAG_MODIFIED:0,
                            KHUI_CNFLAG_MODIFIED);
}

static void
k5_id_write_params(HWND hw, k5_id_dlg_data * d) {

    khm_handle csp_idroot = NULL;
    khm_handle csp_ident = NULL;
    wchar_t ccache[KRB5_MAXCCH_CCNAME];
    khm_size cb;
    khm_int32 rv;
    khm_boolean b;
    khm_boolean applied = FALSE;
    DWORD dwaddress = 0;

    if (!k5_id_is_mod(hw, d))
        return;

    rv = kcdb_identity_get_config(d->ident, KHM_FLAG_CREATE, &csp_idroot);
    if (KHM_SUCCEEDED(rv)) {
        khc_open_space(csp_idroot, CSNAME_KRB5CRED,
                       KHM_FLAG_CREATE | KCONF_FLAG_WRITEIFMOD,
                       &csp_ident);
    }

    if (csp_idroot)
        khc_close_space(csp_idroot);

    if (!csp_ident)
        return;

    if (d->life != d->tc_life.current) {
        d->life = d->tc_life.current;
        khc_write_int32(csp_ident, L"DefaultLifetime", (khm_int32) d->life);
        applied = TRUE;
    }

    if (d->renew_life != d->tc_renew.current) {
        d->renew_life = d->tc_renew.current;
        khc_write_int32(csp_ident, L"DefaultRenewLifetime", (khm_int32) d->renew_life);
        applied = TRUE;
    }

    b = (IsDlgButtonChecked(hw, IDC_CFG_RENEW) == BST_CHECKED);
    if (b != d->renewable) {
        d->renewable = b;
        khc_write_int32(csp_ident, L"Renewable", (khm_int32) b);
        applied = TRUE;
    }

    b = (IsDlgButtonChecked(hw, IDC_CFG_FORWARD) == BST_CHECKED);
    if (b != d->forwardable) {
        d->forwardable = b;
        khc_write_int32(csp_ident, L"Forwardable", (khm_int32) b);
        applied = TRUE;
    }

    b = (IsDlgButtonChecked(hw, IDC_CFG_ADDRESSLESS) == BST_CHECKED);
    if (b != d->addressless) {
        d->addressless = b;
        khc_write_int32(csp_ident, L"Addressless", (khm_int32) b);
        applied = TRUE;
    }

    SendDlgItemMessage(hw, IDC_CFG_PUBLICIP, IPM_GETADDRESS,
                       0, (LPARAM) &dwaddress);

    if (dwaddress != d->public_ip) {
        d->public_ip = dwaddress;
        khc_write_int32(csp_ident, L"PublicIP", (khm_int32) dwaddress);
        applied = TRUE;
    }

    GetDlgItemText(hw, IDC_CFG_CCACHE, ccache, ARRAYLENGTH(ccache));

    if (SUCCEEDED(StringCbLength(ccache, sizeof(ccache), &cb)) &&
        cb > sizeof(wchar_t)) {

        if (wcscmp(ccache, d->ccache)) {
            khc_write_string(csp_ident, L"DefaultCCName", ccache);
            StringCbCopy(d->ccache, sizeof(d->ccache), ccache);
            applied = TRUE;
        }

    } else {
        khc_remove_value(csp_ident, L"DefaultCCName", KCONF_FLAG_USER);
        d->ccache[0] = L'\0';
        applied = TRUE;
    }

    if (csp_ident)
        khc_close_space(csp_ident);

    khui_cfg_set_flags_inst(&d->cfg,
                            (applied ? KHUI_CNFLAG_APPLIED : 0),
                            KHUI_CNFLAG_APPLIED | KHUI_CNFLAG_MODIFIED);
}

INT_PTR CALLBACK 
k5_id_tab_dlgproc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {

    k5_id_dlg_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        d = PMALLOC(sizeof(*d));
#ifdef DEBUG
        assert(d);
#endif
        ZeroMemory(d, sizeof(*d));

        d->cfg = *((khui_config_init_data *) lParam);

#pragma warning(push)
#pragma warning(disable: 4244)
        SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

        k5_id_read_params(d);

        khui_tracker_install(GetDlgItem(hwnd, IDC_CFG_DEFLIFE),
                             &d->tc_life);
        khui_tracker_install(GetDlgItem(hwnd, IDC_CFG_DEFRLIFE),
                             &d->tc_renew);
        khui_tracker_refresh(&d->tc_life);
        khui_tracker_refresh(&d->tc_renew);

        SetDlgItemText(hwnd, IDC_CFG_CCACHE, d->ccache);

        CheckDlgButton(hwnd, IDC_CFG_RENEW,
                       (d->renewable? BST_CHECKED: BST_UNCHECKED));

        CheckDlgButton(hwnd, IDC_CFG_FORWARD,
                       (d->forwardable? BST_CHECKED: BST_UNCHECKED));

        CheckDlgButton(hwnd, IDC_CFG_ADDRESSLESS,
                       (d->addressless? BST_CHECKED: BST_UNCHECKED));

        SendDlgItemMessage(hwnd, IDC_CFG_PUBLICIP,
                           IPM_SETADDRESS,
                           0, (LPARAM) d->public_ip);
        break;

    case WM_COMMAND:
        d = (k5_id_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d == NULL)
            break;

        if (HIWORD(wParam) == EN_CHANGE ||
            HIWORD(wParam) == BN_CLICKED)
            k5_id_check_mod(hwnd, d);
        break;

    case KHUI_WM_CFG_NOTIFY:
        d = (k5_id_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d == NULL)
            break;

        if (HIWORD(wParam) == WMCFG_APPLY) {
            k5_id_write_params(hwnd, d);
        }
        break;

    case WM_DESTROY:
        d = (k5_id_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d == NULL)
            break;

        khui_tracker_kill_controls(&d->tc_life);
        khui_tracker_kill_controls(&d->tc_renew);

        if (d->ident)
            kcdb_identity_release(d->ident);

        PFREE(d);
        SetWindowLongPtr(hwnd, DWLP_USER, 0);
        break;
    }
    return FALSE;
}
