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

#pragma warning(push)
#pragma warning(disable: 4995)
#include<shlwapi.h>
#pragma warning(pop)

typedef struct tag_k5_id_dlg_data {
    khui_config_init_data cfg;

    khm_handle   ident;

    khui_tracker tc_life;
    khui_tracker tc_renew;

    wchar_t ccache[KRB5_MAXCCH_CCNAME];

    time_t life;
    time_t renew_life;
} k5_id_dlg_data;

static void
k5_id_read_params(k5_id_dlg_data * d) {

    wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
    khm_size cb;
    khm_int32 rv;
    khm_int32 t;
    khm_handle csp_ident;
    khm_handle csp_idroot = NULL;

    cb = sizeof(idname);
    khui_cfg_get_name(d->cfg.ctx_node, idname, &cb);

    rv = kcdb_identity_create(idname, 0, &d->ident);
#ifdef DEBUG
    assert(KHM_SUCCEEDED(rv));
#endif

    rv = kcdb_identity_get_config(d->ident, 0, &csp_idroot);
    if (KHM_SUCCEEDED(rv) &&
        KHM_SUCCEEDED(khc_open_space(csp_idroot, CSNAME_KRB5CRED, 0,
                                     &csp_ident))) {
        khc_shadow_space(csp_ident, csp_params);
    } else {
        csp_ident = csp_params;
    }

    if (csp_idroot)
        khc_close_space(csp_idroot);

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

    cb = sizeof(d->ccache);
    rv = khc_read_string(csp_ident, L"DefaultCCName", d->ccache, &cb);
    if (KHM_FAILED(rv))
        ZeroMemory(d->ccache, sizeof(d->ccache));

    khui_tracker_initialize(&d->tc_life);
    d->tc_life.current = d->life;
    d->tc_life.min = 0;
    d->tc_life.max = 3600 * 24 * 7;

    khui_tracker_initialize(&d->tc_renew);
    d->tc_renew.current = d->renew_life;
    d->tc_renew.min = 0;
    d->tc_renew.max = 3600 * 24 * 30;

    if (csp_ident != csp_params)
        khc_close_space(csp_ident);
}

static khm_boolean
k5_id_is_mod(HWND hw, k5_id_dlg_data * d) {
    wchar_t ccache[KRB5_MAXCCH_CCNAME];

    GetDlgItemText(hw, IDC_CFG_CCACHE, ccache, ARRAYLENGTH(ccache));

    if (wcsicmp(ccache, d->ccache) ||
        d->tc_renew.current != d->renew_life ||
        d->tc_life.current != d->life)
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

    if (!k5_id_is_mod(hw, d))
        return;

    rv = kcdb_identity_get_config(d->ident, KHM_FLAG_CREATE, &csp_idroot);
    if (KHM_SUCCEEDED(rv)) {
        khc_open_space(csp_idroot, CSNAME_KRB5CRED,
                       KHM_FLAG_CREATE,
                       &csp_ident);
    }

    if (csp_idroot)
        khc_close_space(csp_idroot);

    if (!csp_ident)
        return;

    if (d->life != d->tc_life.current) {
        d->life = d->tc_life.current;
        khc_write_int32(csp_ident, L"DefaultLifetime", (khm_int32) d->life);
    }

    if (d->renew_life != d->tc_renew.current) {
        d->renew_life = d->tc_renew.current;
        khc_write_int32(csp_ident, L"DefaultRenewLifetime", (khm_int32) d->renew_life);
    }

    GetDlgItemText(hw, IDC_CFG_CCACHE, ccache, ARRAYLENGTH(ccache));

    if (SUCCEEDED(StringCbLength(ccache, sizeof(ccache), &cb)) &&
        wcsicmp(ccache, d->ccache)) {
        khc_write_string(csp_ident, L"DefaultCCName", ccache);
        StringCbCopy(d->ccache, sizeof(d->ccache), ccache);
    } else {
        khc_remove_value(csp_ident, L"DefaultCCName", KCONF_FLAG_USER);
    }

    if (csp_ident)
        khc_close_space(csp_ident);

    khui_cfg_set_flags_inst(&d->cfg,
                            KHUI_CNFLAG_APPLIED,
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
        break;

    case WM_COMMAND:
        d = (k5_id_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (HIWORD(wParam) == EN_CHANGE)
            k5_id_check_mod(hwnd, d);
        break;

    case KHUI_WM_CFG_NOTIFY:
        d = (k5_id_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (HIWORD(wParam) == WMCFG_APPLY) {
            k5_id_write_params(hwnd, d);
        }
        break;

    case WM_DESTROY:
        d = (k5_id_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        khui_tracker_kill_controls(&d->tc_life);
        khui_tracker_kill_controls(&d->tc_renew);

        if (d->ident)
            kcdb_identity_release(d->ident);

        PFREE(d);
        break;
    }
    return FALSE;
}
