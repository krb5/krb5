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

typedef struct tag_k5_ids_opts {
    khm_int32 renewable;
    khm_int32 forwardable;
    khm_int32 addressless;
} k5_ids_opts;

typedef struct tag_k5_ids_dlg_data {
    khui_config_init_data cfg;

    khui_tracker tc_life;
    khui_tracker tc_renew;
    khui_tracker tc_life_min;
    khui_tracker tc_life_max;
    khui_tracker tc_renew_min;
    khui_tracker tc_renew_max;

    time_t life;
    time_t renew_life;
    time_t life_min;
    time_t life_max;
    time_t renew_min;
    time_t renew_max;

    k5_ids_opts opt;
    k5_ids_opts opt_saved;

} k5_ids_dlg_data;

static khm_boolean
k5_ids_is_mod(k5_ids_dlg_data * d) {
    if (d->life != d->tc_life.current ||
        d->renew_life != d->tc_renew.current ||
        d->life_max != d->tc_life_max.current ||
        d->life_min != d->tc_life_min.current ||
        d->renew_max != d->tc_renew_max.current ||
        d->renew_min != d->tc_renew_min.current ||
        !!d->opt.renewable != !!d->opt_saved.renewable ||
        !!d->opt.forwardable != !!d->opt_saved.forwardable ||
        !!d->opt.addressless != !!d->opt_saved.addressless)
        return TRUE;
    return FALSE;
}

static void
k5_ids_check_mod(k5_ids_dlg_data * d) {
    BOOL modified = k5_ids_is_mod(d);

    khui_cfg_set_flags_inst(&d->cfg,
                            (modified)?KHUI_CNFLAG_MODIFIED:0,
                            KHUI_CNFLAG_MODIFIED);
}

static void
k5_ids_write_params(k5_ids_dlg_data * d) {

    khm_int32 rv;

#ifdef DEBUG
    assert(csp_params);
#endif

    if (!k5_ids_is_mod(d))
        return;

#define WRITEPARAM(po,pn,vn) \
  if (po != pn) {            \
   po = pn;                  \
   rv = khc_write_int32(csp_params, vn, (khm_int32) po); \
   assert(KHM_SUCCEEDED(rv));       \
  }
    
    WRITEPARAM(d->life,d->tc_life.current, L"DefaultLifetime");
    WRITEPARAM(d->renew_life,d->tc_renew.current, L"DefaultRenewLifetime");
    WRITEPARAM(d->life_max,d->tc_life_max.current, L"MaxLifetime");
    WRITEPARAM(d->life_min,d->tc_life_min.current, L"MinLifetime");
    WRITEPARAM(d->renew_max,d->tc_renew_max.current, L"MaxRenewLifetime");
    WRITEPARAM(d->renew_min,d->tc_renew_min.current, L"MinRenewLifetime");
    WRITEPARAM(d->opt_saved.renewable, d->opt.renewable, L"Renewable");
    WRITEPARAM(d->opt_saved.forwardable, d->opt.forwardable, L"Forwardable");
    WRITEPARAM(d->opt_saved.addressless, d->opt.addressless, L"Addressless");

#undef WRITEPARAM

    khui_cfg_set_flags_inst(&d->cfg,
                            KHUI_CNFLAG_APPLIED,
                            KHUI_CNFLAG_APPLIED | KHUI_CNFLAG_MODIFIED);
}

static void
k5_ids_read_params(k5_ids_dlg_data * d) {
    k5_params p;

    khm_krb5_get_identity_params(NULL, &p);

    d->life = p.lifetime;
    d->life_max = p.lifetime_max;
    d->life_min = p.lifetime_min;

    d->renew_life = p.renew_life;
    d->renew_max = p.renew_life_max;
    d->renew_min = p.renew_life_min;

    d->opt_saved.forwardable = p.forwardable;
    d->opt_saved.renewable = p.renewable;
    d->opt_saved.addressless = p.addressless;

    d->opt = d->opt_saved;

    khui_tracker_initialize(&d->tc_life);
    d->tc_life.current = d->life;
    d->tc_life.min = 0;
    d->tc_life.max = 3600 * 24 * 7;

    khui_tracker_initialize(&d->tc_renew);
    d->tc_renew.current = d->renew_life;
    d->tc_renew.min = 0;
    d->tc_renew.max = 3600 * 24 * 30;

    khui_tracker_initialize(&d->tc_life_min);
    d->tc_life_min.current = d->life_min;
    d->tc_life_min.min = d->tc_life.min;
    d->tc_life_min.max = d->tc_life.max;

    khui_tracker_initialize(&d->tc_life_max);
    d->tc_life_max.current = d->life_max;
    d->tc_life_max.min = d->tc_life.min;
    d->tc_life_max.max = d->tc_life.max;

    khui_tracker_initialize(&d->tc_renew_min);
    d->tc_renew_min.current = d->renew_min;
    d->tc_renew_min.min = d->tc_renew.min;
    d->tc_renew_min.max = d->tc_renew.max;

    khui_tracker_initialize(&d->tc_renew_max);
    d->tc_renew_max.current = d->renew_max;
    d->tc_renew_max.min = d->tc_renew.min;
    d->tc_renew_max.max = d->tc_renew.max;
}

INT_PTR CALLBACK 
k5_ids_tab_dlgproc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {
    k5_ids_dlg_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        d = PMALLOC(sizeof(*d));
#ifdef DEBUG
        assert(d);
#endif
        ZeroMemory(d, sizeof(*d));
#pragma warning(push)
#pragma warning(disable: 4244)
        SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

        d->cfg = *((khui_config_init_data *) lParam);

        k5_ids_read_params(d);

        khui_tracker_install(GetDlgItem(hwnd, IDC_CFG_DEFLIFE),
                             &d->tc_life);
        khui_tracker_install(GetDlgItem(hwnd, IDC_CFG_DEFRLIFE),
                             &d->tc_renew);
        khui_tracker_install(GetDlgItem(hwnd, IDC_CFG_LRNG_MIN),
                             &d->tc_life_min);
        khui_tracker_install(GetDlgItem(hwnd, IDC_CFG_LRNG_MAX),
                             &d->tc_life_max);
        khui_tracker_install(GetDlgItem(hwnd, IDC_CFG_RLRNG_MIN),
                             &d->tc_renew_min);
        khui_tracker_install(GetDlgItem(hwnd, IDC_CFG_RLRNG_MAX),
                             &d->tc_renew_max);
        khui_tracker_refresh(&d->tc_life);
        khui_tracker_refresh(&d->tc_life_min);
        khui_tracker_refresh(&d->tc_life_max);
        khui_tracker_refresh(&d->tc_renew);
        khui_tracker_refresh(&d->tc_renew_min);
        khui_tracker_refresh(&d->tc_renew_max);

        CheckDlgButton(hwnd, IDC_CFG_RENEW, (d->opt.renewable ? BST_CHECKED: BST_UNCHECKED));
        CheckDlgButton(hwnd, IDC_CFG_FORWARD, (d->opt.forwardable ? BST_CHECKED: BST_UNCHECKED));
        CheckDlgButton(hwnd, IDC_CFG_ADDRESSLESS, (d->opt.addressless ? BST_CHECKED: BST_UNCHECKED));
        break;

    case WM_COMMAND:
        d = (k5_ids_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (HIWORD(wParam) == EN_CHANGE) {
            k5_ids_check_mod(d);
        } else if (HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case IDC_CFG_RENEW:
                d->opt.renewable = (IsDlgButtonChecked(hwnd, IDC_CFG_RENEW) == BST_CHECKED);
                break;

            case IDC_CFG_FORWARD:
                d->opt.forwardable = (IsDlgButtonChecked(hwnd, IDC_CFG_FORWARD) == BST_CHECKED);
                break;

            case IDC_CFG_ADDRESSLESS:
                d->opt.addressless = (IsDlgButtonChecked(hwnd, IDC_CFG_ADDRESSLESS) == BST_CHECKED);
                break;
            }

            k5_ids_check_mod(d);
        }
        break;

    case KHUI_WM_CFG_NOTIFY:
        d = (k5_ids_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);
        if (HIWORD(wParam) == WMCFG_APPLY) {
            k5_ids_write_params(d);
        }
        break;

    case WM_DESTROY:
        d = (k5_ids_dlg_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        khui_tracker_kill_controls(&d->tc_life);
        khui_tracker_kill_controls(&d->tc_renew);
        khui_tracker_kill_controls(&d->tc_life_min);
        khui_tracker_kill_controls(&d->tc_life_max);
        khui_tracker_kill_controls(&d->tc_renew_min);
        khui_tracker_kill_controls(&d->tc_renew_max);

        PFREE(d);
        break;
    }
    return FALSE;
}


