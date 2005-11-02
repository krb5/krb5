/*
 * Copyright (c) 2004 Massachusetts Institute of Technology
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

INT_PTR CALLBACK 
k5_config_dlgproc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {
    switch(uMsg) {
    case WM_INITDIALOG:
        {
            HWND hw;
            wchar_t * realms;
            wchar_t * defrealm;
            wchar_t * t;
            char conffile[MAX_PATH];
            wchar_t wconffile[MAX_PATH];
            wchar_t importopts[256];
            WKSTA_INFO_100 * winfo100;

            hw = GetDlgItem(hwnd, IDC_CFG_DEFREALM);
#ifdef DEBUG
            assert(hw);
#endif
            realms = khm_krb5_get_realm_list();
            defrealm = khm_krb5_get_default_realm();
#ifdef DEBUG
            assert(realms);
            assert(defrealm);
#endif

            SendMessage(hw, CB_RESETCONTENT, 0, 0);

            for(t = realms; t && *t; t = multi_string_next(t)) {
                SendMessage(hw, CB_ADDSTRING, 0, (LPARAM) t);
            }

            SendMessage(hw, CB_SELECTSTRING, -1, (LPARAM) defrealm);

            free(defrealm);
            free(realms);

            khm_get_profile_file(conffile, sizeof(conffile));

            AnsiStrToUnicode(wconffile, sizeof(wconffile), conffile);

            SetDlgItemText(hwnd, IDC_CFG_CFGFILE, wconffile);

            /* hostname/domain */
            if (NetWkstaGetInfo(NULL, 100, (LPBYTE *) &winfo100) == NERR_Success) {
                SetDlgItemText(hwnd, IDC_CFG_HOSTNAME, winfo100->wki100_computername);
                SetDlgItemText(hwnd, IDC_CFG_DOMAIN, winfo100->wki100_langroup);
                NetApiBufferFree(winfo100);
            }

            /* and the import ticket options */
            LoadString(hResModule, IDS_K5CFG_IMPORT_OPTIONS,
                       importopts, ARRAYLENGTH(importopts));

            hw = GetDlgItem(hwnd, IDC_CFG_IMPORT);
#ifdef DEBUG
            assert(hw);
#endif
            SendMessage(hw, CB_RESETCONTENT, 0, 0);

            for (t=importopts; 
                 t && *t && *t != L' ' &&
                     t < importopts + ARRAYLENGTH(importopts);
                 t = multi_string_next(t)) {

                SendMessage(hw, CB_ADDSTRING, 0, (LPARAM) t);
            }

            SendMessage(hw, CB_SETCURSEL, 0, 0);
            
        }
        break;

    case WM_DESTROY:
        break;
    }
    return FALSE;
}

INT_PTR CALLBACK 
k5_realms_dlgproc(HWND hwndDlg,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {
    switch(uMsg) {
    case WM_INITDIALOG:
        break;

    case WM_DESTROY:
        break;
    }
    return FALSE;
}

typedef struct tag_k5_ids_dlg_data {
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
} k5_ids_dlg_data;

static void
k5_ids_read_params(k5_ids_dlg_data * d) {
    khm_int32 t;
    khm_int32 rv;

#ifdef DEBUG
    assert(csp_params);
#endif

    rv = khc_read_int32(csp_params, L"DefaultLifetime", &t);
    assert(KHM_SUCCEEDED(rv));
    d->life = t;

    rv = khc_read_int32(csp_params, L"DefaultRenewLifetime", &t);
    assert(KHM_SUCCEEDED(rv));
    d->renew_life = t;

    rv = khc_read_int32(csp_params, L"MaxLifetime", &t);
    assert(KHM_SUCCEEDED(rv));
    d->life_max = t;

    rv = khc_read_int32(csp_params, L"MinLifetime", &t);
    assert(KHM_SUCCEEDED(rv));
    d->life_min = t;

    rv = khc_read_int32(csp_params, L"MaxRenewLifetime", &t);
    assert(KHM_SUCCEEDED(rv));
    d->renew_max = t;

    rv = khc_read_int32(csp_params, L"MinRenewLifetime", &t);
    assert(KHM_SUCCEEDED(rv));
    d->renew_min = t;

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
        d = malloc(sizeof(*d));
#ifdef DEBUG
        assert(d);
#endif
        ZeroMemory(d, sizeof(*d));
#pragma warning(push)
#pragma warning(disable: 4244)
        SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

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
        break;
    }
    return FALSE;
}

INT_PTR CALLBACK 
k5_id_tab_dlgproc(HWND hwndDlg,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {
    switch(uMsg) {
    case WM_INITDIALOG:
        break;

    case WM_DESTROY:
        break;
    }
    return FALSE;
}


void
k5_register_config_panels(void) {
    khui_config_node node;
    khui_config_node_reg reg;
    wchar_t wshort[KHUI_MAXCCH_SHORT_DESC];
    wchar_t wlong[KHUI_MAXCCH_LONG_DESC];

    ZeroMemory(&reg, sizeof(reg));

    LoadString(hResModule, IDS_K5CFG_SHORT_DESC,
               wshort, ARRAYLENGTH(wshort));
    LoadString(hResModule, IDS_K5CFG_LONG_DESC,
               wlong, ARRAYLENGTH(wlong));

    reg.name = L"Kerberos5";
    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = hResModule;
    reg.dlg_template = MAKEINTRESOURCE(IDD_CONFIG);
    reg.dlg_proc = k5_config_dlgproc;
    reg.flags = 0;

    khui_cfg_register(NULL, &reg);

    if (KHM_FAILED(khui_cfg_open(NULL, L"Kerberos5", &node))) {
        node = NULL;
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    ZeroMemory(&reg, sizeof(reg));

    LoadString(hResModule, IDS_K5RLM_SHORT_DESC,
               wshort, ARRAYLENGTH(wshort));
    LoadString(hResModule, IDS_K5RLM_LONG_DESC,
               wlong, ARRAYLENGTH(wlong));

    reg.name = L"KerberosRealms";
    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = hResModule;
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_REALMS);
    reg.dlg_proc = k5_realms_dlgproc;
    reg.flags = 0;

    khui_cfg_register(node, &reg);

    khui_cfg_release(node);

    if (KHM_FAILED(khui_cfg_open(NULL, L"KhmIdentities", &node))) {
        node = NULL;
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    ZeroMemory(&reg, sizeof(reg));

    LoadString(hResModule, IDS_K5CFG_IDS_SHORT_DESC,
               wshort, ARRAYLENGTH(wshort));
    LoadString(hResModule, IDS_K5CFG_IDS_LONG_DESC,
               wlong, ARRAYLENGTH(wlong));

    reg.name = L"KerberosIdentities";
    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = hResModule;
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_IDS_TAB);
    reg.dlg_proc = k5_ids_tab_dlgproc;
    reg.flags = KHUI_CNFLAG_SUBPANEL;

    khui_cfg_register(node, &reg);

    ZeroMemory(&reg, sizeof(reg));

    LoadString(hResModule, IDS_K5CFG_ID_SHORT_DESC,
               wshort, ARRAYLENGTH(wshort));
    LoadString(hResModule, IDS_K5CFG_ID_LONG_DESC,
               wlong, ARRAYLENGTH(wlong));

    reg.name = L"KerberosIdentitiesPlural";
    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = hResModule;
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_ID_TAB);
    reg.dlg_proc = k5_id_tab_dlgproc;
    reg.flags = KHUI_CNFLAG_SUBPANEL | KHUI_CNFLAG_PLURAL;

    khui_cfg_register(node, &reg);

    khui_cfg_release(node);
}

void
k5_unregister_config_panels(void) {
    khui_config_node node_main;
    khui_config_node node_realms;
    khui_config_node node_ids;
    khui_config_node node_tab;

    if (KHM_FAILED(khui_cfg_open(NULL, L"Kerberos5", &node_main))) {
        node_main = NULL;
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    if (KHM_SUCCEEDED(khui_cfg_open(node_main, L"KerberosRealms", 
                                    &node_realms))) {
        khui_cfg_remove(node_realms);
        khui_cfg_release(node_realms);
    }
#ifdef DEBUG
    else
        assert(FALSE);
#endif

    if (node_main) {
        khui_cfg_remove(node_main);
        khui_cfg_release(node_main);
    }

    if (KHM_FAILED(khui_cfg_open(NULL, L"KhmIdentities", &node_ids))) {
        node_ids = NULL;
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    if (KHM_SUCCEEDED(khui_cfg_open(node_ids, L"KerberosIdentities", &node_tab))) {
        khui_cfg_remove(node_tab);
        khui_cfg_release(node_tab);
    }
    if (KHM_SUCCEEDED(khui_cfg_open(node_ids, L"KerberosIdentitiesPlural", &node_tab))) {
        khui_cfg_remove(node_tab);
        khui_cfg_release(node_tab);
    }

    if (node_ids)
        khui_cfg_release(node_ids);
}
