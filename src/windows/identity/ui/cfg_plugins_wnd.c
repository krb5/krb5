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

#define MAX_PLUGINS 256

typedef struct tag_plugin_data {
    kmm_plugin_info plugin;
    kmm_module_info module;
} plugin_data;

typedef struct tag_plugin_dlg_data {
    plugin_data * info[MAX_PLUGINS];
    khm_size n_info;

    plugin_data * selected;
    HICON plugin_ico;
} plugin_dlg_data;

void update_dialog_fields(HWND hwnd,
                          plugin_dlg_data * d,
                          plugin_data * info) {
    wchar_t buf[256];
    UINT resid;
    wchar_t * t;
    khm_handle csp_module = NULL;

    d->selected = info;

    if (info->plugin.reg.description)
        SetDlgItemText(hwnd, IDC_CFG_DESC, info->plugin.reg.description);
    else {
        wchar_t fmt[128];

        LoadString(khm_hInstance, IDS_CFG_NODESC, fmt, ARRAYLENGTH(fmt));
        StringCbPrintf(buf, sizeof(buf), fmt, info->plugin.reg.name);
        SetDlgItemText(hwnd, IDC_CFG_DESC, buf);
    }
    
    switch(info->plugin.state) {
    case KMM_PLUGIN_STATE_FAIL_INIT:
        resid = IDS_PISTATE_FAILINIT;
        break;

    case KMM_PLUGIN_STATE_FAIL_UNKNOWN:
        resid = IDS_PISTATE_FAILUNK;
        break;

    case KMM_PLUGIN_STATE_FAIL_MAX_FAILURE:
        resid = IDS_PISTATE_FAILMAX;
        break;

    case KMM_PLUGIN_STATE_FAIL_NOT_REGISTERED:
        resid = IDS_PISTATE_FAILREG;
        break;

    case KMM_PLUGIN_STATE_FAIL_DISABLED:
        resid = IDS_PISTATE_FAILDIS;
        break;

    case KMM_PLUGIN_STATE_FAIL_LOAD:
        resid = IDS_PISTATE_FAILLOD;
        break;

    case KMM_PLUGIN_STATE_NONE:
    case KMM_PLUGIN_STATE_PLACEHOLDER:
        resid = IDS_PISTATE_PLACEHOLD;
        break;

    case KMM_PLUGIN_STATE_REG:
    case KMM_PLUGIN_STATE_PREINIT:
        resid = IDS_PISTATE_REG;
        break;

    case KMM_PLUGIN_STATE_HOLD:
        resid = IDS_PISTATE_HOLD;
        break;

    case KMM_PLUGIN_STATE_INIT:
        resid = IDS_PISTATE_INIT;
        break;

    case KMM_PLUGIN_STATE_RUNNING:
        resid = IDS_PISTATE_RUN;
        break;

    case KMM_PLUGIN_STATE_EXITED:
        resid = IDS_PISTATE_EXIT;
        break;

    default:
#ifdef DEBUG
        assert(FALSE);
#endif
        resid = IDS_PISTATE_FAILUNK;
    }

    LoadString(khm_hInstance, resid,
               buf, ARRAYLENGTH(buf));

    SetDlgItemText(hwnd, IDC_CFG_STATE, buf);

    SendDlgItemMessage(hwnd, IDC_CFG_DEPS,
                       LB_RESETCONTENT, 0, 0);

    for (t = info->plugin.reg.dependencies; t && *t;
         t = multi_string_next(t)) {
        SendDlgItemMessage(hwnd, IDC_CFG_DEPS,
                           LB_INSERTSTRING, -1, (LPARAM) t);
    }

    if (info->plugin.reg.module)
        SetDlgItemText(hwnd, IDC_CFG_MODULE,
                       info->plugin.reg.module);
    else
        SetDlgItemText(hwnd, IDC_CFG_MODULE,
                       L"");

    if (info->module.reg.vendor)
        SetDlgItemText(hwnd, IDC_CFG_VENDOR,
                       info->module.reg.vendor);
    else
        SetDlgItemText(hwnd, IDC_CFG_VENDOR,
                       L"");

    StringCbPrintf(buf, sizeof(buf), L"%u.%u.%u.%u",
                   (unsigned int) info->module.product_version.major,
                   (unsigned int) info->module.product_version.minor,
                   (unsigned int) info->module.product_version.patch,
                   (unsigned int) info->module.product_version.aux);

    SetDlgItemText(hwnd, IDC_CFG_VERSION, buf);

    if (info->plugin.reg.icon) {
        SendDlgItemMessage(hwnd, IDC_CFG_ICON,
                           STM_SETICON,
                           (WPARAM) info->plugin.reg.icon,
                           0);
    } else {
        SendDlgItemMessage(hwnd, IDC_CFG_ICON,
                           STM_SETICON,
                           (WPARAM) d->plugin_ico,
                           0);
    }

    if (KHM_SUCCEEDED(kmm_get_module_config(info->module.reg.name,
                                            0, &csp_module)) &&
        (khc_value_exists(csp_module, L"ImagePath") &
         (KCONF_FLAG_MACHINE | KCONF_FLAG_USER))) {

        EnableWindow(GetDlgItem(hwnd, IDC_CFG_UNREGISTER), TRUE);
    } else {
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_UNREGISTER), FALSE);
    }

    if (csp_module)
        khc_close_space(csp_module);

    if (info->plugin.flags & KMM_PLUGIN_FLAG_DISABLED) {
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_ENABLE), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_DISABLE), FALSE);
    } else {
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_ENABLE), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_DISABLE), TRUE);
    }
}

#define IDX_PLUGIN_NORMAL   1
#define IDX_PLUGIN_DISABLED 2
#define IDX_PLUGIN_ERROR    3

INT_PTR CALLBACK
khm_cfg_plugins_proc(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam) {

    plugin_dlg_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        {
            kmm_plugin p;
            kmm_plugin pn;
            kmm_module m;
            khm_size i;
            LVCOLUMN lvc;
            RECT r;
            HWND hw;
            wchar_t buf[256];
            HIMAGELIST h_ilist;
            HICON h_icon;

            d = PMALLOC(sizeof(*d));
#ifdef DEBUG
            assert(d);
#endif
            ZeroMemory(d, sizeof(*d));
#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

            p = NULL;
            i = 0;
            do {
                if (KHM_FAILED(kmm_get_next_plugin(p, &pn)))
                    break;

                if (p)
                    kmm_release_plugin(p);
                p = pn;

#ifdef DEBUG
                assert(d->info[i] == NULL);
#endif
                d->info[i] = PMALLOC(sizeof(*(d->info[i])));
#ifdef DEBUG
                assert(d->info[i]);
#endif
                ZeroMemory(&d->info[i]->plugin,
                           sizeof(d->info[i]->plugin));

                if (KHM_FAILED(kmm_get_plugin_info_i(p, &d->info[i]->plugin))) {
                    PFREE(d->info[i]);
                    d->info[i] = NULL;
                    break;
                }

                ZeroMemory(&d->info[i]->module,
                           sizeof(d->info[i]->module));

                if (KHM_SUCCEEDED(kmm_load_module(d->info[i]->plugin.reg.module,
                                                  KMM_LM_FLAG_NOLOAD,
                                                  &m))) {
                    kmm_get_module_info_i(m, &d->info[i]->module);
                    kmm_release_module(m);
                }

                i ++;

                if (i == MAX_PLUGINS)
                    break;
            } while(p);

            if (p)
                kmm_release_plugin(p);

            d->n_info = i;

            /* now populate the list view */
            hw = GetDlgItem(hwnd, IDC_CFG_PLUGINS);
#ifdef DEBUG
            assert(hw);
#endif

            h_ilist = ImageList_Create(GetSystemMetrics(SM_CXSMICON),
                                       GetSystemMetrics(SM_CYSMICON),
                                       ILC_COLOR8,
                                       4, 4);

            h_icon = LoadImage(khm_hInstance,
                               MAKEINTRESOURCE(IDI_CFG_PLUGIN),
                               IMAGE_ICON,
                               GetSystemMetrics(SM_CXSMICON),
                               GetSystemMetrics(SM_CYSMICON),
                               LR_DEFAULTCOLOR);
#ifdef DEBUG
            assert(h_icon);
#endif
            ImageList_AddIcon(h_ilist, h_icon);
            DestroyIcon(h_icon);

            h_icon = LoadImage(khm_hInstance,
                               MAKEINTRESOURCE(IDI_CFG_PLUGIN_DIS),
                               IMAGE_ICON,
                               GetSystemMetrics(SM_CXSMICON),
                               GetSystemMetrics(SM_CYSMICON),
                               LR_DEFAULTCOLOR);
#ifdef DEBUG
            assert(h_icon);
#endif
            ImageList_AddIcon(h_ilist, h_icon);
            DestroyIcon(h_icon);

            h_icon = LoadImage(khm_hInstance,
                               MAKEINTRESOURCE(IDI_CFG_PLUGIN_ERR),
                               IMAGE_ICON,
                               GetSystemMetrics(SM_CXSMICON),
                               GetSystemMetrics(SM_CYSMICON),
                               LR_DEFAULTCOLOR);
#ifdef DEBUG
            assert(h_icon);
#endif
            ImageList_AddIcon(h_ilist, h_icon);
            DestroyIcon(h_icon);

            ListView_SetImageList(hw, h_ilist, LVSIL_STATE);

            ZeroMemory(&lvc, sizeof(lvc));

            lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            GetWindowRect(hw, &r);
            lvc.cx = ((r.right - r.left) * 95) / 100;
            lvc.pszText = buf;

            LoadString(khm_hInstance, IDS_CFG_PI_COL_PLUGINS,
                       buf, ARRAYLENGTH(buf));

            ListView_InsertColumn(hw, 0, &lvc);

            for(i=0; i<d->n_info; i++) {
                LVITEM lvi;

                ZeroMemory(&lvi, sizeof(lvi));

                lvi.mask = LVIF_PARAM | LVIF_TEXT | LVIF_STATE;
                lvi.lParam = (LPARAM) d->info[i];
                lvi.pszText = d->info[i]->plugin.reg.name;

                if (d->info[i]->plugin.flags & KMM_PLUGIN_FLAG_DISABLED) {
                    lvi.state = INDEXTOSTATEIMAGEMASK(IDX_PLUGIN_DISABLED);
                } else if (d->info[i]->plugin.state < 0) {
                    lvi.state = INDEXTOSTATEIMAGEMASK(IDX_PLUGIN_ERROR);
                } else {
                    lvi.state = INDEXTOSTATEIMAGEMASK(IDX_PLUGIN_NORMAL);
                }

                ListView_InsertItem(hw, &lvi);
            }

            d->plugin_ico =
                (HICON) LoadImage(khm_hInstance,
                                  MAKEINTRESOURCE(IDI_CFG_PLUGIN),
                                  IMAGE_ICON,
                                  GetSystemMetrics(SM_CXICON),
                                  GetSystemMetrics(SM_CYICON),
                                  LR_DEFAULTCOLOR);
        }
        return FALSE;

    case WM_NOTIFY:
        {
            LPNMHDR lpnm;
            HWND hw;

            d = (plugin_dlg_data *) (LONG_PTR) 
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (wParam == IDC_CFG_PLUGINS &&
                (lpnm = (LPNMHDR) lParam) &&
                lpnm->code == LVN_ITEMCHANGED) {

                LVITEM lvi;

                hw = GetDlgItem(hwnd, IDC_CFG_PLUGINS);
#ifdef DEBUG
                assert(hw);
#endif
                if (ListView_GetSelectedCount(hw) != 1) {
                    SetDlgItemText(hwnd, IDC_CFG_DESC, L"");
                    SetDlgItemText(hwnd, IDC_CFG_STATE, L"");
                    SetDlgItemText(hwnd, IDC_CFG_MODULE, L"");
                    SetDlgItemText(hwnd, IDC_CFG_VENDOR, L"");
                    SetDlgItemText(hwnd, IDC_CFG_VERSION, L"");
                    EnableWindow(GetDlgItem(hwnd, IDC_CFG_ENABLE), FALSE);
                    EnableWindow(GetDlgItem(hwnd, IDC_CFG_DISABLE), FALSE);
                    EnableWindow(GetDlgItem(hwnd, IDC_CFG_UNREGISTER), FALSE);
                    SendDlgItemMessage(hwnd, IDC_CFG_DEPS, 
                                       LB_RESETCONTENT, 0, 0);
                    SendDlgItemMessage(hwnd, IDC_CFG_ICON, STM_SETICON,
                                       (WPARAM) d->plugin_ico, 0);
                    d->selected = NULL;
                } else {
                    int idx;
                    plugin_data * info;

                    idx = ListView_GetNextItem(hw, -1, LVNI_SELECTED);
#ifdef DEBUG
                    assert(idx != -1);
#endif
                    ZeroMemory(&lvi, sizeof(lvi));
                    lvi.iItem = idx;
                    lvi.iSubItem = 0;
                    lvi.mask = LVIF_PARAM;

                    ListView_GetItem(hw, &lvi);
#ifdef DEBUG
                    assert(lvi.lParam != 0);
#endif
                    info = (plugin_data *) lvi.lParam;

                    update_dialog_fields(hwnd, d, info);
                }
            }
        }
        return TRUE;

    case WM_COMMAND:
        {

            d = (plugin_dlg_data *) (LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);

            switch (wParam) {
            case MAKEWPARAM(IDC_CFG_ENABLE, BN_CLICKED):
                if (d->selected != NULL) {
                    khui_alert * alert = NULL;
                    wchar_t buf[KHUI_MAXCCH_MESSAGE];
                    wchar_t fmt[KHUI_MAXCCH_MESSAGE];
                    kmm_plugin p;

                    khui_alert_create_empty(&alert);

                    LoadString(khm_hInstance, IDS_CFG_P_ENBCNFT,
                               fmt, ARRAYLENGTH(fmt));
                    StringCbPrintf(buf, sizeof(buf), fmt, d->selected->plugin.reg.name);
                    khui_alert_set_title(alert, buf);

                    LoadString(khm_hInstance, IDS_CFG_P_ENBCNFM,
                               fmt, ARRAYLENGTH(fmt));
                    StringCbPrintf(buf, sizeof(buf), fmt, d->selected->plugin.reg.name);
                    khui_alert_set_message(alert, buf);

                    khui_alert_set_severity(alert, KHERR_INFO);

                    khui_alert_show_modal(alert);

                    kmm_enable_plugin(d->selected->plugin.h_plugin, TRUE);

                    khui_alert_release(alert);

                    p = d->selected->plugin.h_plugin;
                    kmm_hold_plugin(p);
                    kmm_release_plugin_info_i(&d->selected->plugin);
                    kmm_get_plugin_info_i(p, &d->selected->plugin);
                    kmm_release_plugin(p);

                    update_dialog_fields(hwnd, d, d->selected);
                }
                break;

            case MAKEWPARAM(IDC_CFG_DISABLE, BN_CLICKED):
                if (d->selected != NULL) {
                    khui_alert * alert = NULL;
                    wchar_t buf[KHUI_MAXCCH_MESSAGE];
                    wchar_t fmt[KHUI_MAXCCH_MESSAGE];
                    wchar_t depends[KHUI_MAXCCH_MESSAGE];
                    khm_size i;
                    kmm_plugin p;

                    khui_alert_create_empty(&alert);
#ifdef DEBUG
                    assert(alert);
#endif
                    if (alert == NULL)
                        break;

                    LoadString(khm_hInstance, IDS_CFG_P_DELCNFT,
                               fmt, ARRAYLENGTH(fmt));
                    StringCbPrintf(buf, sizeof(buf), fmt, d->selected->plugin.reg.name);
                    khui_alert_set_title(alert, buf);

                    LoadString(khm_hInstance, IDS_CFG_P_DELCNFM,
                               fmt, ARRAYLENGTH(fmt));
                    StringCbPrintf(buf, sizeof(buf), fmt, d->selected->plugin.reg.name);
                    khui_alert_set_message(alert, buf);

                    depends[0] = L'\0';

                    for (i=0; i<d->n_info; i++) {
                        wchar_t * t;

                        t = d->info[i]->plugin.reg.dependencies;

                        while(t) {
                            if (!wcscmp(t, d->selected->plugin.reg.name)) {
                                if (depends[0])
                                    StringCbCat(depends, sizeof(depends), L", ");
                                StringCbCat(depends, sizeof(depends),
                                            d->info[i]->plugin.reg.name);
                                break;
                            }
                            t = multi_string_next(t);
                        }
                    }

                    if (depends[0]) {
                        LoadString(khm_hInstance, IDS_CFG_P_DELCNFS,
                                   fmt, ARRAYLENGTH(fmt));
                        StringCbPrintf(buf, sizeof(buf), fmt, depends);
                        khui_alert_set_suggestion(alert, buf);
                    } else {
                        LoadString(khm_hInstance, IDS_CFG_P_DELNDEP,
                                   buf, ARRAYLENGTH(buf));
                        khui_alert_set_suggestion(alert, buf);
                    }

                    khui_alert_add_command(alert, KHUI_PACTION_YES);
                    khui_alert_add_command(alert, KHUI_PACTION_NO);

                    khui_alert_set_severity(alert, KHERR_WARNING);

                    if (KHM_SUCCEEDED(khui_alert_show_modal(alert)) &&
                        alert->response == KHUI_PACTION_YES) {
                        kmm_enable_plugin(d->selected->plugin.h_plugin, FALSE);
                    }

                    khui_alert_release(alert);

                    p = d->selected->plugin.h_plugin;
                    kmm_hold_plugin(p);
                    kmm_release_plugin_info_i(&d->selected->plugin);
                    kmm_get_plugin_info_i(p, &d->selected->plugin);
                    kmm_release_plugin(p);

                    update_dialog_fields(hwnd, d, d->selected);
                }
                break;

            case MAKEWPARAM(IDC_CFG_UNREGISTER, BN_CLICKED):
                {
                    khui_alert * alert = NULL;
                    wchar_t buf[KHUI_MAXCCH_MESSAGE];
                    wchar_t fmt[KHUI_MAXCCH_MESSAGE];
                    wchar_t plist[KHUI_MAXCCH_MESSAGE];
                    khm_size i;

                    if (d->selected == NULL) {
#ifdef DEBUG
                        assert(FALSE);
#endif
                        break;
                    }

                    khui_alert_create_empty(&alert);

                    LoadString(khm_hInstance, IDS_CFG_P_UNRCNFT,
                               fmt, ARRAYLENGTH(fmt));
                    StringCbPrintf(buf, sizeof(buf), fmt,
                                   d->selected->plugin.reg.name);

                    khui_alert_set_title(alert, buf);

                    LoadString(khm_hInstance, IDS_CFG_P_UNRCNFM,
                               fmt, ARRAYLENGTH(fmt));
                    StringCbPrintf(buf, sizeof(buf), fmt,
                                   d->selected->plugin.reg.name);

                    khui_alert_set_message(alert, buf);

                    plist[0] = L'\0';
                    for (i=0; i < d->n_info; i++) {
                        if (!wcscmp(d->info[i]->module.reg.name,
                                    d->selected->module.reg.name)) {
                            if (plist[0])
                                StringCbCat(plist, sizeof(plist), L", ");
                            StringCbCat(plist, sizeof(plist),
                                        d->info[i]->plugin.reg.name);
                        }
                    }

#ifdef DEBUG
                    /* there should have been at least one plugin */
                    assert(plist[0]);
#endif

                    LoadString(khm_hInstance, IDS_CFG_P_UNRCNFS,
                               fmt, ARRAYLENGTH(fmt));
                    StringCbPrintf(buf, sizeof(buf), fmt, plist);
                    khui_alert_set_suggestion(alert, buf);

                    khui_alert_add_command(alert, KHUI_PACTION_YES);
                    khui_alert_add_command(alert, KHUI_PACTION_NO);

                    khui_alert_set_severity(alert, KHERR_WARNING);

                    if (KHM_SUCCEEDED(khui_alert_show_modal(alert)) &&
                        alert->response == KHUI_PACTION_YES) {
                        kmm_unregister_module(d->selected->module.reg.name, 0);

                        update_dialog_fields(hwnd, d, d->selected);
                    }
                }
                break;

            case MAKEWPARAM(IDC_CFG_REGISTER, BN_CLICKED):
                {
                    
                }
                break;
            }
        }
        return TRUE;

    case WM_DESTROY:
        {
            khm_size i;

            d = (plugin_dlg_data *) (LONG_PTR) 
                GetWindowLongPtr(hwnd, DWLP_USER);
#ifdef DEBUG
            assert(d);
#endif
            for (i=0; i<d->n_info; i++) {
#ifdef DEBUG
                assert(d->info[i]);
#endif
                kmm_release_plugin_info_i(&d->info[i]->plugin);
                kmm_release_module_info_i(&d->info[i]->module);
                PFREE(d->info[i]);
            }

            PFREE(d);

            khm_set_dialog_result(hwnd, 0);
        }
        return TRUE;
    }
    return FALSE;
}
