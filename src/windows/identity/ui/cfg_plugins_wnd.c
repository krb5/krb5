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
} plugin_dlg_data;

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


            d = malloc(sizeof(*d));
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
                d->info[i] = malloc(sizeof(*(d->info[i])));
#ifdef DEBUG
                assert(d->info[i]);
#endif

                if (KHM_FAILED(kmm_get_plugin_info_i(p, &d->info[i]->plugin))) {
                    free(d->info[i]);
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
            ListView_SetView(hw, LV_VIEW_DETAILS);

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

                lvi.mask = LVIF_PARAM | LVIF_TEXT;
                lvi.lParam = (LPARAM) d->info[i];
                lvi.pszText = d->info[i]->plugin.reg.name;

                ListView_InsertItem(hw, &lvi);
            }
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
                    EnableWindow(GetDlgItem(hwnd, IDC_CFG_ENABLE), FALSE);
                    EnableWindow(GetDlgItem(hwnd, IDC_CFG_DISABLE), FALSE);
                    SendDlgItemMessage(hwnd, IDC_CFG_DEPS, 
                                       LB_RESETCONTENT, 0, 0);
                } else {
                    int idx;
                    plugin_data * info;
                    wchar_t buf[256];
                    UINT resid;
                    wchar_t * t;

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

                    if (info->plugin.reg.description)
                        SetDlgItemText(hwnd, IDC_CFG_DESC, info->plugin.reg.description);
                    else
                        SetDlgItemText(hwnd, IDC_CFG_DESC, L"");

                    switch(info->plugin.state) {
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
                                           LB_INSERTSTRING,
                                           -1,
                                           (LPARAM) t);
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
                }
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
                free(d->info[i]);
            }

            free(d);

            khm_set_dialog_result(hwnd, 0);
        }
        return TRUE;
    }
    return FALSE;
}
