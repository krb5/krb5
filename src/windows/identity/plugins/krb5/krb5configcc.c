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

#if _WIN32_WINNT < 0x501
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x501
#endif

#include<krbcred.h>
#include<krb5.h>
#include<assert.h>
#include<lm.h>
#include<commctrl.h>
#include<shlwapi.h>

#include<strsafe.h>

typedef struct tag_k5_file_cc {
    wchar_t path[MAX_PATH];
    khm_int32 flags;
} k5_file_cc;

#define K5_FCC_ALLOC_INCR  8

#define K5_FCC_FLAG_EXISTS 1

typedef struct tag_k5_ccc_data {
    khm_boolean   inc_api;
    khm_boolean   inc_mslsa;
    k5_file_cc *  file_ccs;
    khm_size      n_file_ccs;
    khm_size      nc_file_ccs;
} k5_ccc_data;

typedef struct tag_k5_ccc_dlg_data {
    khui_config_node node;
    k5_ccc_data save;
    k5_ccc_data work;
} k5_ccc_dlg_data;

void k5_free_file_ccs(k5_ccc_data * d) {
    if (d->file_ccs)
        PFREE(d->file_ccs);
    d->n_file_ccs = 0;
    d->nc_file_ccs = 0;
}

void k5_flush_file_ccs(k5_ccc_data * d) {
    d->n_file_ccs = 0;
}

void k5_del_file_cc(k5_ccc_data * d, khm_size idx) {
    if (idx > d->n_file_ccs)
        return;

    if (idx < d->n_file_ccs - 1) {
        MoveMemory(&d->file_ccs[idx],
                   &d->file_ccs[idx + 1],
                   sizeof(d->file_ccs[0]) * (d->n_file_ccs - (idx + 1)));
    }

    d->n_file_ccs--;
}

void k5_add_file_cc(k5_ccc_data * d, wchar_t * path) {
    khm_size i;
    khm_size cch;

    if (FAILED(StringCchLength(path, MAX_PATH, &cch)) ||
        cch == 0)
        return;

    /* see if it's there first */
    for (i=0; i < d->n_file_ccs; i++) {
        if(!_wcsicmp(d->file_ccs[i].path, path))
            return;
    }

    if (d->n_file_ccs == d->nc_file_ccs) {
        k5_file_cc * f;

        d->nc_file_ccs = UBOUNDSS(d->n_file_ccs + 1,
                                  K5_FCC_ALLOC_INCR,
                                  K5_FCC_ALLOC_INCR);
#ifdef DEBUG
        assert(d->nc_file_ccs > d->n_file_ccs);
#endif
        f = PMALLOC(sizeof(*f) * d->nc_file_ccs);
        ZeroMemory(f, sizeof(*f) * d->nc_file_ccs);

        if (d->n_file_ccs > 0) {
#ifdef DEBUG
            assert(d->file_ccs != NULL);
#endif
            memcpy(f, d->file_ccs, sizeof(*f) * d->n_file_ccs);
        }
        if (d->file_ccs)
            PFREE(d->file_ccs);
        d->file_ccs = f;
    }

    StringCbCopy(d->file_ccs[d->n_file_ccs].path,
                 sizeof(d->file_ccs[0].path),
                 path);
    if(PathFileExists(path))
        d->file_ccs[d->n_file_ccs].flags = K5_FCC_FLAG_EXISTS;
    else
        d->file_ccs[d->n_file_ccs].flags = 0;

    d->n_file_ccs++;
}

void k5_read_file_cc_data(k5_ccc_data * d) {
    khm_int32 t;
    wchar_t * fclist = NULL;
    wchar_t * fc;
    khm_size cb;

#ifdef DEBUG
    assert(csp_params);
#endif

    d->inc_api = TRUE;
    t = TRUE;
    khc_read_int32(csp_params, L"MsLsaList", &t);
    d->inc_mslsa = t;

    if (khc_read_multi_string(csp_params, L"FileCCList", NULL, &cb)
        != KHM_ERROR_TOO_LONG ||
        cb <= sizeof(wchar_t) * 2) {

        k5_flush_file_ccs(d);
    } else {
        fclist = PMALLOC(cb);
#ifdef DEBUG
        assert(fclist);
#endif
        khc_read_multi_string(csp_params, L"FileCCList", fclist, &cb);

        for(fc = fclist; fc && *fc; fc = multi_string_next(fc)) {
            k5_add_file_cc(d, fc);
        }

        PFREE(fclist);
    }
}

void k5_write_file_cc_data(k5_ccc_data * d) {
    wchar_t * ms;
    khm_size cb;
    khm_size cbt;
    khm_int32 t;
    khm_size i;

#ifdef DEBUG
    assert(csp_params);
#endif
    if (KHM_FAILED(khc_read_int32(csp_params, L"MsLsaList", &t)) ||
        !!t != !!d->inc_mslsa) {
        khc_write_int32(csp_params, L"MsLsaList", !!d->inc_mslsa);
    }

    if (d->n_file_ccs > 0) {
        cb = d->n_file_ccs * MAX_PATH * sizeof(wchar_t);
        ms = PMALLOC(cb);
#ifdef DEBUG
        assert(ms);
#endif
        multi_string_init(ms, cb);

        for(i=0; i<d->n_file_ccs; i++) {
            cbt = cb;
            multi_string_append(ms, &cbt, d->file_ccs[i].path);
        }

        khc_write_multi_string(csp_params, L"FileCCList", ms);

        PFREE(ms);
    } else {
        if (khc_read_multi_string(csp_params, L"FileCCList", NULL, &cb)
            != KHM_ERROR_TOO_LONG ||
            cb != sizeof(wchar_t) * 2)

            khc_write_multi_string(csp_params, L"FileCCList", L"\0\0");
    }
}

void k5_copy_file_cc_data(k5_ccc_data * dest, const k5_ccc_data * src) {
    khm_size i;

    k5_flush_file_ccs(dest);
    dest->inc_mslsa = src->inc_mslsa;
    dest->inc_api = src->inc_api;

    for (i=0; i < src->n_file_ccs; i++) {
        k5_add_file_cc(dest, src->file_ccs[i].path);
    }
}

BOOL k5_ccc_get_mod(k5_ccc_dlg_data * d) {
    khm_size i, j;

    if (!!d->work.inc_mslsa != !!d->save.inc_mslsa ||
        !!d->work.inc_api != !!d->save.inc_api ||
        d->work.n_file_ccs != d->save.n_file_ccs)
        return TRUE;

    for (i=0; i < d->work.n_file_ccs; i++) {
        for (j=0; j < d->save.n_file_ccs; j++) {
            if (!_wcsicmp(d->work.file_ccs[i].path,
                         d->save.file_ccs[j].path))
                break;
        }
        if (j >= d->save.n_file_ccs)
            return TRUE;
    }

    return FALSE;
}

void k5_ccc_update_ui(HWND hwnd, k5_ccc_dlg_data * d) {
    khm_size i;
    HWND lv;

    if (d->work.inc_api)
        CheckDlgButton(hwnd, IDC_CFG_INCAPI, BST_CHECKED);
    else
        CheckDlgButton(hwnd, IDC_CFG_INCAPI, BST_UNCHECKED);
    if (d->work.inc_mslsa)
        CheckDlgButton(hwnd, IDC_CFG_INCMSLSA, BST_CHECKED);
    else
        CheckDlgButton(hwnd, IDC_CFG_INCMSLSA, BST_UNCHECKED);

    lv = GetDlgItem(hwnd, IDC_CFG_FCLIST);
#ifdef DEBUG
    assert(lv);
#endif
    ListView_DeleteAllItems(lv);

    for (i=0; i<d->work.n_file_ccs; i++) {
        LVITEM lvi;

        ZeroMemory(&lvi, sizeof(lvi));

        lvi.mask = LVIF_PARAM | LVIF_TEXT;
        lvi.lParam = (LPARAM) i;
        lvi.pszText = d->work.file_ccs[i].path;

        ListView_InsertItem(lv, &lvi);
    }

    if (k5_ccc_get_mod(d)) {
        khui_cfg_set_flags(d->node,
                           KHUI_CNFLAG_MODIFIED,
                           KHUI_CNFLAG_MODIFIED);
    } else {
        khui_cfg_set_flags(d->node,
                           0,
                           KHUI_CNFLAG_MODIFIED);
    }
}

void k5_ccc_update_data(HWND hwnd, k5_ccc_data * d) {
    if (IsDlgButtonChecked(hwnd, IDC_CFG_INCAPI) == BST_CHECKED)
        d->inc_api = TRUE;
    else
        d->inc_api = FALSE;

    if (IsDlgButtonChecked(hwnd, IDC_CFG_INCMSLSA) == BST_CHECKED)
        d->inc_mslsa = TRUE;
    else
        d->inc_mslsa = FALSE;
    /* everything else is controlled by buttons */
}

INT_PTR CALLBACK
k5_ccconfig_dlgproc(HWND hwnd,
                    UINT uMsg,
                    WPARAM wParam,
                    LPARAM lParam) {

    k5_ccc_dlg_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        d = PMALLOC(sizeof(*d));
#ifdef DEBUG
        assert(d);
#endif
        ZeroMemory(d, sizeof(*d));
        k5_read_file_cc_data(&d->save);
        k5_copy_file_cc_data(&d->work, &d->save);

        d->node = (khui_config_node) lParam;

#pragma warning(push)
#pragma warning(disable: 4244)
        SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

        {
            LVCOLUMN lvc;
            HWND lv;
            wchar_t buf[256];
            RECT r;

            lv = GetDlgItem(hwnd, IDC_CFG_FCLIST);
#ifdef DEBUG
            assert(lv);
#endif
            ZeroMemory(&lvc, sizeof(lvc));
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;

            LoadString(hResModule, IDS_CFG_FCTITLE,
                       buf, ARRAYLENGTH(buf));

            GetWindowRect(lv, &r);

            lvc.pszText = buf;
            lvc.cx = (r.right - r.left) * 9 / 10;

            ListView_InsertColumn(lv, 0, &lvc);
        }

        SendDlgItemMessage(hwnd, IDC_CFG_FCNAME, EM_SETLIMITTEXT,
                           MAX_PATH - 1, 0);

        k5_ccc_update_ui(hwnd, d);
        break;

    case WM_COMMAND:
        d = (k5_ccc_dlg_data *) (DWORD_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d == NULL)
            break;

        switch(wParam) {
        case MAKEWPARAM(IDC_CFG_ADD, BN_CLICKED):
            {
                wchar_t path[MAX_PATH];
                wchar_t cpath[MAX_PATH];
                khm_size i;

                GetDlgItemText(hwnd, IDC_CFG_FCNAME,
                               cpath, ARRAYLENGTH(cpath));

                PathCanonicalize(path, cpath);

                if (!*path)
                    return TRUE; /* nothing to add */

                for (i=0; i < d->work.n_file_ccs; i++) {
                    if (!_wcsicmp(path, d->work.file_ccs[i].path)) {

                        /* allow the user to correct case, as appropriate */
                        StringCbCopy(d->work.file_ccs[i].path,
                                     sizeof(d->work.file_ccs[i].path),
                                     path);
                        k5_ccc_update_ui(hwnd, d);
                        return TRUE;
                    }
                }

                /* not there.  we need to add.  but check a few things
                   first */
                if (!PathFileExists(path)) {
                    wchar_t title[64];
                    wchar_t text[128];

                    LoadString(hResModule, IDS_CFG_FCN_WARNING,
                               title, ARRAYLENGTH(title));

                    LoadString(hResModule, IDS_CFG_FCN_W_NOTFOUND,
                               text, ARRAYLENGTH(text));
#if _WIN32_WINNT >= 0x501
                    if (IS_COMMCTL6())
                    {
                        EDITBALLOONTIP bt;

                        bt.cbStruct = sizeof(bt);
                        bt.pszTitle = title;
                        bt.pszText = text;
                        bt.ttiIcon = TTI_WARNING;

                        SendDlgItemMessage(hwnd, IDC_CFG_FCNAME,
                                           EM_SHOWBALLOONTIP,
                                           0,
                                           (LPARAM) &bt);
                    } else {
#endif
                        MessageBox(hwnd, text, title, MB_OK | MB_ICONWARNING);
#if _WIN32_WINNT >= 0x501
                    }
#endif
                } else if (PathIsRelative(path)) {
                    wchar_t title[64];
                    wchar_t text[128];

                    LoadString(hResModule, IDS_CFG_FCN_WARNING,
                               title, ARRAYLENGTH(title));
                    LoadString(hResModule, IDS_CFG_FCN_W_RELATIVE,
                               text, ARRAYLENGTH(text));

#if _WIN32_WINNT >= 0x501
                    if (IS_COMMCTL6())
                    {
                        EDITBALLOONTIP bt;

                        bt.cbStruct = sizeof(bt);
                        bt.pszTitle = title;
                        bt.pszText = text;
                        bt.ttiIcon = TTI_WARNING;

                        SendDlgItemMessage(hwnd, IDC_CFG_FCNAME,
                                           EM_SHOWBALLOONTIP,
                                           0,
                                           (LPARAM) &bt);
                    } else {
#endif
                        MessageBox(hwnd, text, title, MB_OK | MB_ICONWARNING);
#if _WIN32_WINNT >= 0x501
                    }
#endif
                }

                k5_add_file_cc(&d->work, path);

                k5_ccc_update_ui(hwnd, d);
            }
            return TRUE;

        case MAKEWPARAM(IDC_CFG_BROWSE, BN_CLICKED):
            {
                OPENFILENAME ofn;
                wchar_t path[MAX_PATH * 8];
                wchar_t title[128];

                ZeroMemory(&ofn, sizeof(ofn));
                ZeroMemory(path, sizeof(path));

                GetDlgItemText(hwnd, IDC_CFG_FCNAME,
                               path, ARRAYLENGTH(path));

                /* don't pass in invalid paths */
                if (!PathFileExists(path))
                    *path = 0;

                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFilter = L"All files\0*.*\0\0";
                ofn.nFilterIndex = 1;
                ofn.lpstrFile = path;
                ofn.nMaxFile = ARRAYLENGTH(path);
                ofn.lpstrTitle = title;

                LoadString(hResModule, IDS_CFG_FCOPENTITLE,
                           title, ARRAYLENGTH(title));

                ofn.Flags = OFN_ALLOWMULTISELECT |
                    OFN_DONTADDTORECENT |
                    OFN_FORCESHOWHIDDEN |
                    OFN_EXPLORER;

                if (GetOpenFileName(&ofn)) {
                    wchar_t * p;
                    wchar_t spath[MAX_PATH];

                    p = multi_string_next(path);
                    if (p) {
                        /* multi select */
                        for(;p && *p; p = multi_string_next(p)) {
                            StringCbCopy(spath, sizeof(spath), path);
                            PathAppend(spath, p);

                            k5_add_file_cc(&d->work, spath);
                        }
                    } else {
                        /* single select */
                        k5_add_file_cc(&d->work, path);
                    }
                    k5_ccc_update_ui(hwnd, d);
                }
            }
            return TRUE;

        case MAKEWPARAM(IDC_CFG_REMOVE, BN_CLICKED):
            {
                khm_size i;
                int lv_idx;
                HWND lv;
                wchar_t buf[MAX_PATH];

                lv = GetDlgItem(hwnd, IDC_CFG_FCLIST);
#ifdef DEBUG
                assert(lv);
#endif

                lv_idx = -1;
                while((lv_idx = ListView_GetNextItem(lv, lv_idx,
                                                     LVNI_SELECTED)) != -1) {
                    ListView_GetItemText(lv, lv_idx, 0, buf, ARRAYLENGTH(buf));
                    for (i=0; i < d->work.n_file_ccs; i++) {
                        if (!_wcsicmp(buf, d->work.file_ccs[i].path)) {
                            k5_del_file_cc(&d->work, i);
                            break;
                        }
                    }
                }

                k5_ccc_update_ui(hwnd, d);
            }
            return TRUE;

        case MAKEWPARAM(IDC_CFG_INCAPI, BN_CLICKED):
        case MAKEWPARAM(IDC_CFG_INCMSLSA, BN_CLICKED):
            k5_ccc_update_data(hwnd, &d->work);
            k5_ccc_update_ui(hwnd, d);
            return TRUE;
        }
        break;

    case WM_DESTROY:
        d = (k5_ccc_dlg_data *) (DWORD_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d == NULL)
            break;

        k5_free_file_ccs(&d->work);
        k5_free_file_ccs(&d->save);
        PFREE(d);
        SetWindowLongPtr(hwnd, DWLP_USER, 0);
        return TRUE;

    case KHUI_WM_CFG_NOTIFY:
        d = (k5_ccc_dlg_data *) (DWORD_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d == NULL)
            break;

        switch(HIWORD(wParam)) {
        case WMCFG_APPLY:
            if (k5_ccc_get_mod(d)) {
                k5_write_file_cc_data(&d->work);
                k5_copy_file_cc_data(&d->save, &d->work);
                khui_cfg_set_flags(d->node,
                                   KHUI_CNFLAG_APPLIED,
                                   KHUI_CNFLAG_APPLIED);
                k5_ccc_update_ui(hwnd, d);

                kmq_post_sub_msg(k5_sub, KMSG_CRED, KMSG_CRED_REFRESH, 0, 0);
            }
            break;
        }
    }
    return FALSE;
}
