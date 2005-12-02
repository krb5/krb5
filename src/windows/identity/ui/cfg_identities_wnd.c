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

static khui_config_node
get_window_node(HWND hwnd) {
    return (khui_config_node) (LONG_PTR)
        GetWindowLongPtr(hwnd, DWLP_USER);
}

static void
set_window_node(HWND hwnd, khui_config_node node) {
#pragma warning(push)
#pragma warning(disable: 4244)
    SetWindowLongPtr(hwnd, DWLP_USER,
                     (LONG_PTR) node);
#pragma warning(pop)
}

static void
add_subpanels(HWND hwnd, 
              khui_config_node ctx_node,
              khui_config_node ref_node) {

    HWND hw_tab;
    HWND hw_target;
    khui_config_node sub;
    khui_config_node_reg reg;
    khui_config_init_data idata;
    int idx;

    hw_tab = GetDlgItem(hwnd, IDC_CFG_TAB);
    hw_target = GetDlgItem(hwnd, IDC_CFG_TARGET);
#ifdef DEBUG
    assert(hw_tab);
    assert(hw_target);
#endif

    if (KHM_FAILED(khui_cfg_get_first_subpanel(ref_node, &sub))) {
#ifdef DEBUG
        assert(FALSE);
#endif
        return;
    }

    idx = 0;
    while(sub) {
        HWND hwnd_panel;
        TCITEM tci;
        int iid;

        khui_cfg_get_reg(sub, &reg);

        if ((ctx_node == ref_node && (reg.flags & KHUI_CNFLAG_PLURAL)) ||
            (ctx_node != ref_node && !(reg.flags & KHUI_CNFLAG_PLURAL)))
            goto _next_node;

        idata.ctx_node = ctx_node;
        idata.this_node = sub;
        idata.ref_node = ref_node;

        hwnd_panel = CreateDialogParam(reg.h_module,
                                       reg.dlg_template,
                                       hwnd,
                                       reg.dlg_proc,
                                       (LPARAM) &idata);

#ifdef DEBUG
        assert(hwnd_panel);
#endif

        ShowWindow(hwnd_panel, SW_HIDE);

        ZeroMemory(&tci, sizeof(tci));

        tci.mask = TCIF_PARAM | TCIF_TEXT;
        tci.lParam = (LPARAM) sub;
        tci.pszText = (LPWSTR) reg.short_desc;

        iid = TabCtrl_InsertItem(hw_tab, 0, &tci);
        idx++;

        if (reg.flags & KHUI_CNFLAG_PLURAL) {
            khui_cfg_set_param_inst(sub, ctx_node, iid);
            khui_cfg_set_hwnd_inst(sub, ctx_node, hwnd_panel);
        } else {
            khui_cfg_set_param(sub, iid);
            khui_cfg_set_hwnd(sub, hwnd_panel);
        }

    _next_node:

        khui_cfg_get_next_release(&sub);
    }

    TabCtrl_SetCurSel(hw_tab, 0);
}

static void
apply_all(HWND hwnd, 
          HWND hw_tab,
          khui_config_node noderef) {
    TCITEM tci;
    HWND hw;
    khui_config_node_reg reg;
    int idx;
    int count;

    count = TabCtrl_GetItemCount(hw_tab);

    for (idx = 0; idx < count; idx++) {

        ZeroMemory(&tci, sizeof(tci));

        tci.mask = TCIF_PARAM;
        TabCtrl_GetItem(hw_tab,
                        idx,
                        &tci);

#ifdef DEBUG
        assert(tci.lParam);
#endif
        khui_cfg_get_reg((khui_config_node) tci.lParam, &reg);
        if (reg.flags & KHUI_CNFLAG_PLURAL)
            hw = khui_cfg_get_hwnd_inst((khui_config_node) tci.lParam,
                                        noderef);
        else
            hw = khui_cfg_get_hwnd((khui_config_node) tci.lParam);
#ifdef DEBUG
        assert(hw);
#endif

        PostMessage(hw, KHUI_WM_CFG_NOTIFY,
                    MAKEWPARAM(0, WMCFG_APPLY), 0);
    }
}

static void
show_tab_panel(HWND hwnd,
               khui_config_node node,
               HWND hw_tab,
               int idx,
               BOOL show) {
    TCITEM tci;
    HWND hw;
    HWND hw_target;
    RECT r;
    RECT rref;
    khui_config_node_reg reg;

    ZeroMemory(&tci, sizeof(tci));

    tci.mask = TCIF_PARAM;
    TabCtrl_GetItem(hw_tab,
                    idx,
                    &tci);

#ifdef DEBUG
    assert(tci.lParam);
#endif
    khui_cfg_get_reg((khui_config_node) tci.lParam, &reg);
    if (reg.flags & KHUI_CNFLAG_PLURAL)
        hw = khui_cfg_get_hwnd_inst((khui_config_node) tci.lParam,
                                    node);
    else
        hw = khui_cfg_get_hwnd((khui_config_node) tci.lParam);
#ifdef DEBUG
    assert(hw);
#endif

    if (!show) {
        ShowWindow(hw, SW_HIDE);
        return;
    }

    hw_target = GetDlgItem(hwnd, IDC_CFG_TARGET);
#ifdef DEBUG
    assert(hw_target);
#endif
    GetWindowRect(hwnd, &rref);
    GetWindowRect(hw_target, &r);

    OffsetRect(&r, -rref.left, -rref.top);

    SetWindowPos(hw,
                 hw_tab,
                 r.left, r.top,
                 r.right - r.left, r.bottom - r.top,
                 SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                 SWP_SHOWWINDOW);
}

static INT_PTR
handle_cfg_notify(HWND hwnd,
                  WPARAM wParam,
                  LPARAM lParam) {
    khui_config_node node;
    HWND hw;

    node = get_window_node(hwnd);

    if (HIWORD(wParam) == WMCFG_APPLY) {

        hw = GetDlgItem(hwnd, IDC_CFG_TAB);

        apply_all(hwnd,
                  hw,
                  node);
    }

    return TRUE;
}

static INT_PTR
handle_notify(HWND hwnd,
              WPARAM wParam,
              LPARAM lParam) {
    LPNMHDR lpnm;
    int i;


    khui_config_node node;

    lpnm = (LPNMHDR) lParam;
    node = get_window_node(hwnd);

    if (lpnm->idFrom == IDC_CFG_TAB) {
        switch(lpnm->code) {
        case TCN_SELCHANGING:
            i = TabCtrl_GetCurSel(lpnm->hwndFrom);

            show_tab_panel(hwnd, 
                           node,
                           lpnm->hwndFrom,
                           i,
                           FALSE);
            break;

        case TCN_SELCHANGE:
            i = TabCtrl_GetCurSel(lpnm->hwndFrom);

            show_tab_panel(hwnd,
                           node,
                           lpnm->hwndFrom,
                           i,
                           TRUE);
            break;
        }
        return TRUE;
    } else {
        return FALSE;
    }
}

typedef struct tag_ident_props {
    BOOL monitor;
    BOOL auto_renew;
    BOOL sticky;
} ident_props;

typedef struct tag_ident_data {
    khm_handle ident;
    wchar_t * idname;
    int lv_idx;

    BOOL removed;
    BOOL applied;

    khm_int32 flags;

    ident_props saved;
    ident_props work;

    HWND hwnd;
} ident_data;

typedef struct tag_idents_data {
    BOOL         valid;

    ident_data * idents;
    khm_size     n_idents;
    khm_size     nc_idents;

    int          refcount;

    HIMAGELIST   hi_status;
    int          idx_id;
    int          idx_default;
    int          idx_modified;
    int          idx_applied;
    int          idx_deleted;

    HWND         hwnd;
    khui_config_init_data cfg;
} idents_data;

static idents_data cfg_idents = {FALSE, NULL, 0, 0, 0, NULL };

static void
read_params_ident(ident_data * d) {
    khm_handle csp_ident;
    khm_handle csp_cw;
    khm_int32 t;

    if (KHM_FAILED(kcdb_identity_get_config(d->ident,
                                            KHM_PERM_READ,
                                            &csp_ident))) {
        csp_ident = NULL;
    }

    if (KHM_SUCCEEDED(khc_open_space(NULL, L"CredWindow", KHM_PERM_READ,
                                     &csp_cw))) {
        if (csp_ident) {
            khc_shadow_space(csp_ident,
                             csp_cw);
            khc_close_space(csp_cw);
        } else {
            csp_ident = csp_cw;
        }
        csp_cw = NULL;
    } else {
#ifdef DEBUG
        assert(FALSE);
#endif
        d->saved.monitor = TRUE;
        d->saved.auto_renew = TRUE;
        d->saved.sticky = FALSE;
        d->work = d->saved;

        if (csp_ident)
            khc_close_space(csp_ident);

        return;
    }

    if (KHM_FAILED(khc_read_int32(csp_ident, L"Monitor", &t))) {
#ifdef DEBUG
        assert(FALSE);
#endif
        d->saved.monitor = TRUE;
    } else {
        d->saved.monitor = !!t;
    }

    if (KHM_FAILED(khc_read_int32(csp_ident, L"AllowAutoRenew", &t))) {
#ifdef DEBUG
        assert(FALSE);
#endif
        d->saved.auto_renew = TRUE;
    } else {
        d->saved.auto_renew = !!t;
    }

    if (KHM_FAILED(khc_read_int32(csp_ident, L"Sticky", &t))) {
        d->saved.sticky = FALSE;
    } else {
        d->saved.sticky = !!t;
    }

    khc_close_space(csp_ident);

    d->work = d->saved;
    d->applied = FALSE;
}

static void
write_params_ident(ident_data * d) {
    khm_handle csp_ident;

    if (d->saved.monitor == d->work.monitor &&
        d->saved.auto_renew == d->work.auto_renew &&
        d->saved.sticky == d->work.sticky &&
        !d->removed)
        return;

    if (KHM_FAILED(kcdb_identity_get_config(d->ident, KHM_PERM_WRITE,
                                            &csp_ident))) {
#ifdef DEBUG
        assert(FALSE);
#endif
        return;
    }

    if (d->saved.monitor != d->work.monitor)
        khc_write_int32(csp_ident, L"Monitor", !!d->work.monitor);

    if (d->saved.auto_renew != d->work.auto_renew)
        khc_write_int32(csp_ident, L"AllowAutoRenew", !!d->work.auto_renew);

    if (d->saved.sticky != d->work.sticky) {
        kcdb_identity_set_flags(d->ident,
                                (d->work.sticky)?KCDB_IDENT_FLAG_STICKY:0,
                                KCDB_IDENT_FLAG_STICKY);
    }

    khc_close_space(csp_ident);

    d->saved = d->work;

    d->applied = TRUE;

    if (d->hwnd)
        PostMessage(d->hwnd, KHUI_WM_CFG_NOTIFY,
                    MAKEWPARAM(0, WMCFG_UPDATE_STATE), 0);
}

static void
write_params_idents(void) {
    int i;

    for (i=0; i < (int)cfg_idents.n_idents; i++) {
        write_params_ident(&cfg_idents.idents[i]);
    }

    if (cfg_idents.hwnd)
        PostMessage(cfg_idents.hwnd, KHUI_WM_CFG_NOTIFY,
                    MAKEWPARAM(0, WMCFG_UPDATE_STATE), 0);
}

static void
init_idents_data(void) {
    khm_int32 rv;
    wchar_t * t;
    wchar_t * widnames = NULL;
    khm_size cb;
    int n_tries = 0;
    int i;

    if (cfg_idents.valid)
        return;

#ifdef DEBUG
    assert(cfg_idents.idents == NULL);
    assert(cfg_idents.n_idents == 0);
    assert(cfg_idents.nc_idents == 0);
#endif

    do {
        rv = kcdb_identity_enum(KCDB_IDENT_FLAG_CONFIG,
                                KCDB_IDENT_FLAG_CONFIG,
                                NULL,
                                &cb,
                                &cfg_idents.n_idents);

        if (rv != KHM_ERROR_TOO_LONG ||
            cfg_idents.n_idents == 0 ||
            cb == 0)
            break;

        if (widnames)
            PFREE(widnames);
        widnames = PMALLOC(cb);
#ifdef DEBUG
        assert(widnames);
#endif

        rv = kcdb_identity_enum(KCDB_IDENT_FLAG_CONFIG,
                                KCDB_IDENT_FLAG_CONFIG,
                                widnames,
                                &cb,
                                &cfg_idents.n_idents);
        n_tries++;
    } while(KHM_FAILED(rv) &&
            n_tries < 5);

    if (KHM_FAILED(rv) ||
        cfg_idents.n_idents == 0) {
        cfg_idents.n_idents = 0;
        goto _cleanup;
    }

    cfg_idents.idents = PMALLOC(sizeof(*cfg_idents.idents) * 
                               cfg_idents.n_idents);
#ifdef DEBUG
    assert(cfg_idents.idents);
#endif
    ZeroMemory(cfg_idents.idents, 
               sizeof(*cfg_idents.idents) * cfg_idents.n_idents);
    cfg_idents.nc_idents = cfg_idents.n_idents;

    i = 0;
    for (t = widnames; t && *t; t = multi_string_next(t)) {
        khm_handle ident;

        if (KHM_FAILED(kcdb_identity_create(t, 0, &ident))) {
            cfg_idents.n_idents--;
            continue;
        }

        StringCbLength(t, KCDB_IDENT_MAXCB_NAME, &cb);
        cb += sizeof(wchar_t);

        cfg_idents.idents[i].idname = PMALLOC(cb);
#ifdef DEBUG
        assert(cfg_idents.idents[i].idname);
#endif
        StringCbCopy(cfg_idents.idents[i].idname, cb, t);

        cfg_idents.idents[i].ident = ident;
        cfg_idents.idents[i].removed = FALSE;

        kcdb_identity_get_flags(ident, &cfg_idents.idents[i].flags);

        read_params_ident(&cfg_idents.idents[i]);

        i++;
        /* leave identity held */
    }

 _cleanup:

    cfg_idents.valid = TRUE;

    if (widnames)
        PFREE(widnames);
}

static void
free_idents_data(void) {
    int i;

    if (!cfg_idents.valid)
        return;

    for (i=0; i< (int) cfg_idents.n_idents; i++) {
        if (cfg_idents.idents[i].ident)
            kcdb_identity_release(cfg_idents.idents[i].ident);
        if (cfg_idents.idents[i].idname)
            PFREE(cfg_idents.idents[i].idname);
    }

    if (cfg_idents.idents)
        PFREE(cfg_idents.idents);

    cfg_idents.idents = NULL;
    cfg_idents.n_idents = 0;
    cfg_idents.nc_idents = 0;
    cfg_idents.valid = FALSE;
}

static void
hold_idents_data(void) {
    if (!cfg_idents.valid)
        init_idents_data();
#ifdef DEBUG
    assert(cfg_idents.valid);
#endif
    cfg_idents.refcount++;
}

static void
release_idents_data(void) {
#ifdef DEBUG
    assert(cfg_idents.valid);
#endif
    cfg_idents.refcount--;

    if (cfg_idents.refcount == 0)
        free_idents_data();
}

#define BS_TRUE 1
#define BS_FALSE 2

static void
refresh_view_idents_sel(HWND hwnd) {
    HWND hw;
    int sel_count;
    int i;
    int idx;
    ident_data * d;
    LVITEM lvi;

    int monitor = 0;
    int auto_renew = 0;
    int sticky = 0;

    hw = GetDlgItem(hwnd, IDC_CFG_IDENTS);

    sel_count = ListView_GetSelectedCount(hw);

    idx = -1;
    for (i=0; i < sel_count; i++) {
        idx = ListView_GetNextItem(hw, idx, LVNI_SELECTED);
#ifdef DEBUG
        assert(idx != -1);
#endif
        ZeroMemory(&lvi, sizeof(lvi));

        lvi.iItem = idx;
        lvi.iSubItem = 0;
        lvi.mask = LVIF_PARAM;

        ListView_GetItem(hw, &lvi);

        d = (ident_data *) lvi.lParam;
#ifdef DEBUG
        assert(d != NULL);
#endif

        if (d->work.monitor)
            monitor |= BS_TRUE;
        else
            monitor |= BS_FALSE;

        if (d->work.auto_renew)
            auto_renew |= BS_TRUE;
        else
            auto_renew |= BS_FALSE;

        if (d->work.sticky)
            sticky |= BS_TRUE;
        else
            sticky |= BS_FALSE;
    }

    CheckDlgButton(hwnd, IDC_CFG_MONITOR,
                   (monitor == BS_TRUE)? BST_CHECKED:
                   ((monitor == BS_FALSE)? BST_UNCHECKED:
                    BST_INDETERMINATE));

    CheckDlgButton(hwnd, IDC_CFG_RENEW,
                   (auto_renew == BS_TRUE)? BST_CHECKED:
                   ((auto_renew == BS_FALSE)? BST_UNCHECKED:
                    BST_INDETERMINATE));

    CheckDlgButton(hwnd, IDC_CFG_STICKY,
                   (sticky == BS_TRUE)? BST_CHECKED:
                   ((sticky == BS_FALSE)? BST_UNCHECKED:
                    BST_INDETERMINATE));

    if (sel_count > 0) {
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_MONITOR), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_RENEW), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_STICKY), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_REMOVE), TRUE);
    } else {
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_MONITOR), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_RENEW), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_STICKY), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_REMOVE), FALSE);
    }
}

#undef BS_TRUE
#undef BS_FALSE

static void
refresh_data_idents(HWND hwnd) {
    HWND hw;
    int sel_count;
    int i;
    int idx;
    ident_data * d;
    LVITEM lvi;

    UINT monitor = IsDlgButtonChecked(hwnd, IDC_CFG_MONITOR);
    UINT auto_renew = IsDlgButtonChecked(hwnd, IDC_CFG_RENEW);
    UINT sticky = IsDlgButtonChecked(hwnd, IDC_CFG_STICKY);

    hw = GetDlgItem(hwnd, IDC_CFG_IDENTS);

    sel_count = ListView_GetSelectedCount(hw);

    idx = -1;
    for (i=0; i < sel_count; i++) {
        idx = ListView_GetNextItem(hw, idx, LVNI_SELECTED);
#ifdef DEBUG
        assert(idx != -1);
#endif
        ZeroMemory(&lvi, sizeof(lvi));

        lvi.iItem = idx;
        lvi.iSubItem = 0;
        lvi.mask = LVIF_PARAM;

        ListView_GetItem(hw, &lvi);

        d = (ident_data *) lvi.lParam;
#ifdef DEBUG
        assert(d != NULL);
#endif

        if (monitor == BST_CHECKED)
            d->work.monitor = TRUE;
        else if (monitor == BST_UNCHECKED)
            d->work.monitor = FALSE;

        if (auto_renew == BST_CHECKED)
            d->work.auto_renew = TRUE;
        else if (auto_renew == BST_UNCHECKED)
            d->work.auto_renew = FALSE;

        if (sticky == BST_CHECKED)
            d->work.sticky = TRUE;
        else if (sticky == BST_UNCHECKED)
            d->work.sticky = FALSE;

        if (d->hwnd)
            PostMessage(d->hwnd, KHUI_WM_CFG_NOTIFY,
                        MAKEWPARAM(0, WMCFG_UPDATE_STATE), 0);
    }
}

static void
refresh_view_idents_state(HWND hwnd) {
    HWND hw;
    int i;
    LVITEM lvi;
    ident_data * d;

    BOOL modified = FALSE;
    BOOL applied = FALSE;

    hw = GetDlgItem(hwnd, IDC_CFG_IDENTS);

    for (i = -1;;) {

        i = ListView_GetNextItem(hw, i, LVNI_ALL);
        if (i == -1)
            break;

        ZeroMemory(&lvi, sizeof(lvi));
        lvi.iItem = i;
        lvi.iSubItem = 0;
        lvi.mask = LVIF_PARAM;

        ListView_GetItem(hw, &lvi);

        d = (ident_data *) lvi.lParam;
#ifdef DEBUG
        assert(d != NULL);
#endif

        ZeroMemory(&lvi, sizeof(lvi));

        lvi.mask = LVIF_STATE;
        lvi.stateMask = LVIS_STATEIMAGEMASK;
        lvi.iItem = i;
        lvi.iSubItem = 0;

        if (d->removed) {
            lvi.state = INDEXTOSTATEIMAGEMASK(cfg_idents.idx_deleted);
            modified = TRUE;
        } else if (d->saved.monitor != d->work.monitor ||
                   d->saved.auto_renew != d->work.auto_renew ||
                   d->saved.sticky != d->work.sticky) {
            lvi.state = INDEXTOSTATEIMAGEMASK(cfg_idents.idx_modified);
            modified = TRUE;
        } else if (d->applied) {
            lvi.state = INDEXTOSTATEIMAGEMASK(cfg_idents.idx_applied);
            applied = TRUE;
        } else {
            lvi.state = INDEXTOSTATEIMAGEMASK(cfg_idents.idx_default);
        }

        ListView_SetItem(hw, &lvi);
    }

    {
        khm_int32 flags = 0;

        if (modified)
            flags |= KHUI_CNFLAG_MODIFIED;
        if (applied)
            flags |= KHUI_CNFLAG_APPLIED;

        khui_cfg_set_flags_inst(&cfg_idents.cfg, flags,
                                KHUI_CNFLAG_APPLIED | KHUI_CNFLAG_MODIFIED);
    }
}

static void
remove_idents(HWND hwnd) {
    HWND hw;
    int sel_count;
    int i;
    int idx;
    ident_data * d;
    LVITEM lvi;

    hw = GetDlgItem(hwnd, IDC_CFG_IDENTS);

    sel_count = ListView_GetSelectedCount(hw);

    idx = -1;
    for (i=0; i < sel_count; i++) {
        idx = ListView_GetNextItem(hw, idx, LVNI_SELECTED);
#ifdef DEBUG
        assert(idx != -1);
#endif
        ZeroMemory(&lvi, sizeof(lvi));

        lvi.iItem = idx;
        lvi.iSubItem = 0;
        lvi.mask = LVIF_PARAM;

        ListView_GetItem(hw, &lvi);

        d = (ident_data *) lvi.lParam;
#ifdef DEBUG
        assert(d != NULL);
#endif

        d->removed = TRUE;
    }
}

INT_PTR CALLBACK
khm_cfg_ids_tab_proc(HWND hwnd,
                    UINT umsg,
                    WPARAM wParam,
                    LPARAM lParam) {

    switch(umsg) {
    case WM_INITDIALOG:
        {
            HWND hw;
            HICON hicon;
            LVCOLUMN lvcol;
            LVITEM lvi;
            wchar_t coltext[256];
            RECT r;
            int i;

            hold_idents_data();

            cfg_idents.hwnd = hwnd;
            cfg_idents.cfg = *((khui_config_init_data *) lParam);

            /* first add the column */
            hw = GetDlgItem(hwnd, IDC_CFG_IDENTS);

            ZeroMemory(&lvcol, sizeof(lvcol));
            lvcol.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;

            lvcol.fmt = LVCFMT_IMAGE | LVCFMT_LEFT;

            GetWindowRect(hw, &r);
            lvcol.cx = ((r.right - r.left) * 95) / 100;

            LoadString(khm_hInstance, IDS_CFG_IDS_IDENTITY,
                       coltext, ARRAYLENGTH(coltext));
            lvcol.pszText = coltext;

            ListView_InsertColumn(hw, 0, &lvcol);

            /* and the status icons */
            if (cfg_idents.hi_status)
                goto _done_with_icons;

            cfg_idents.hi_status = 
                ImageList_Create(GetSystemMetrics(SM_CXSMICON),
                                 GetSystemMetrics(SM_CYSMICON), 
                                 ILC_COLOR8 | ILC_MASK,
                                 4,4);

            hicon =
                LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_ID),
                          IMAGE_ICON,
                          GetSystemMetrics(SM_CXSMICON),
                          GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

            cfg_idents.idx_id = ImageList_AddIcon(cfg_idents.hi_status,
                                                  hicon);

            DestroyIcon(hicon);

            hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_DEFAULT),
                              IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

            cfg_idents.idx_default = ImageList_AddIcon(cfg_idents.hi_status, 
                                                       hicon) + 1;

            DestroyIcon(hicon);

            hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_MODIFIED),
                              IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

            cfg_idents.idx_modified = ImageList_AddIcon(cfg_idents.hi_status, 
                                                        hicon) + 1;

            DestroyIcon(hicon);

            hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_APPLIED),
                              IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

            cfg_idents.idx_applied = ImageList_AddIcon(cfg_idents.hi_status, 
                                                       hicon) + 1;

            DestroyIcon(hicon);

            hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_DELETED),
                              IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

            cfg_idents.idx_deleted = ImageList_AddIcon(cfg_idents.hi_status, 
                                                       hicon) + 1;

            DestroyIcon(hicon);

            ListView_SetImageList(hw, cfg_idents.hi_status, LVSIL_SMALL);
            ListView_SetImageList(hw, cfg_idents.hi_status, LVSIL_STATE);

        _done_with_icons:

            /* now add each identity */
            for(i=0; i < (int)cfg_idents.n_idents; i++) {
                ZeroMemory(&lvi, sizeof(lvi));

                lvi.mask = LVIF_PARAM | LVIF_TEXT | LVIF_STATE | LVIF_IMAGE;
                lvi.iImage = cfg_idents.idx_id;
                lvi.lParam = (LPARAM) &cfg_idents.idents[i];
                lvi.pszText = cfg_idents.idents[i].idname;
                lvi.state = INDEXTOSTATEIMAGEMASK(cfg_idents.idx_default);
                lvi.stateMask = LVIS_STATEIMAGEMASK;

                cfg_idents.idents[i].lv_idx = ListView_InsertItem(hw, &lvi);
            }

        }
        return FALSE;

    case WM_NOTIFY:
        {
            LPNMHDR lpnm = (LPNMHDR) lParam;

            if (lpnm->code == LVN_ITEMCHANGED) {
                refresh_view_idents_sel(hwnd);
            }
        }
        return TRUE;

    case WM_COMMAND:

        if (HIWORD(wParam) == BN_CLICKED) {
            UINT ctrl = LOWORD(wParam);
            switch(ctrl) {
            case IDC_CFG_MONITOR:
            case IDC_CFG_RENEW:
            case IDC_CFG_STICKY:
                if (IsDlgButtonChecked(hwnd, ctrl) == BST_CHECKED)
                    CheckDlgButton(hwnd, ctrl, BST_UNCHECKED);
                else
                    CheckDlgButton(hwnd, ctrl, BST_CHECKED);
                refresh_data_idents(hwnd);
                break;

            case IDC_CFG_REMOVE:
                remove_idents(hwnd);
                break;
            }

            refresh_view_idents_state(hwnd);
        }

        khm_set_dialog_result(hwnd, 0);
        return TRUE;

    case KHUI_WM_CFG_NOTIFY:
        {
            switch(HIWORD(wParam)) {
            case WMCFG_APPLY:
                write_params_idents();
                break;

            case WMCFG_UPDATE_STATE:
                refresh_view_idents_state(hwnd);
                refresh_view_idents_sel(hwnd);
                break;
            }
        }
        return TRUE;

    case WM_DESTROY:
        cfg_idents.hwnd = NULL;

        if (cfg_idents.hi_status != NULL) {
            ImageList_Destroy(cfg_idents.hi_status);
            cfg_idents.hi_status = NULL;
        }
        release_idents_data();

        khm_set_dialog_result(hwnd, 0);

        return TRUE;
    }

    return FALSE;
}

INT_PTR CALLBACK
khm_cfg_identities_proc(HWND hwnd,
                        UINT uMsg,
                        WPARAM wParam,
                        LPARAM lParam) {
    HWND hw;
    switch(uMsg) {
    case WM_INITDIALOG:
        set_window_node(hwnd, (khui_config_node) lParam);
        add_subpanels(hwnd, (khui_config_node) lParam,
                      (khui_config_node) lParam);
        hw = GetDlgItem(hwnd, IDC_CFG_TAB);
        show_tab_panel(hwnd,
                       (khui_config_node) lParam,
                       hw,
                       TabCtrl_GetCurSel(hw),
                       TRUE);
        return FALSE;

    case WM_DESTROY:
        return 0;

    case KHUI_WM_CFG_NOTIFY:
        return handle_cfg_notify(hwnd, wParam, lParam);

    case WM_NOTIFY:
        return handle_notify(hwnd, wParam, lParam);
    }

    return FALSE;
}

static ident_data *
find_ident_by_node(khui_config_node node) {
    khm_size cb;
    wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
    int i;

    cb = sizeof(idname);
    khui_cfg_get_name(node, idname, &cb);

    for (i=0; i < (int)cfg_idents.n_idents; i++) {
        if (!wcscmp(cfg_idents.idents[i].idname, idname))
            break;
    }

    if (i < (int)cfg_idents.n_idents)
        return &cfg_idents.idents[i];
    else
        return NULL;
}

static void
refresh_view_ident(HWND hwnd, khui_config_node node) {
    ident_data * d;

    d = find_ident_by_node(node);
#ifdef DEBUG
    assert(d);
#endif

    CheckDlgButton(hwnd, IDC_CFG_MONITOR,
                   (d->work.monitor? BST_CHECKED: BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_CFG_RENEW,
                   (d->work.auto_renew? BST_CHECKED: BST_UNCHECKED));
    CheckDlgButton(hwnd, IDC_CFG_STICKY,
                   (d->work.sticky? BST_CHECKED: BST_UNCHECKED));
}

static void
refresh_data_ident(HWND hwnd, khui_config_init_data * idata) {
    ident_data * d;

    d = find_ident_by_node(idata->ctx_node);
#ifdef DEBUG
    assert(d);
#endif

    if (IsDlgButtonChecked(hwnd, IDC_CFG_MONITOR) == BST_CHECKED)
        d->work.monitor = TRUE;
    else
        d->work.monitor = FALSE;

    if (IsDlgButtonChecked(hwnd, IDC_CFG_RENEW) == BST_CHECKED)
        d->work.auto_renew = TRUE;
    else
        d->work.auto_renew = FALSE;

    if (IsDlgButtonChecked(hwnd, IDC_CFG_STICKY) == BST_CHECKED)
        d->work.sticky = TRUE;
    else
        d->work.sticky = FALSE;

    if (d->work.monitor != d->saved.monitor ||
        d->work.auto_renew != d->saved.auto_renew ||
        d->work.sticky != d->saved.sticky) {

        khui_cfg_set_flags_inst(idata, KHUI_CNFLAG_MODIFIED,
                                KHUI_CNFLAG_MODIFIED);

    } else {
        khui_cfg_set_flags_inst(idata, 0,
                                KHUI_CNFLAG_MODIFIED);
    }
}

INT_PTR CALLBACK
khm_cfg_id_tab_proc(HWND hwnd,
                    UINT umsg,
                    WPARAM wParam,
                    LPARAM lParam) {

    khui_config_init_data * idata;

    switch(umsg) {
    case WM_INITDIALOG:
        {
            ident_data * d;

            hold_idents_data();

            idata = (khui_config_init_data *) lParam;

            khui_cfg_init_dialog_data(hwnd, idata, 0, NULL, NULL);

            refresh_view_ident(hwnd, idata->ctx_node);

            d = find_ident_by_node(idata->ctx_node);
            if (d)
                d->hwnd = hwnd;
#ifdef DEBUG
            else
                assert(FALSE);
#endif
        }
        return FALSE;

    case WM_COMMAND:
        khui_cfg_get_dialog_data(hwnd, &idata, NULL);

        if (HIWORD(wParam) == BN_CLICKED) {
            switch(LOWORD(wParam)) {
            case IDC_CFG_MONITOR:
            case IDC_CFG_RENEW:
            case IDC_CFG_STICKY:

                refresh_data_ident(hwnd, idata);
                if (cfg_idents.hwnd)
                    PostMessage(cfg_idents.hwnd, KHUI_WM_CFG_NOTIFY,
                                MAKEWPARAM(1, WMCFG_UPDATE_STATE), 0);
                break;
            }
        }
        khm_set_dialog_result(hwnd, 0);
        return TRUE;

    case WM_DESTROY:
        {
            ident_data * d;

            khui_cfg_get_dialog_data(hwnd, &idata, NULL);

            d = find_ident_by_node(idata->ctx_node);
            if (d)
                d->hwnd = NULL;

            release_idents_data();
            khui_cfg_free_dialog_data(hwnd);
            khm_set_dialog_result(hwnd, 0);
        }
        return TRUE;

    case KHUI_WM_CFG_NOTIFY:
        {
            ident_data * d;

            khui_cfg_get_dialog_data(hwnd, &idata, NULL);

            switch (HIWORD(wParam)) {
            case WMCFG_APPLY:
                d = find_ident_by_node(idata->ctx_node);
                write_params_ident(d);
                khui_cfg_set_flags_inst(idata, KHUI_CNFLAG_APPLIED,
                                        KHUI_CNFLAG_APPLIED | 
                                        KHUI_CNFLAG_MODIFIED);
                break;

            case WMCFG_UPDATE_STATE:
                refresh_view_ident(hwnd, idata->ctx_node);
                refresh_data_ident(hwnd, idata);
                break;
            }
        }
        return TRUE;
    }

    return FALSE;
}

INT_PTR CALLBACK
khm_cfg_identity_proc(HWND hwnd,
                      UINT uMsg,
                      WPARAM wParam,
                      LPARAM lParam) {
    HWND hw;

    switch(uMsg) {
    case WM_INITDIALOG:
        {
            khui_config_node refnode = NULL;

            set_window_node(hwnd, (khui_config_node) lParam);

            khui_cfg_open(NULL, L"KhmIdentities", &refnode);
#ifdef DEBUG
            assert(refnode != NULL);
#endif
            add_subpanels(hwnd,
                          (khui_config_node) lParam,
                          refnode);

            hw = GetDlgItem(hwnd, IDC_CFG_TAB);

            show_tab_panel(hwnd,
                           (khui_config_node) lParam,
                           hw,
                           TabCtrl_GetCurSel(hw),
                           TRUE);

            khui_cfg_release(refnode);
        }
        return FALSE;

    case WM_DESTROY:
        return 0;

    case KHUI_WM_CFG_NOTIFY:
        return handle_cfg_notify(hwnd, wParam, lParam);

    case WM_NOTIFY:
        return handle_notify(hwnd, wParam, lParam);
    }
    return FALSE;
}
