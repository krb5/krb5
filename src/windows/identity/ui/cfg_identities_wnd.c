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
#if _WIN32_WINNT >= 0x0501
#include<uxtheme.h>
#endif

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
#if _WIN32_WINNT >= 0x0501
        EnableThemeDialogTexture(hwnd_panel, ETDT_ENABLETAB);
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
    BOOL cont = TRUE;

    count = TabCtrl_GetItemCount(hw_tab);

    for (idx = 0; idx < count && cont; idx++) {

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

        SendMessage(hw, KHUI_WM_CFG_NOTIFY,
                    MAKEWPARAM(0, WMCFG_APPLY), (LPARAM) &cont);
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
    HWND hw_firstctl;
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

    hw_firstctl = GetNextDlgTabItem(hw, NULL, FALSE);
    if (hw_firstctl) {
        SetFocus(hw_firstctl);
    }
}

static INT_PTR
handle_cfg_notify(HWND hwnd,
                  WPARAM wParam,
                  LPARAM lParam) {
    khui_config_node node;
    HWND hw;

    node = get_window_node(hwnd);
    if (node == NULL)
        return TRUE;

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
    if (node == NULL)
        return FALSE;

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

    BOOL removed;               /* this identity was marked for removal */
    BOOL applied;
    BOOL purged;                /* this identity was actually removed */

    khm_int32 flags;

    ident_props saved;
    ident_props work;

    HWND hwnd;
} ident_data;

typedef struct tag_global_props {
    BOOL monitor;
    BOOL auto_renew;
    BOOL sticky;
} global_props;

typedef struct tag_idents_data {
    BOOL         valid;

    ident_data * idents;
    khm_size     n_idents;
    khm_size     nc_idents;
#define IDENTS_DATA_ALLOC_INCR 8

    /* global options */
    global_props saved;
    global_props work;
    BOOL         applied;

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

static idents_data cfg_idents = {FALSE, NULL, 0, 0,
                                 {0, 0, 0},
                                 {0, 0, 0},
                                 FALSE,

                                 0, NULL };

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

    if (d->removed) {
        khm_handle h = NULL;
        khm_int32 flags = 0;

        khc_remove_space(csp_ident);

        /* calling kcdb_identity_get_config() will update the
           KCDB_IDENT_FLAG_CONFIG flag for the identity to reflect the
           fact that it nolonger has a configuration. */
        kcdb_identity_get_config(d->ident, 0, &h);
        if (h) {
            /* what the ? */
#ifdef DEBUG
            assert(FALSE);
#endif
            khc_close_space(h);
        }
#ifdef DEBUG
        kcdb_identity_get_flags(d->ident, &flags);
        assert(!(flags & KCDB_IDENT_FLAG_CONFIG));
#endif

        d->purged = TRUE;

    } else {

        if (d->saved.monitor != d->work.monitor)
            khc_write_int32(csp_ident, L"Monitor", !!d->work.monitor);

        if (d->saved.auto_renew != d->work.auto_renew)
            khc_write_int32(csp_ident, L"AllowAutoRenew",
                            !!d->work.auto_renew);

        if (d->saved.sticky != d->work.sticky) {
            kcdb_identity_set_flags(d->ident,
                                    (d->work.sticky)?KCDB_IDENT_FLAG_STICKY:0,
                                    KCDB_IDENT_FLAG_STICKY);
        }
    }

    khc_close_space(csp_ident);

    d->saved = d->work;

    d->applied = TRUE;

    if (d->hwnd && !d->removed)
        PostMessage(d->hwnd, KHUI_WM_CFG_NOTIFY,
                    MAKEWPARAM(0, WMCFG_UPDATE_STATE), 0);

    khm_refresh_config();
}

static void
write_params_idents(void) {
    khm_handle csp_cw = NULL;

    if (KHM_SUCCEEDED(khc_open_space(NULL, L"CredWindow",
                                     KHM_FLAG_CREATE, &csp_cw))) {
        if (cfg_idents.work.monitor != cfg_idents.saved.monitor) {
            khc_write_int32(csp_cw, L"DefaultMonitor",
                            !!cfg_idents.work.monitor);
            cfg_idents.saved.monitor = cfg_idents.work.monitor;
            cfg_idents.applied = TRUE;
        }
        if (cfg_idents.work.auto_renew != cfg_idents.saved.auto_renew) {
            khc_write_int32(csp_cw, L"DefaultAllowAutoRenew",
                            !!cfg_idents.work.auto_renew);
            cfg_idents.saved.auto_renew = cfg_idents.work.auto_renew;
            cfg_idents.applied = TRUE;
        }
        if (cfg_idents.work.sticky != cfg_idents.saved.sticky) {
            khc_write_int32(csp_cw, L"DefaultSticky",
                            !!cfg_idents.work.sticky);
            cfg_idents.saved.sticky = cfg_idents.work.sticky;
            cfg_idents.applied = TRUE;
        }

        khc_close_space(csp_cw);
        csp_cw = NULL;
    }

#if 0
    for (i=0; i < (int)cfg_idents.n_idents; i++) {
        write_params_ident(&cfg_idents.idents[i]);
    }
#endif

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
    khm_handle csp_cw = NULL;

    if (cfg_idents.valid)
        return;

#ifdef DEBUG
    assert(cfg_idents.idents == NULL);
    assert(cfg_idents.n_idents == 0);
    assert(cfg_idents.nc_idents == 0);
#endif

    if (KHM_SUCCEEDED(khc_open_space(NULL, L"CredWindow", 0, &csp_cw))) {
        khm_int32 t;

        if (KHM_SUCCEEDED(khc_read_int32(csp_cw, L"DefaultMonitor", &t)))
            cfg_idents.saved.monitor = !!t;
        else
            cfg_idents.saved.monitor = TRUE;

        if (KHM_SUCCEEDED(khc_read_int32(csp_cw, L"DefaultAllowAutoRenew", &t)))
            cfg_idents.saved.auto_renew = !!t;
        else
            cfg_idents.saved.auto_renew = TRUE;

        if (KHM_SUCCEEDED(khc_read_int32(csp_cw, L"DefaultSticky", &t)))
            cfg_idents.saved.sticky = !!t;
        else
            cfg_idents.saved.sticky = FALSE;

        khc_close_space(csp_cw);
        csp_cw = NULL;

    } else {

        cfg_idents.saved.monitor = TRUE;
        cfg_idents.saved.auto_renew = TRUE;
        cfg_idents.saved.sticky = FALSE;

    }

    cfg_idents.work = cfg_idents.saved;
    cfg_idents.applied = FALSE;

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
#ifdef DEBUG
        assert(cfg_idents.idents[i].flags & KCDB_IDENT_FLAG_CONFIG);
#endif

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


static void
refresh_data_idents(HWND hwnd) {
    cfg_idents.work.monitor =
        (IsDlgButtonChecked(hwnd, IDC_CFG_MONITOR) == BST_CHECKED);
    cfg_idents.work.auto_renew =
        (IsDlgButtonChecked(hwnd, IDC_CFG_RENEW) == BST_CHECKED);
    cfg_idents.work.sticky =
        (IsDlgButtonChecked(hwnd, IDC_CFG_STICKY) == BST_CHECKED);
}

static void
refresh_view_idents_state(HWND hwnd) {
    BOOL modified;
    BOOL applied;
    khm_int32 flags = 0;

    applied = cfg_idents.applied;
    modified = (cfg_idents.work.monitor != cfg_idents.saved.monitor ||
                cfg_idents.work.auto_renew != cfg_idents.saved.auto_renew ||
                cfg_idents.work.sticky != cfg_idents.saved.sticky);

    if (modified)
        flags |= KHUI_CNFLAG_MODIFIED;
    if (applied)
        flags |= KHUI_CNFLAG_APPLIED;

    khui_cfg_set_flags_inst(&cfg_idents.cfg, flags,
                            KHUI_CNFLAG_APPLIED | KHUI_CNFLAG_MODIFIED);
}

struct ctrl_row_dimensions {
    RECT enclosure;
    RECT label;
    RECT control;
};

typedef struct tag_add_ident_data {
    khui_new_creds * nc;

    struct ctrl_row_dimensions dim_small;
    struct ctrl_row_dimensions dim_medium;
    struct ctrl_row_dimensions dim_large;
    int row_gap;

    int current_y;
    int current_x;

    HWND hwnd_last_ctrl;
} add_ident_data;

void
get_ctrl_row_metrics(struct ctrl_row_dimensions * dim, HWND hw_lbl, HWND hw_ctl) {

    assert(hw_lbl);
    assert(hw_ctl);

    GetWindowRect(hw_lbl, &dim->label);
    GetWindowRect(hw_ctl, &dim->control);

    UnionRect(&dim->enclosure, &dim->label, &dim->control);
    OffsetRect(&dim->label,
               -dim->enclosure.left,
               -dim->enclosure.top);
    OffsetRect(&dim->control,
               -dim->enclosure.left,
               -dim->enclosure.top);
    OffsetRect(&dim->enclosure,
               -dim->enclosure.left,
               -dim->enclosure.top);
}

/* dialog box procedure for the "Add new identity" dialog */
INT_PTR CALLBACK
khm_cfg_add_ident_proc(HWND hwnd,
                       UINT umsg,
                       WPARAM wParam,
                       LPARAM lParam) {
    add_ident_data * d;

    switch(umsg) {
    case WM_INITDIALOG:
        /* we create a new credentials blob and pull in the identity
           selectors from the identity provider. */
        d = PMALLOC(sizeof(*d));
        ZeroMemory(d, sizeof(*d));

        khui_cw_create_cred_blob(&d->nc);
#ifdef DEBUG
        assert(d->nc != NULL);
#endif
        if (d->nc == NULL) {
            PFREE(d);
            break;
        }

        if (KHM_FAILED(kcdb_identpro_get_ui_cb(&d->nc->ident_cb))) {
            /* this should have worked.  The only reason it would fail
               is if there is no identity provider or if the identity
               provider does not support providing idnetity
               selectors. */
            khui_cw_destroy_cred_blob(d->nc);
            PFREE(d);
            break;
        }

#pragma warning(push)
#pragma warning(disable: 4244)
        SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)

        /* get metrics for dynamic controls */
        get_ctrl_row_metrics(&d->dim_small,
                             GetDlgItem(hwnd, IDC_SM_LBL),
                             GetDlgItem(hwnd, IDC_SM_CTL));
        get_ctrl_row_metrics(&d->dim_medium,
                             GetDlgItem(hwnd, IDC_MED_LBL),
                             GetDlgItem(hwnd, IDC_MED_CTL));
        get_ctrl_row_metrics(&d->dim_large,
                             GetDlgItem(hwnd, IDC_LG_LBL),
                             GetDlgItem(hwnd, IDC_LG_CTL));

        {
            RECT rlbl;
            RECT rctl;
            RECT rwnd;

            GetWindowRect(GetDlgItem(hwnd, IDC_SM_LBL),
                          &rlbl);
            GetWindowRect(GetDlgItem(hwnd, IDC_SM_CTL),
                          &rctl);
            GetWindowRect(hwnd, &rwnd);

            OffsetRect(&rlbl, -rwnd.left, -rwnd.top);
            OffsetRect(&rctl, -rwnd.left, -rwnd.top);

            d->current_x = rlbl.left;
            d->current_y = rctl.top - GetSystemMetrics(SM_CYCAPTION);

            GetWindowRect(GetDlgItem(hwnd, IDC_MED_CTL),
                          &rlbl);
            OffsetRect(&rlbl, -rwnd.left, -rwnd.top);

            d->row_gap = rlbl.top - rctl.bottom;
        }

        d->nc->hwnd = hwnd;

        /* now call the UI callback and make it create the
           controls. */
        d->nc->ident_cb(d->nc, WMNC_IDENT_INIT, NULL, 0, 0,
                        (LPARAM) hwnd);

        break;

    case WM_DESTROY:
        d = (add_ident_data *)(LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            break;

        d->nc->ident_cb(d->nc, WMNC_IDENT_EXIT, NULL, 0, 0, 0);

        khui_cw_destroy_cred_blob(d->nc);
        PFREE(d);
        SetWindowLongPtr(hwnd, DWLP_USER, 0);
        break;

    case KHUI_WM_NC_NOTIFY:
        d = (add_ident_data *)(LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);
        if (d == NULL)
            break;

        switch(HIWORD(wParam)) {
        case WMNC_ADD_CONTROL_ROW:
            {
                khui_control_row * row;
                RECT r_lbl, r_inp, r_enc;
                struct ctrl_row_dimensions * dim;
                HFONT hf;

                row = (khui_control_row *) lParam;

#ifdef DEBUG
                assert(row->label);
                assert(row->input);
                assert(d);
#endif

                if (row->size == KHUI_CTRLSIZE_SMALL) {
                    dim = &d->dim_small;
                } else if (row->size == KHUI_CTRLSIZE_HALF) {
                    dim = &d->dim_medium;
                } else {
                    dim = &d->dim_large;
#ifdef DEBUG
                    assert(row->size == KHUI_CTRLSIZE_FULL);
#endif
                }

                CopyRect(&r_enc, &dim->enclosure);
                CopyRect(&r_lbl, &dim->label);
                CopyRect(&r_inp, &dim->control);

                OffsetRect(&r_enc, d->current_x, d->current_y);
                OffsetRect(&r_lbl, r_enc.left, r_enc.top);
                OffsetRect(&r_inp, r_enc.left, r_enc.top);

                d->current_y += r_enc.bottom - r_enc.top;

                hf = (HFONT) SendDlgItemMessage(hwnd, IDOK, WM_GETFONT, 0, 0);

                if (row->label) {
                    SetWindowPos(row->label,
                                 ((d->hwnd_last_ctrl != NULL)?
                                  d->hwnd_last_ctrl :
                                  HWND_TOP),
                                 r_lbl.left, r_lbl.top,
                                 r_lbl.right - r_lbl.left,
                                 r_lbl.bottom - r_lbl.top,
                                 SWP_DEFERERASE | SWP_NOACTIVATE |
                                 SWP_NOOWNERZORDER);
                    if (hf)
                        SendMessage(row->label, WM_SETFONT,
                                    (WPARAM) hf,
                                    TRUE);
                    d->hwnd_last_ctrl = row->label;
                }

                if (row->input) {
                    SetWindowPos(row->input,
                                 ((d->hwnd_last_ctrl != NULL)?
                                  d->hwnd_last_ctrl :
                                  HWND_TOP),
                                 r_inp.left, r_inp.top,
                                 r_inp.right - r_inp.left,
                                 r_inp.bottom - r_inp.top,
                                 SWP_DEFERERASE | SWP_NOACTIVATE |
                                 SWP_NOOWNERZORDER);
                    if (hf)
                        SendMessage(row->input, WM_SETFONT,
                                    (WPARAM) hf,
                                    TRUE);
                    d->hwnd_last_ctrl = row->input;
                }
            }
            break;

        case WMNC_IDENTITY_CHANGE:
            break;
        }
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
            wchar_t err_msg[1024];
            khm_handle ident = NULL;
            khm_handle csp_ident = NULL;
            khm_size cb;
            khm_int32 rv = KHM_ERROR_SUCCESS;
            khm_int32 flags = 0;

            d = (add_ident_data *)(LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (!d || !d->nc)
                break;

            if (d->nc->ident_cb)
                d->nc->ident_cb(d->nc, WMNC_IDENT_PREPROCESS, NULL, 0, 0, 0);

            /* check if there was an identity selected */
            if (d->nc->n_identities == 0 ||
                d->nc->identities[0] == NULL) {

                StringCbCopy(idname, sizeof(idname), L"");

                LoadString(khm_hInstance, IDS_CFG_IDNAME_NON,
                           err_msg, ARRAYLENGTH(err_msg));

                goto show_failure;
            }

            ident = d->nc->identities[0];
            kcdb_identity_hold(ident);

            cb = sizeof(idname);
            kcdb_identity_get_name(ident, idname, &cb);

            /* check if the identity is already in the
               configuration */
            if (KHM_SUCCEEDED(kcdb_identity_get_flags(ident, &flags)) &&
                (flags & KCDB_IDENT_FLAG_CONFIG)) {

                wchar_t fmt[256];

                LoadString(khm_hInstance, IDS_CFG_IDNAME_EXT,
                           fmt, ARRAYLENGTH(fmt));
                StringCbPrintf(err_msg, sizeof(err_msg), fmt, idname);

                kcdb_identity_release(ident);
                ident = NULL;

                goto show_failure;
            }

            /* now we have to create the identity configuration. */
            if (KHM_FAILED(rv = kcdb_identity_get_config(ident,
                                                         KHM_FLAG_CREATE,
                                                         &csp_ident))) {
                wchar_t fmt[256];

                LoadString(khm_hInstance, IDS_CFG_IDNAME_CCC,
                           fmt, ARRAYLENGTH(fmt));
                StringCbPrintf(err_msg, sizeof(err_msg), fmt, rv);

                kcdb_identity_release(ident);
                ident = NULL;

                goto show_failure;
            }

            /* create a value so that the configuration space will
               actually be created in the registry.  We don't want
               this new identity to be sticky. */
            khc_write_int32(csp_ident, L"Sticky", 0);

            khm_refresh_config();

            kcdb_identity_release(ident);
            khc_close_space(csp_ident);

            EndDialog(hwnd, 0);
            break;

        show_failure:
            {
                wchar_t title[512];
                wchar_t fmt[256];

                if (!err_msg[0])
                    break;

                LoadString(khm_hInstance, IDS_CFG_IDNAME_PRB,
                           fmt, ARRAYLENGTH(fmt));
                StringCbPrintf(title, sizeof(title), fmt, idname);

                MessageBox(hwnd, err_msg, title, MB_OK | MB_ICONSTOP);

                /* don't end the dialog yet */
                break;
            }
            break;
            
        } else if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hwnd, 1);
        } else {
            d = (add_ident_data *)(LONG_PTR)
                GetWindowLongPtr(hwnd, DWLP_USER);

            if (d && d->nc && d->nc->ident_cb) {
                return d->nc->ident_cb(d->nc, WMNC_IDENT_WMSG,
                                       hwnd, umsg, wParam, lParam);
            }
        }
        break;
    }

    return FALSE;
}

/* dialog procedure for the "general" pane of the "identities"
   configuration node. */
INT_PTR CALLBACK
khm_cfg_ids_tab_proc(HWND hwnd,
                    UINT umsg,
                    WPARAM wParam,
                    LPARAM lParam) {

    switch(umsg) {
    case WM_INITDIALOG:
        {
            HICON hicon;

            hold_idents_data();

            cfg_idents.hwnd = hwnd;
            cfg_idents.cfg = *((khui_config_init_data *) lParam);

            /* add the status icons */
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

        _done_with_icons:

            CheckDlgButton(hwnd, IDC_CFG_MONITOR,
                           (cfg_idents.work.monitor)?BST_CHECKED:BST_UNCHECKED);
            CheckDlgButton(hwnd, IDC_CFG_RENEW,
                           (cfg_idents.work.auto_renew)?BST_CHECKED:BST_UNCHECKED);
            CheckDlgButton(hwnd, IDC_CFG_STICKY,
                           (cfg_idents.work.sticky)?BST_CHECKED:BST_UNCHECKED);

        }
        return FALSE;

    case WM_COMMAND:

        if (HIWORD(wParam) == BN_CLICKED) {
            UINT ctrl = LOWORD(wParam);

            switch(ctrl) {
            case IDC_CFG_MONITOR:
            case IDC_CFG_RENEW:
            case IDC_CFG_STICKY:
                refresh_data_idents(hwnd);
                break;

            case IDC_CFG_ADDIDENT:
                DialogBoxParam(khm_hInstance,
                               MAKEINTRESOURCE(IDD_CFG_ADDIDENT),
                               hwnd,
                               khm_cfg_add_ident_proc,
                               (LPARAM) hwnd);
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

/* dialog procedure for the "Identities" configuration node */
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
    khm_handle ident = NULL;

    cb = sizeof(idname);
    khui_cfg_get_name(node, idname, &cb);

    for (i=0; i < (int)cfg_idents.n_idents; i++) {
        if (!wcscmp(cfg_idents.idents[i].idname, idname))
            break;
    }

    if (i < (int)cfg_idents.n_idents) {
        if (cfg_idents.idents[i].purged) {
            /* we are re-creating a purged identity */
            cfg_idents.idents[i].purged = FALSE;
            cfg_idents.idents[i].removed = FALSE;
            cfg_idents.idents[i].applied = FALSE;

            read_params_ident(&cfg_idents.idents[i]);
        }
        return &cfg_idents.idents[i];
    }

    /* there is no identity data for this configuration node.  We try
       to create it. */
    if (KHM_FAILED(kcdb_identity_create(idname, 0, &ident)))
        return NULL;

    if (cfg_idents.n_idents >= cfg_idents.nc_idents) {
        cfg_idents.nc_idents = UBOUNDSS(cfg_idents.n_idents + 1,
                                        IDENTS_DATA_ALLOC_INCR,
                                        IDENTS_DATA_ALLOC_INCR);
#ifdef DEBUG
        assert(cfg_idents.nc_idents > cfg_idents.n_idents);
#endif
        cfg_idents.idents = PREALLOC(cfg_idents.idents,
                                     sizeof(*cfg_idents.idents) *
                                     cfg_idents.nc_idents);
#ifdef DEBUG
        assert(cfg_idents.idents);
#endif
        ZeroMemory(&(cfg_idents.idents[cfg_idents.n_idents]),
                   sizeof(*cfg_idents.idents) *
                   (cfg_idents.nc_idents - cfg_idents.n_idents));
    }

    i = (int) cfg_idents.n_idents;

    StringCbLength(idname, KCDB_IDENT_MAXCB_NAME, &cb);
    cb += sizeof(wchar_t);

    cfg_idents.idents[i].idname = PMALLOC(cb);
#ifdef DEBUG
    assert(cfg_idents.idents[i].idname);
#endif
    StringCbCopy(cfg_idents.idents[i].idname, cb, idname);

    cfg_idents.idents[i].ident = ident;
    cfg_idents.idents[i].removed = FALSE;

    kcdb_identity_get_flags(ident, &cfg_idents.idents[i].flags);
#ifdef DEBUG
    assert(cfg_idents.idents[i].flags & KCDB_IDENT_FLAG_CONFIG);
#endif

    read_params_ident(&cfg_idents.idents[i]);

    cfg_idents.n_idents++;

    /* leave ident held. */

    return &cfg_idents.idents[i];
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
mark_remove_ident(HWND hwnd, khui_config_init_data * idata) {
    ident_data * d;

    d = find_ident_by_node(idata->ctx_node);
#ifdef DEBUG
    assert(d);
#endif

    if (d->removed)
        return;

    d->removed = TRUE;

    khui_cfg_set_flags_inst(idata, KHUI_CNFLAG_MODIFIED,
                            KHUI_CNFLAG_MODIFIED);

    EnableWindow(GetDlgItem(hwnd, IDC_CFG_REMOVE), FALSE);
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

/* dialog procedure for the "general" pane of individual identity
   configuration nodes. */
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

            case IDC_CFG_REMOVE:
                mark_remove_ident(hwnd, idata);
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
            BOOL * cont;

            khui_cfg_get_dialog_data(hwnd, &idata, NULL);

            switch (HIWORD(wParam)) {
            case WMCFG_APPLY:
                cont = (BOOL *) lParam;
                d = find_ident_by_node(idata->ctx_node);
                write_params_ident(d);
                if (d->removed) {
                    if (cont)
                        *cont = FALSE;
                } else {
                    khui_cfg_set_flags_inst(idata, KHUI_CNFLAG_APPLIED,
                                            KHUI_CNFLAG_APPLIED | 
                                            KHUI_CNFLAG_MODIFIED);
                }
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

/* dialog procedure for individual identity configuration nodes */
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
