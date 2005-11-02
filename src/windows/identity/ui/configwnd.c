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

static HWND cfgui_hwnd = NULL;

typedef struct tag_cfgui_wnd_data {
    khui_config_node current;
    HWND hw_current;
    HWND hw_generic_pane;
    HBRUSH hbr_white;
    HFONT hf_title;
    khui_bitmap kbmp_logo;
    HIMAGELIST hi_status;
    BOOL modified;
    int idx_default;
    int idx_modified;
    int idx_applied;
} cfgui_wnd_data;

static cfgui_wnd_data *
cfgui_get_wnd_data(HWND hwnd) {
    return (cfgui_wnd_data *)(LONG_PTR) 
        GetWindowLongPtr(hwnd, DWLP_USER);
}

static void
cfgui_set_wnd_data(HWND hwnd, cfgui_wnd_data * d) {
#pragma warning(push)
#pragma warning(disable: 4244)
    SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) d);
#pragma warning(pop)
}

static void
cfgui_add_node(cfgui_wnd_data * d,
               HWND hwtv,
               khui_config_node node,
               khui_config_node parent,
               BOOL sorted) {

    khui_config_node_reg reg;
    khui_config_node c;
    wchar_t wbuf[256];
    const wchar_t * short_desc;
    TVINSERTSTRUCT s;
    HTREEITEM hItem;

    if (node) {
        khui_cfg_get_reg(node, &reg);
        short_desc = reg.short_desc;
    } else {
        short_desc = wbuf;
        LoadString(khm_hInstance, IDS_CFG_ROOT_NAME,
                   wbuf, ARRAYLENGTH(wbuf));
        reg.flags = 0;
    }

    ZeroMemory(&s, sizeof(s));

    s.hParent = (node)?
        (HTREEITEM) khui_cfg_get_param(parent):
        TVI_ROOT;

    s.hInsertAfter = (sorted)? TVI_SORT: TVI_FIRST;

    s.itemex.mask =
        TVIF_CHILDREN |
        TVIF_PARAM |
        TVIF_TEXT |
        TVIF_STATE;

    {
        khui_config_node n;

        if (KHM_SUCCEEDED(khui_cfg_get_first_child(node,
                                                   &n))) {
            s.itemex.cChildren = 1;
            s.itemex.state = TVIS_EXPANDED;
            s.itemex.stateMask = TVIS_EXPANDED;
            khui_cfg_release(n);
        } else {
            s.itemex.cChildren = 0;
            s.itemex.state = 0;
            s.itemex.stateMask = TVIS_EXPANDED;
        }

        s.itemex.state |= INDEXTOSTATEIMAGEMASK(d->idx_default);
        s.itemex.stateMask |= TVIS_STATEIMAGEMASK;
    }

    s.itemex.lParam = (LPARAM) node;
    khui_cfg_hold(node);

    s.itemex.pszText = (LPWSTR) short_desc;

    hItem = TreeView_InsertItem(hwtv, &s);

    khui_cfg_set_param(node, (LPARAM) hItem);

    if (KHM_SUCCEEDED(khui_cfg_get_first_child(node,
                                             &c))) {
        do {
            cfgui_add_node(d, hwtv, c, node,
                           !!(reg.flags & KHUI_CNFLAG_SORT_CHILDREN));
        } while (KHM_SUCCEEDED(khui_cfg_get_next_release(&c)));
    }
}

static void 
cfgui_initialize_dialog(HWND hwnd) {
    cfgui_wnd_data * d;
    HWND hwtv;
    HWND hwtitle;
    HFONT hf;
    HDC hdc;
    HICON hicon;

    d = cfgui_get_wnd_data(hwnd);

    /* create and fill the image list for the treeview */

    d->hi_status = ImageList_Create(SM_CXICON, SM_CYICON, 
                                    ILC_COLOR8 | ILC_MASK,
                                    4,4);

    hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_DEFAULT),
                      IMAGE_ICON, SM_CXICON, SM_CYICON, LR_DEFAULTCOLOR);

    /* note that we can't use index 0 because that is used to indicate
       that there is no state image for the node */
    do {
        d->idx_default = ImageList_AddIcon(d->hi_status, hicon);
    } while(d->idx_default == 0);

    DestroyIcon(hicon);

    hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_MODIFIED),
                      IMAGE_ICON, SM_CXICON, SM_CYICON, LR_DEFAULTCOLOR);

    d->idx_modified = ImageList_AddIcon(d->hi_status, hicon);

    DestroyIcon(hicon);

    hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_APPLIED),
                      IMAGE_ICON, SM_CXICON, SM_CYICON, LR_DEFAULTCOLOR);

    d->idx_applied = ImageList_AddIcon(d->hi_status, hicon);

    DestroyIcon(hicon);

    /* now for the treeview */
    hwtv = GetDlgItem(hwnd, IDC_CFG_NODELIST);

    TreeView_SetImageList(hwtv, d->hi_status, TVSIL_STATE);

    cfgui_add_node(d, hwtv, NULL, NULL, FALSE);

    hdc = GetDC(hwnd);
    hf = CreateFont(-MulDiv(12, 
                            GetDeviceCaps(hdc, LOGPIXELSY), 
                            72),
                    0,          /* nWidth */
                    0,          /* nEscapement */
                    0,          /* nOrientation */
                    FW_BOLD,    /* fnWeight */
                    TRUE,       /* fdwItalic */
                    FALSE,      /* fdwUnderline */
                    FALSE,      /* fdwStrikeOut */
                    DEFAULT_CHARSET, /* fdwCharSet */
                    OUT_DEFAULT_PRECIS, /* fdwOutputPrecision */
                    CLIP_DEFAULT_PRECIS, /* fdwClipPrecision */
                    DEFAULT_QUALITY, /* fdwQuality */
                    FF_SWISS | DEFAULT_PITCH, /* pitch&family */
                    NULL);      /* face */
    ReleaseDC(hwnd, hdc);

    d->hf_title = hf;

    hwtitle = GetDlgItem(hwnd, IDC_CFG_TITLE);

    SendMessage(hwtitle,
                WM_SETFONT,
                (WPARAM) hf,
                (LPARAM) FALSE);
}

static void
cfgui_free_node(HWND hwtv, HTREEITEM hItem) {
    TVITEMEX iex;
    HTREEITEM hChItem;

    ZeroMemory(&iex, sizeof(iex));

    iex.mask = TVIF_PARAM;
    iex.hItem = hItem;

    if (TreeView_GetItem(hwtv, &iex)) {
        khui_config_node node;

        node = (khui_config_node) iex.lParam;
        khui_cfg_release(node);
    }

    hChItem = TreeView_GetChild(hwtv, hItem);
    while(hChItem) {
        cfgui_free_node(hwtv, hChItem);

        hChItem = TreeView_GetNextSibling(hwtv, hChItem);
    }
}

static void
cfgui_uninitialize_dialog(HWND hwnd) {
    cfgui_wnd_data * d;
    HWND hwtv;

    d = cfgui_get_wnd_data(hwnd);

    hwtv = GetDlgItem(hwnd, IDC_CFG_NODELIST);

    cfgui_free_node(hwtv, TreeView_GetRoot(hwtv));

    if (d->hf_title)
        DeleteObject(d->hf_title);

    if (d->hi_status)
        ImageList_Destroy(d->hi_status);
}

static void
cfgui_activate_node(HWND hwnd, khui_config_node node) {

    cfgui_wnd_data * d;
    HTREEITEM hItem;
    HWND hw_new;
    HWND hwtv;

    d = cfgui_get_wnd_data(hwnd);
    hwtv = GetDlgItem(hwnd, IDC_CFG_NODELIST);
    hItem = (HTREEITEM) khui_cfg_get_param(node);

#ifdef DEBUG
    assert(hItem);
    assert(hwtv);
#endif

    if (node == NULL) {
        hw_new = d->hw_generic_pane;
    } else {
        khui_config_node_reg reg;
        khm_int32 rv;

        hw_new = khui_cfg_get_hwnd(node);

        if (hw_new == NULL) {
            rv = khui_cfg_get_reg(node, &reg);
#ifdef DEBUG
            assert(KHM_SUCCEEDED(rv));
#endif
            hw_new = CreateDialogParam(reg.h_module,
                                       reg.dlg_template,
                                       hwnd,
                                       reg.dlg_proc,
                                       (LPARAM) node);
#ifdef DEBUG
            assert(hw_new);
#endif
            khui_cfg_set_hwnd(node, hw_new);
        }
    }

    if (hw_new == d->hw_current)
        return;                 /* nothing to do */

    {
        RECT r_title;
        RECT r_pane;
        HWND hw;

        if (d->hw_current)
            ShowWindow(d->hw_current, SW_HIDE);

        hw = GetDlgItem(hwnd, IDC_CFG_TITLE);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r_title);

        hw = GetDlgItem(hwnd, IDC_CFG_PANE);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r_pane);

        OffsetRect(&r_pane, -r_title.left, -r_title.top);

        SetWindowPos(hw_new,
                     hwtv,
                     r_pane.left, r_pane.top,
                     r_pane.right - r_pane.left,
                     r_pane.bottom - r_pane.top,
                     SWP_NOOWNERZORDER |
                     SWP_SHOWWINDOW |
                     SWP_NOACTIVATE);
    }

    if (node == NULL) {
        wchar_t wbuf[256];

        LoadString(khm_hInstance, IDS_CFG_ROOT_TITLE,
                   wbuf, ARRAYLENGTH(wbuf));

        SetDlgItemText(hwnd, IDC_CFG_TITLE, wbuf);
    } else {
        khm_int32 rv;
        khui_config_node_reg reg;

        rv = khui_cfg_get_reg(node, &reg);
#ifdef DEBUG
        assert(KHM_SUCCEEDED(rv));
#endif
        SetDlgItemText(hwnd, IDC_CFG_TITLE, reg.long_desc);
    }

    d->hw_current = hw_new;
    d->current = node;

    TreeView_SelectItem(hwtv, hItem);
}

static BOOL
cfgui_check_mod_state(khui_config_node node) {
    khm_int32 flags;
    khui_config_node c = NULL;
    BOOL rv = FALSE;

    flags = khui_cfg_get_flags(node);

    if (flags & KHUI_CNFLAG_MODIFIED)
        return TRUE;

    if (KHM_FAILED(khui_cfg_get_first_child(node, &c)))
        return FALSE;

    while(c) {
        rv = (rv || cfgui_check_mod_state(c));
        khui_cfg_get_next_release(&c);
    }

    return rv;
}

static void
cfgui_apply_settings(khui_config_node node) {
    HWND hwnd;
    khui_config_node c;

    hwnd = khui_cfg_get_hwnd(node);

    if (hwnd)
        SendMessage(hwnd, KHUI_WM_CFG_NOTIFY,
                    MAKEWPARAM(0, WMCFG_APPLY),
                    (LPARAM) node);

    if (KHM_FAILED(khui_cfg_get_first_child(node, &c)))
        return;

    while (c) {
        cfgui_apply_settings(c);
        khui_cfg_get_next_release(&c);
    }
}

static void
cfgui_update_state(HWND hwnd, 
                   khm_int32 flags,
                   khui_config_node node) {
    cfgui_wnd_data * d;
    HWND hwtv;
    HTREEITEM hItem;
    TVITEMEX itx;
    int idx;

    d = cfgui_get_wnd_data(hwnd);
    hwtv = GetDlgItem(hwnd, IDC_CFG_NODELIST);
    hItem = (HTREEITEM) khui_cfg_get_param(node);

    ZeroMemory(&itx, sizeof(itx));

    if (flags & KHUI_CNFLAG_MODIFIED)
        idx = d->idx_modified;
    else if (flags & KHUI_CNFLAG_APPLIED)
        idx = d->idx_applied;
    else
        idx = d->idx_default;

    itx.hItem = hItem;
    itx.mask = TVIF_STATE;
    itx.state = INDEXTOSTATEIMAGEMASK(idx);
    itx.stateMask = TVIS_STATEIMAGEMASK;

    TreeView_SetItem(hwtv, &itx);

    if(cfgui_check_mod_state(NULL)) {
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_SUMMARY), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDAPPLY), TRUE);
    } else {
        EnableWindow(GetDlgItem(hwnd, IDC_CFG_SUMMARY), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDAPPLY), FALSE);
    }
}


/* dialog procedure for the generic dialog */
static INT_PTR CALLBACK
cfgui_dlgproc_generic(HWND hwnd,
                      UINT uMsg,
                      WPARAM wParam,
                      LPARAM lParam) {
    cfgui_wnd_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        d = (cfgui_wnd_data *) lParam;
        cfgui_set_wnd_data(hwnd, d);
        return TRUE;

    case WM_CTLCOLORSTATIC:
        d = cfgui_get_wnd_data(hwnd);
        return (BOOL)(DWORD_PTR) d->hbr_white;

    case WM_ERASEBKGND:
        {
            HDC hdc = (HDC) wParam;
            RECT r_client;
            RECT r_logo;
            RECT r_fill;

            d = cfgui_get_wnd_data(hwnd);

            GetClientRect(hwnd, &r_client);
            SetRectEmpty(&r_logo);

            r_logo.right = d->kbmp_logo.cx;
            r_logo.bottom = d->kbmp_logo.cy;

            OffsetRect(&r_logo,
                       r_client.right - r_logo.right,
                       r_client.bottom - r_logo.bottom);

            khui_draw_bitmap(hdc,
                             r_logo.left,
                             r_logo.top,
                             &d->kbmp_logo);

            r_fill.left = 0;
            r_fill.top = 0;
            r_fill.right = r_logo.left;
            r_fill.bottom = r_client.bottom;
            FillRect(hdc, &r_fill, d->hbr_white);

            r_fill.left = r_logo.left;
            r_fill.right = r_client.right;
            r_fill.bottom = r_logo.top;
            FillRect(hdc, &r_fill, d->hbr_white);

            SetWindowLong(hwnd, DWL_MSGRESULT, (LONG) TRUE);
        }
        return TRUE;
    }

    return FALSE;
}

static INT_PTR CALLBACK 
cfgui_dlgproc(HWND hwnd,
              UINT uMsg,
              WPARAM wParam,
              LPARAM lParam) {

    khui_config_node node;
    cfgui_wnd_data * d;

    switch(uMsg) {
    case WM_INITDIALOG:
        node = (khui_config_node) lParam;

        khui_cfg_clear_params();

        d = malloc(sizeof(*d));
        ZeroMemory(d, sizeof(*d));

        d->hbr_white = CreateSolidBrush(RGB(255,255,255));

        d->hw_generic_pane = 
            CreateDialogParam(khm_hInstance,
                              MAKEINTRESOURCE(IDD_CFG_GENERIC),
                              hwnd,
                              cfgui_dlgproc_generic,
                              (LPARAM) d);

        khui_bitmap_from_hbmp(&d->kbmp_logo,
                              LoadImage(
                                        khm_hInstance,
                                        MAKEINTRESOURCE(IDB_LOGO_OPAQUE),
                                        IMAGE_BITMAP,
                                        0,
                                        0,
                                        LR_DEFAULTCOLOR));

        cfgui_set_wnd_data(hwnd, d);

        cfgui_initialize_dialog(hwnd);

        cfgui_activate_node(hwnd, node);

        khm_add_dialog(hwnd);
        khm_enter_modal(hwnd);

        khui_cfg_set_configui_handle(hwnd);

        return TRUE;

    case WM_DESTROY:
        cfgui_hwnd = NULL;

        khui_cfg_set_configui_handle(NULL);

        cfgui_uninitialize_dialog(hwnd);

        d = cfgui_get_wnd_data(hwnd);
        khui_delete_bitmap(&d->kbmp_logo);
        DeleteObject(d->hbr_white);

        khm_leave_modal();
        khm_del_dialog(hwnd);

        SetForegroundWindow(khm_hwnd_main);

        return FALSE;

    case WM_NOTIFY:
        {
            LPNMHDR lpnm;
            LPNMTREEVIEW lptv;

            lpnm = (LPNMHDR) lParam;

            switch (lpnm->code) {
            case TVN_SELCHANGED:
                lptv = (LPNMTREEVIEW) lParam;
                cfgui_activate_node(hwnd,
                                    (khui_config_node) 
                                    lptv->itemNew.lParam);
                return TRUE;
            }
        }
        return TRUE;

    case WM_CTLCOLORSTATIC:
        {
            d = cfgui_get_wnd_data(hwnd);
            return (BOOL)(DWORD_PTR) d->hbr_white;
        }
        /* implicit break */

    case WM_COMMAND:
        switch(wParam) {
        case MAKEWPARAM(IDCANCEL, BN_CLICKED):
            DestroyWindow(hwnd);
            break;

        case MAKEWPARAM(IDAPPLY, BN_CLICKED):
            cfgui_apply_settings(NULL);
            break;

        case MAKEWPARAM(IDOK, BN_CLICKED):
            cfgui_apply_settings(NULL);
            DestroyWindow(hwnd);
            break;
        }
        return TRUE;

    case KHUI_WM_CFG_NOTIFY:
        switch(HIWORD(wParam)) {
        case WMCFG_SHOW_NODE:
            cfgui_activate_node(hwnd, (khui_config_node) lParam);
            break;

        case WMCFG_UPDATE_STATE:
            cfgui_update_state(hwnd, LOWORD(wParam), 
                               (khui_config_node) lParam);
            break;
        }
        return TRUE;
    }

    return FALSE;
}

static void 
cfgui_create_window(khui_config_node node) {
#ifdef DEBUG
    assert(cfgui_hwnd == NULL);
#endif

    khm_refresh_config();

    cfgui_hwnd = CreateDialogParam(khm_hInstance,
                                   MAKEINTRESOURCE(IDD_CFG_MAIN),
                                   khm_hwnd_main,
                                   cfgui_dlgproc,
                                   (LPARAM) node);
#ifdef DEBUG
    assert(cfgui_hwnd != NULL);
#endif
    ShowWindow(cfgui_hwnd,SW_SHOW);
}

static void 
cfgui_destroy_window(void) {
    if (cfgui_hwnd)
        DestroyWindow(cfgui_hwnd);
    /* cfgui_hwnd will be set to NULL in the dialog proc */
}

void 
khm_show_config_pane(khui_config_node node) {
    if (cfgui_hwnd != NULL) {
        SendMessage(cfgui_hwnd, KHUI_WM_CFG_NOTIFY,
                    MAKEWPARAM(0, WMCFG_SHOW_NODE),
                    (LPARAM) node);
    } else {
        cfgui_create_window(node);
    }
}

void khm_refresh_config(void) {
    khm_size cb;
    khm_size n_idents;
    wchar_t * idents = NULL;
    wchar_t * t;
    khm_int32 rv;
    int n_tries = 0;
    khui_config_node cfg_ids = NULL;

    do {
        rv = kcdb_identity_enum(KCDB_IDENT_FLAG_CONFIG,
                                KCDB_IDENT_FLAG_CONFIG,
                                NULL,
                                &cb,
                                &n_idents);

        if (rv != KHM_ERROR_TOO_LONG ||
            n_idents == 0)
            return;

        if (idents)
            free(idents);
        idents = malloc(cb);
#ifdef DEBUG
        assert(idents);
#endif

        rv = kcdb_identity_enum(KCDB_IDENT_FLAG_CONFIG,
                                KCDB_IDENT_FLAG_CONFIG,
                                idents,
                                &cb,
                                &n_idents);

        n_tries++;
    } while(KHM_FAILED(rv) &&
            n_tries < 5);

    if (KHM_FAILED(rv))
        goto _cleanup;

    if (KHM_FAILED(khui_cfg_open(NULL,
                                 L"KhmIdentities",
                                 &cfg_ids)))
        goto _cleanup;

    for(t = idents; t && *t; t = multi_string_next(t)) {
        khui_config_node cfg_id = NULL;

        rv = khui_cfg_open(cfg_ids,
                           t,
                           &cfg_id);

        if (KHM_FAILED(rv)) {
            khui_config_node_reg reg;
            wchar_t wshort[KHUI_MAXCCH_SHORT_DESC];
            wchar_t wlong[KHUI_MAXCCH_LONG_DESC];
            wchar_t wfmt[KHUI_MAXCCH_SHORT_DESC];

            ZeroMemory(&reg, sizeof(reg));

            reg.name = t;
            reg.short_desc = wshort;
            reg.long_desc = wlong;
            reg.h_module = khm_hInstance;
            reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_IDENTITY);
            reg.dlg_proc = khm_cfg_identity_proc;
            reg.flags = 0;

            LoadString(khm_hInstance, IDS_CFG_IDENTITY_SHORT,
                       wfmt, ARRAYLENGTH(wfmt));
            StringCbPrintf(wshort, sizeof(wshort), wfmt, t);

            LoadString(khm_hInstance, IDS_CFG_IDENTITY_LONG,
                       wfmt, ARRAYLENGTH(wfmt));
            StringCbPrintf(wlong, sizeof(wlong), wfmt, t);

            khui_cfg_register(cfg_ids,
                              &reg);
        } else {
            khui_cfg_release(cfg_id);
        }
    }

 _cleanup:
    if (cfg_ids)
        khui_cfg_release(cfg_ids);

    if (idents)
        free(idents);
}

void khm_init_config(void) {
    wchar_t wshort[KHUI_MAXCCH_SHORT_DESC];
    wchar_t wlong[KHUI_MAXCCH_LONG_DESC];
    khui_config_node_reg reg;
    khui_config_node node;

    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = khm_hInstance;
    reg.flags = 0;

    reg.name = L"KhmGeneral";
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_GENERAL);
    reg.dlg_proc = khm_cfg_general_proc;
    LoadString(khm_hInstance, IDS_CFG_GENERAL_SHORT,
               wshort, ARRAYLENGTH(wshort));
    LoadString(khm_hInstance, IDS_CFG_GENERAL_LONG,
               wlong, ARRAYLENGTH(wlong));

    khui_cfg_register(NULL, &reg);

    reg.name = L"KhmIdentities";
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_IDENTITIES);
    reg.dlg_proc = khm_cfg_identities_proc;
    LoadString(khm_hInstance, IDS_CFG_IDENTITIES_SHORT,
               wshort, ARRAYLENGTH(wshort));
    LoadString(khm_hInstance, IDS_CFG_IDENTITIES_LONG,
               wlong, ARRAYLENGTH(wlong));

    khui_cfg_register(NULL, &reg);

    node = NULL;
    khui_cfg_open(NULL, L"KhmIdentities", &node);
#ifdef DEBUG
    assert(node);
#endif

    reg.name = L"KhmIdentitiesTab";
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_IDS_TAB);
    reg.dlg_proc = khm_cfg_ids_tab_proc;
    LoadString(khm_hInstance, IDS_CFG_IDS_TAB_SHORT,
               wshort, ARRAYLENGTH(wshort));
    LoadString(khm_hInstance, IDS_CFG_IDS_TAB_LONG,
               wlong, ARRAYLENGTH(wlong));
    reg.flags = KHUI_CNFLAG_SUBPANEL;

    khui_cfg_register(node, &reg);

    reg.name = L"KhmIdentitiesTabPlural";
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_ID_TAB);
    reg.dlg_proc = khm_cfg_id_tab_proc;
    LoadString(khm_hInstance, IDS_CFG_ID_TAB_SHORT,
               wshort, ARRAYLENGTH(wshort));
    LoadString(khm_hInstance, IDS_CFG_ID_TAB_LONG,
               wlong, ARRAYLENGTH(wlong));
    reg.flags = KHUI_CNFLAG_PLURAL | KHUI_CNFLAG_SUBPANEL;

    khui_cfg_register(node, &reg);

    reg.flags = 0;
    khui_cfg_release(node);

    reg.name = L"KhmNotifications";
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_NOTIF);
    reg.dlg_proc = khm_cfg_notifications_proc;
    LoadString(khm_hInstance, IDS_CFG_NOTIF_SHORT,
               wshort, ARRAYLENGTH(wshort));
    LoadString(khm_hInstance, IDS_CFG_NOTIF_LONG,
               wlong, ARRAYLENGTH(wlong));

    khui_cfg_register(NULL, &reg);

    reg.name = L"KhmPlugins";
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_PLUGINS);
    reg.dlg_proc = khm_cfg_plugins_proc;
    LoadString(khm_hInstance, IDS_CFG_PLUGINS_SHORT,
               wshort, ARRAYLENGTH(wshort));
    LoadString(khm_hInstance, IDS_CFG_PLUGINS_LONG,
               wlong, ARRAYLENGTH(wlong));

    khui_cfg_register(NULL, &reg);
}

void khm_exit_config(void) {
}
