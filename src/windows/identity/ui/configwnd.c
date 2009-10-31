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
    if (d == NULL)
        return;

    /* create and fill the image list for the treeview */

    d->hi_status = ImageList_Create(GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                    ILC_COLOR8 | ILC_MASK,
                                    4,4);

    hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_DEFAULT),
                      IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

    /* note that we can't use index 0 because that is used to indicate
       that there is no state image for the node */
    do {
        d->idx_default = ImageList_AddIcon(d->hi_status, hicon);
    } while(d->idx_default == 0);

    DestroyIcon(hicon);

    hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_MODIFIED),
                      IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

    d->idx_modified = ImageList_AddIcon(d->hi_status, hicon);

    DestroyIcon(hicon);

    hicon = LoadImage(khm_hInstance, MAKEINTRESOURCE(IDI_CFG_APPLIED),
                      IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

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
    if (d == NULL)
        return;

    hwtv = GetDlgItem(hwnd, IDC_CFG_NODELIST);

    cfgui_free_node(hwtv, TreeView_GetRoot(hwtv));

    if (d->hf_title)
        DeleteObject(d->hf_title);

    if (d->hi_status)
        ImageList_Destroy(d->hi_status);
}

static HWND
cfgui_create_config_node_window(HWND hwnd, khui_config_node node) {
    khui_config_node_reg reg;
    khm_int32 rv;
    HWND hw_new;

    khui_config_node parent;

    if (KHM_SUCCEEDED(khui_cfg_get_parent(node, &parent))) {
        HWND hwp;

        hwp = khui_cfg_get_hwnd(parent);

        if (hwp == NULL)
            cfgui_create_config_node_window(hwnd, parent);

        khui_cfg_release(parent);
    }

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

    return hw_new;
}

static void
cfgui_activate_node(HWND hwnd, khui_config_node node) {

    cfgui_wnd_data * d;
    HTREEITEM hItem;
    HWND hw_new;
    HWND hwtv;

    d = cfgui_get_wnd_data(hwnd);
    if (d == NULL)
        return;

    hwtv = GetDlgItem(hwnd, IDC_CFG_NODELIST);
    hItem = (HTREEITEM) khui_cfg_get_param(node);

#ifdef DEBUG
    assert(hItem);
    assert(hwtv);
#endif

    if (node == NULL) {
        hw_new = d->hw_generic_pane;
    } else {

        hw_new = khui_cfg_get_hwnd(node);

        if (hw_new == NULL) {
            hw_new = cfgui_create_config_node_window(hwnd, node);
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
    khm_int32 flags;

    hwnd = khui_cfg_get_hwnd(node);
    flags = khui_cfg_get_flags(node);

    if (hwnd && (flags & KHUI_CNFLAG_MODIFIED)) {
        SendMessage(hwnd, KHUI_WM_CFG_NOTIFY,
                    MAKEWPARAM(0, WMCFG_APPLY),
                    (LPARAM) node);
    }

    if (KHM_FAILED(khui_cfg_get_first_child(node, &c)))
        return;

    while (c) {
        cfgui_apply_settings(c);
        khui_cfg_get_next_release(&c);
    }
}

static void
cfgui_remove_item(HWND hwtv,
                  HTREEITEM hItem) {
    khui_config_node node;
    HTREEITEM hChild;
    TVITEMEX itemex;

    for (hChild = TreeView_GetChild(hwtv, hItem);
         hChild;
         hChild = TreeView_GetChild(hwtv, hItem)) {

        cfgui_remove_item(hwtv, hChild);

    }

    ZeroMemory(&itemex, sizeof(itemex));

    itemex.mask = TVIF_PARAM;
    itemex.hItem = hItem;

    TreeView_GetChild(hwtv, &itemex);

    node = (khui_config_node) itemex.lParam;

    if (node) {
        HWND hw;
        hw = khui_cfg_get_hwnd(node);

        if (hw)
            DestroyWindow(hw);

        khui_cfg_release(node);
    }

    TreeView_DeleteItem(hwtv, hItem);
}

struct cfgui_child_info {
    HTREEITEM hItem;
    khui_config_node node;
    BOOL checked;
};

#define CI_ALLOC_INCR 8

static void
cfgui_sync_node(cfgui_wnd_data * d,
                HWND hwtv,
                khui_config_node c,
                HTREEITEM hItem) {
    khui_config_node child;
    HTREEITEM hChild;
    struct cfgui_child_info * childinfo = NULL;
    khm_size n_childinfo = 0;
    khm_size nc_childinfo = 0;
    khm_size i;

    /* first, get the list of children from the treeview control */
    for (hChild = TreeView_GetChild(hwtv, hItem);
         hChild;
         hChild = TreeView_GetNextSibling(hwtv, hChild)) {

        if (n_childinfo >= nc_childinfo) {
            nc_childinfo = UBOUNDSS(n_childinfo + 1,
                                    CI_ALLOC_INCR, CI_ALLOC_INCR);
#ifdef DEBUG
            assert(nc_childinfo > n_childinfo);
#endif
            childinfo = PREALLOC(childinfo,
                                 sizeof(*childinfo) * nc_childinfo);
#ifdef DEBUG
            assert(childinfo);
#endif
        }

        ZeroMemory(&childinfo[n_childinfo],
                   sizeof(childinfo[n_childinfo]));

        childinfo[n_childinfo].hItem = hChild;
        childinfo[n_childinfo].checked = FALSE;
        n_childinfo++;
    }

    /* now, go through the list of actual nodes and make sure they
       match up */
    child = NULL;
    for (khui_cfg_get_first_child(c, &child);
         child;
         khui_cfg_get_next_release(&child)) {

        hChild = (HTREEITEM) khui_cfg_get_param(child);

        for (i=0; i < n_childinfo; i++) {
            if (childinfo[i].hItem == hChild)
                break;
        }

        if (i < n_childinfo) {
            childinfo[i].checked = TRUE;
        } else {
            /* add it to the list, so we can create the node in the
               tree view control later. */
            if (n_childinfo >= nc_childinfo) {
                nc_childinfo = UBOUNDSS(n_childinfo + 1,
                                        CI_ALLOC_INCR, CI_ALLOC_INCR);
#ifdef DEBUG
                assert(nc_childinfo > n_childinfo);
#endif
                childinfo = PREALLOC(childinfo,
                                     sizeof(*childinfo) * nc_childinfo);
#ifdef DEBUG
                assert(childinfo);
#endif
            }

            ZeroMemory(&childinfo[n_childinfo],
                       sizeof(childinfo[n_childinfo]));

            childinfo[n_childinfo].node = child;
            khui_cfg_hold(child);
            n_childinfo++;
        }
    }

    /* by this point, the childinfo list contains items of the
       following forms:

       1. childinfo[i].hItem != NULL && childinfo[i].checked == TRUE

          Corresponds to a tree view item that has a matching
          configuration node.  Nothing to do here.

       2. childinfo[i].hItem != NULL && childinfo[i].checked == FALSE

          Corresponds to a tree view item that has no matching
          configuration node.  These should be removed.

       3. childinfo[i].hItem == NULL && childinfo[i].node != NULL

          Corresponds to a configuration node that has no matching
          tree view item.  These nodes should be added.
    */

    /* first do the removals */
    for (i=0; i < n_childinfo; i++) {
        if (childinfo[i].hItem == NULL)
            break;              /* nothing more to see from this point
                                   on */
        if (!childinfo[i].checked) {
            /* remove! */
            cfgui_remove_item(hwtv, childinfo[i].hItem);
        }
    }

    /* continue from where the previous loop left off */
    for (; i < n_childinfo; i++) {
#ifdef DEBUG
        assert(childinfo[i].hItem == NULL);
        assert(childinfo[i].node != NULL);
#endif

        cfgui_add_node(d, hwtv, childinfo[i].node, c, FALSE);

        khui_cfg_release(childinfo[i].node);
        childinfo[i].node = NULL;
    }

    if (childinfo)
        PFREE(childinfo);

    /* finally recurse through to the next level */
    for (hChild = TreeView_GetChild(hwtv, hItem);
         hChild;
         hChild = TreeView_GetNextSibling(hwtv, hChild)) {

        TVITEMEX itemex;

        ZeroMemory(&itemex, sizeof(itemex));

        itemex.mask = TVIF_PARAM;
        itemex.hItem = hChild;

        TreeView_GetItem(hwtv, &itemex);

        if (itemex.lParam) {
            child = (khui_config_node) itemex.lParam;

            cfgui_sync_node(d, hwtv, child, hChild);
        }
    }
}

static void
cfgui_sync_node_list(cfgui_wnd_data * d, HWND hwnd) {
    HWND hwtv;
    HTREEITEM hItem;

    hwtv = GetDlgItem(hwnd, IDC_CFG_NODELIST);
    hItem = TreeView_GetRoot(hwtv);

    cfgui_sync_node(d, hwtv, NULL, hItem);
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
    if (d == NULL)
        return;

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
        EnableWindow(GetDlgItem(hwnd, IDAPPLY), TRUE);
    } else {
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
        if (d == NULL)
            break;

        return (BOOL)(DWORD_PTR) d->hbr_white;

    case WM_ERASEBKGND:
        {
            HDC hdc = (HDC) wParam;
            RECT r_client;
            RECT r_logo;
            RECT r_fill;

            d = cfgui_get_wnd_data(hwnd);
            if (d == NULL)
                break;

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

            SetWindowLongPtr(hwnd, DWLP_MSGRESULT, (LONG) TRUE);
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

        khui_cfg_set_configui_handle(hwnd);

        d = PMALLOC(sizeof(*d));
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

        return TRUE;

    case WM_DESTROY:
        cfgui_hwnd = NULL;

        khui_cfg_set_configui_handle(NULL);

        cfgui_uninitialize_dialog(hwnd);

        d = cfgui_get_wnd_data(hwnd);
        if (d == NULL)
            break;

        khui_delete_bitmap(&d->kbmp_logo);
        DeleteObject(d->hbr_white);

        cfgui_set_wnd_data(hwnd, NULL);

        khm_del_dialog(hwnd);

        SetForegroundWindow(khm_hwnd_main);

        PFREE(d);

        return FALSE;

    case WM_NOTIFY:
        {
            LPNMHDR lpnm;
            LPNMTREEVIEW lptv;
            LPNMTVGETINFOTIP lpgi;
            khui_config_node node;

            lpnm = (LPNMHDR) lParam;

            switch (lpnm->code) {
            case TVN_SELCHANGED:
                lptv = (LPNMTREEVIEW) lParam;
                cfgui_activate_node(hwnd,
                                    (khui_config_node)
                                    lptv->itemNew.lParam);
                return TRUE;

            case TVN_GETINFOTIP:
                lpgi = (LPNMTVGETINFOTIP) lParam;
                node = (khui_config_node) lpgi->lParam;

                if (node) {
                    khm_int32 flags = 0;

                    flags = khui_cfg_get_flags(node);

                    if (flags & KHUI_CNFLAG_MODIFIED) {
                        LoadString(khm_hInstance, IDS_CFG_IT_MOD,
                                   lpgi->pszText, lpgi->cchTextMax);
                    } else if (flags & KHUI_CNFLAG_APPLIED) {
                        LoadString(khm_hInstance, IDS_CFG_IT_APP,
                                   lpgi->pszText, lpgi->cchTextMax);
                    } else {
                        LoadString(khm_hInstance, IDS_CFG_IT_NONE,
                                   lpgi->pszText, lpgi->cchTextMax);
                    }
                } else {
                    StringCchCopy(lpgi->pszText, lpgi->cchTextMax, L"");
                }

                return TRUE;
            }
        }
        return TRUE;

    case WM_CTLCOLORSTATIC:
        {
            d = cfgui_get_wnd_data(hwnd);
            if (d == NULL)
                break;

            return (BOOL)(DWORD_PTR) d->hbr_white;
        }
        /* implicit break */

    case WM_COMMAND:
        switch(wParam) {
        case MAKEWPARAM(IDCANCEL, BN_CLICKED):
            khm_leave_modal();
            DestroyWindow(hwnd);
            break;

        case MAKEWPARAM(IDAPPLY, BN_CLICKED):
            cfgui_apply_settings(NULL);
            break;

        case MAKEWPARAM(IDOK, BN_CLICKED):
            cfgui_apply_settings(NULL);
            khm_leave_modal();
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

        case WMCFG_SYNC_NODE_LIST:
            d = cfgui_get_wnd_data(hwnd);
            if (d == NULL)
                break;

            cfgui_sync_node_list(d, hwnd);
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
    khui_config_node cfg_r = NULL;
    khui_config_node cfg_iter = NULL;
    khui_menu_def * omenu;
    khm_boolean refresh_menu = FALSE;

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
            PFREE(idents);
        idents = PMALLOC(cb);
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

    for (khui_cfg_get_first_child(cfg_ids, &cfg_iter);
         cfg_iter;
         khui_cfg_get_next_release(&cfg_iter)) {

        wchar_t cfgname[KCDB_IDENT_MAXCCH_NAME];
        khm_size cb;
        khm_handle tident = NULL;
        khm_int32 tflags = 0;

        cb = sizeof(cfgname);
        khui_cfg_get_name(cfg_iter, cfgname, &cb);

        if (KHM_FAILED(kcdb_identity_create(cfgname, 0, &tident)) ||
            KHM_FAILED(kcdb_identity_get_flags(tident, &tflags)) ||
            !(tflags & KCDB_IDENT_FLAG_ACTIVE) ||
            !(tflags & KCDB_IDENT_FLAG_CONFIG)) {

            /* this configuration node needs to be removed */

            khui_cfg_remove(cfg_iter);
        }

        if (tident)
            kcdb_identity_release(tident);
    }

    /* Now iterate through the root level configuration nodes and make
       sure we have a menu item for each of them. */
    if (KHM_FAILED(khui_cfg_get_first_child(NULL, &cfg_r)))
        goto _cleanup;

    omenu = khui_find_menu(KHUI_MENU_OPTIONS);
    if (omenu == NULL)
        goto _cleanup;

    khui_action_lock();

    do {
        khm_int32 action;
        khm_int32 flags;
        khui_action * paction;
        wchar_t cname[KHUI_MAXCCH_NAME];
        wchar_t wshort[KHUI_MAXCCH_SHORT_DESC];
        khm_size cb;
        khm_handle sub;
        khui_config_node_reg reg;

        flags = khui_cfg_get_flags(cfg_r);
        if (flags & KHUI_CNFLAG_SYSTEM)
            goto _next_cfg;

        cb = sizeof(cname);
        if (KHM_FAILED(khui_cfg_get_name(cfg_r, cname, &cb))) {
#ifdef DEBUG
            assert(FALSE);
#endif
            goto _next_cfg;
        }

        paction = khui_find_named_action(cname);

        if (!paction) {
            khui_cfg_get_reg(cfg_r, &reg);

            kmq_create_hwnd_subscription(khm_hwnd_main, &sub);

            StringCbCopy(wshort, sizeof(wshort), reg.short_desc);
            StringCbCat(wshort, sizeof(wshort), L" ...");

            action = khui_action_create(cname,
                                        wshort,
                                        reg.long_desc,
                                        (void *) CFGACTION_MAGIC,
                                        KHUI_ACTIONTYPE_TRIGGER,
                                        sub);

            if (action == 0) {
#ifdef DEBUG
                assert(FALSE);
#endif
                goto _next_cfg;
            }

            khui_menu_insert_action(omenu, (khm_size) -1, action, 0);

            refresh_menu = TRUE;
        }

    _next_cfg:
        if (KHM_FAILED(khui_cfg_get_next_release(&cfg_r)))
            break;
    } while(cfg_r);

    khui_action_unlock();

    if (refresh_menu) {
        khui_refresh_actions();
    }

 _cleanup:
    if (cfg_ids)
        khui_cfg_release(cfg_ids);

    if (cfg_r)
        khui_cfg_release(cfg_r);

    if (idents)
        PFREE(idents);
}

void khm_init_config(void) {
    wchar_t wshort[KHUI_MAXCCH_SHORT_DESC];
    wchar_t wlong[KHUI_MAXCCH_LONG_DESC];
    khui_config_node_reg reg;
    khui_config_node node;

    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = khm_hInstance;
    reg.flags = KHUI_CNFLAG_SYSTEM;

    reg.name = L"KhmGeneral";
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_GENERAL);
    reg.dlg_proc = khm_cfg_general_proc;
    LoadString(khm_hInstance, IDS_CFG_GENERAL_SHORT,
               wshort, ARRAYLENGTH(wshort));
    LoadString(khm_hInstance, IDS_CFG_GENERAL_LONG,
               wlong, ARRAYLENGTH(wlong));

    khui_cfg_register(NULL, &reg);

    reg.name = L"KhmAppear";
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_APPEAR);
    reg.dlg_proc = khm_cfg_appearance_proc;
    LoadString(khm_hInstance, IDS_CFG_APPEAR_SHORT,
               wshort, ARRAYLENGTH(wshort));
    LoadString(khm_hInstance, IDS_CFG_APPEAR_LONG,
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
    reg.flags = KHUI_CNFLAG_SUBPANEL | KHUI_CNFLAG_SYSTEM;

    khui_cfg_register(node, &reg);

    reg.name = L"KhmIdentitiesTabPlural";
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_ID_TAB);
    reg.dlg_proc = khm_cfg_id_tab_proc;
    LoadString(khm_hInstance, IDS_CFG_ID_TAB_SHORT,
               wshort, ARRAYLENGTH(wshort));
    LoadString(khm_hInstance, IDS_CFG_ID_TAB_LONG,
               wlong, ARRAYLENGTH(wlong));
    reg.flags = KHUI_CNFLAG_PLURAL | KHUI_CNFLAG_SUBPANEL | KHUI_CNFLAG_SYSTEM;

    khui_cfg_register(node, &reg);

    reg.flags = KHUI_CNFLAG_SYSTEM;
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
