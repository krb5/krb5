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

ATOM khui_newcredwnd_cls;

/* forward dcl */
static void
nc_position_credtext(khui_nc_wnd_data * d);

/* Common dialog procedure.  Be careful.  This is used by more than
   one dialog. */
static INT_PTR CALLBACK 
nc_common_dlg_proc(HWND hwnd,
                   UINT uMsg,
                   WPARAM wParam,
                   LPARAM lParam)
{
    switch(uMsg) {
    case WM_INITDIALOG:
        {
            khui_nc_wnd_data * d;

            d = (khui_nc_wnd_data *) lParam;

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, lParam);
#pragma warning(pop)
            if (d->nc->subtype == KMSG_CRED_PASSWORD) {
                ShowWindow(GetDlgItem(hwnd, IDC_NC_OPTIONS),
                           SW_HIDE);
            }
        }
        return TRUE;

    case WM_COMMAND:
        {
            int ctrl_id;

            ctrl_id = LOWORD(wParam);
            if (ctrl_id < KHUI_CW_ID_MIN ||
                ctrl_id > KHUI_CW_ID_MAX) {
                /* pump it to the parent */
                PostMessage(GetParent(hwnd), WM_COMMAND, wParam, lParam);
                return TRUE;
            } /* else we allow the message to fall through and get
                 passed into the identity provider's message
                 handler. */
        }
        break;

#if 0
        /* someday this will be used to draw custom tab buttons.  But
           that's not today */
    case WM_DRAWITEM:
        {
            khui_nc_wnd_data * d;
            int id;
            LPDRAWITEMSTRUCT ds;

            d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, DWLP_USER);
            id = wParam;
            ds = (LPDRAWITEMSTRUCT) lParam;

            if(id >= NC_TS_CTRL_ID_MIN && id <= NC_TS_CTRL_ID_MAX) {
                /*TODO: custom draw the buttons */
            }
            else
                return FALSE;
        }
        break;
#endif

    case KHUI_WM_NC_NOTIFY:
        {
            khui_nc_wnd_data * d;
            d = (khui_nc_wnd_data *)(LONG_PTR) 
                GetWindowLongPtr(hwnd, DWLP_USER);

            /* message sent by parent to notify us of something */
            switch(HIWORD(wParam)) {
            case WMNC_DIALOG_EXPAND:
                if(hwnd == d->dlg_main) {
                    HWND hw;
                        
                    if(hw = GetDlgItem(hwnd, IDOK))
                        ShowWindow(hw, SW_HIDE);
                    if(hw = GetDlgItem(hwnd, IDCANCEL))
                        ShowWindow(hw, SW_HIDE);
                    if(hw = GetDlgItem(hwnd, IDC_NC_OPTIONS))
                        ShowWindow(hw, SW_HIDE);

                    d->r_credtext.bottom = d->r_area.bottom;

                    nc_position_credtext(d);

                    return TRUE;
                }
            }
        }
        return TRUE;
    }

    /* check if we have a wnd_data, and if so pass the message on to
       the identity provider callback. */
    {
        khui_nc_wnd_data * d;

        d = (khui_nc_wnd_data *) (LONG_PTR)
            GetWindowLongPtr(hwnd, DWLP_USER);

        if (d && d->nc && d->nc->ident_cb) {
            return d->nc->ident_cb(d->nc, WMNC_IDENT_WMSG, hwnd, uMsg, 
                                   wParam, lParam);
        }
    }

    return FALSE;
}

static void
nc_position_credtext(khui_nc_wnd_data * d)
{
    HWND hw;

    hw = GetDlgItem(d->dlg_main, IDC_NC_CREDTEXT);
#ifdef DEBUG
    assert(hw);
#endif

    if (d->r_credtext.bottom < d->r_credtext.top + d->r_row.bottom * 2) {
        /* not enough room */
        if (d->nc->mode == KHUI_NC_MODE_MINI &&
            d->nc->subtype != KMSG_CRED_PASSWORD) {
            PostMessage(d->nc->hwnd, KHUI_WM_NC_NOTIFY,
                        MAKEWPARAM(0, WMNC_DIALOG_EXPAND), 0);
            return;
        } else {
            ShowWindow(hw, SW_HIDE);
            return;
        }
    } else {
        ShowWindow(hw, SW_SHOW);
    }

    SetWindowPos(hw, NULL,
                 d->r_credtext.left + d->r_n_input.left, /* x */
                 d->r_credtext.top, /* y */
                 d->r_n_input.right - d->r_n_input.left, /* width */
                 d->r_credtext.bottom - d->r_credtext.top, /* height */
                 SWP_NOACTIVATE | SWP_NOOWNERZORDER | 
                 SWP_NOZORDER);

    hw = GetDlgItem(d->dlg_main, IDC_NC_CREDTEXT_LABEL);

    SetWindowPos(hw, NULL,
                 d->r_credtext.left + d->r_n_label.left, /* x */
                 d->r_credtext.top, /* y */
                 d->r_n_label.right - d->r_n_label.left, /* width */
                 d->r_n_label.bottom - d->r_n_label.top, /* height */
                 SWP_NOACTIVATE | SWP_NOOWNERZORDER |
                 SWP_NOZORDER);
}

/* sorts tab buttons */
static int __cdecl 
nc_tab_sort_func(const void * v1, const void * v2)
{
    /* v1 and v2 and of type : khui_new_creds_by_type ** */
    khui_new_creds_by_type *t1, *t2;

    t1 = *((khui_new_creds_by_type **) v1);
    t2 = *((khui_new_creds_by_type **) v2);

    if(t1->ordinal > 0) {
        if(t2->ordinal > 0) {
            if(t1->ordinal == t2->ordinal)
                return wcscmp(t1->name, t2->name);
            else
                /* safe to convert to an int here */
                return (int) (t1->ordinal - t2->ordinal);
        } else
            return -1;
    } else {
        if(t2->ordinal > 0)
            return 1;
        else if (t1->name && t2->name)
            return wcscmp(t1->name, t2->name);
        else
            return 0;
    }
}

static void 
nc_notify_types_async(khui_new_creds * c, UINT uMsg,
                      WPARAM wParam, LPARAM lParam)
{
    khm_size i;

    for(i=0; i<c->n_types; i++) {
        PostMessage(c->types[i]->hwnd_panel, uMsg, wParam, lParam);
    }
}

static void 
nc_notify_types(khui_new_creds * c, UINT uMsg,
                WPARAM wParam, LPARAM lParam)
{
    khm_size i;

    for(i=0; i<c->n_types; i++) {
        SendMessage(c->types[i]->hwnd_panel, uMsg, wParam, lParam);
    }
}

#define NC_MAXCCH_CREDTEXT 16384
#define NC_MAXCB_CREDTEXT (NC_MAXCCH_CREDTEXT * sizeof(wchar_t))

static void 
nc_update_credtext(khui_nc_wnd_data * d) 
{
    wchar_t * ctbuf = NULL;
    wchar_t * buf;
    BOOL okEnable = FALSE;
    BOOL validId = FALSE;
    HWND hw = NULL;
    size_t cch = 0;

    ctbuf = PMALLOC(NC_MAXCB_CREDTEXT);

    assert(ctbuf != NULL);

    LoadString(khm_hInstance, IDS_NC_CREDTEXT_TABS, ctbuf, NC_MAXCCH_CREDTEXT);
    StringCchLength(ctbuf, NC_MAXCCH_CREDTEXT, &cch);
    buf = ctbuf + cch;
    nc_notify_types(d->nc, KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0, WMNC_UPDATE_CREDTEXT), 0);

    /* hopefully all the types have updated their credential texts */
    if(d->nc->n_identities == 1) {
        wchar_t main_fmt[256];
        wchar_t id_fmt[256];
        wchar_t id_name[KCDB_IDENT_MAXCCH_NAME];
        wchar_t id_string[KCDB_IDENT_MAXCCH_NAME + 256];
        khm_size cbbuf;
        khm_int32 flags;


        LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_ONE, 
                   main_fmt, (int) ARRAYLENGTH(main_fmt));

        cbbuf = sizeof(id_name);
        kcdb_identity_get_name(d->nc->identities[0], id_name, &cbbuf);

        kcdb_identity_get_flags(d->nc->identities[0], &flags);

        if (flags & KCDB_IDENT_FLAG_INVALID) {
            LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_INVALID, 
                       id_fmt, (int) ARRAYLENGTH(id_fmt));
        } else if(flags & KCDB_IDENT_FLAG_VALID) {
            LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_VALID, 
                       id_fmt, (int) ARRAYLENGTH(id_fmt));
        } else if(d->nc->subtype == KMSG_CRED_NEW_CREDS) {
            LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_CHECKING, 
                       id_fmt, (int) ARRAYLENGTH(id_fmt));
        } else {
            LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_UNCHECKED, 
                       id_fmt, (int) ARRAYLENGTH(id_fmt));
        }

        StringCbPrintf(id_string, sizeof(id_string), id_fmt, id_name);

        StringCbPrintf(buf, NC_MAXCB_CREDTEXT - cch*sizeof(wchar_t), 
                       main_fmt, id_string);

        if (flags & KCDB_IDENT_FLAG_VALID) {
            if (flags & KCDB_IDENT_FLAG_DEFAULT)
                LoadString(khm_hInstance, IDS_NC_ID_DEF,
                           id_string, ARRAYLENGTH(id_string));
            else if (d->nc->set_default)
                LoadString(khm_hInstance, IDS_NC_ID_WDEF,
                           id_string, ARRAYLENGTH(id_string));
            else
                LoadString(khm_hInstance, IDS_NC_ID_NDEF,
                           id_string, ARRAYLENGTH(id_string));

            StringCbCat(buf, NC_MAXCB_CREDTEXT - cch * sizeof(wchar_t),
                        id_string);
        }

    } else if(d->nc->n_identities > 1) {
        wchar_t *ids_string;
        khm_size cb_ids_string;

        wchar_t id_name[KCDB_IDENT_MAXCCH_NAME];
        wchar_t id_fmt[256];
        wchar_t id_string[KCDB_IDENT_MAXCCH_NAME + 256];

        wchar_t main_fmt[256];
        khm_size cbbuf;

        LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_MANY, 
                   main_fmt, (int) ARRAYLENGTH(main_fmt));

        /* we are going to concatenate all the identity names into
           a comma separated string */

        /* d->nc->n_identities is at least 2 */
        ids_string = PMALLOC((KCDB_IDENT_MAXCB_NAME + sizeof(id_fmt)) * 
                            (d->nc->n_identities - 1));
        cb_ids_string = 
            (KCDB_IDENT_MAXCB_NAME + sizeof(id_fmt)) * 
            (d->nc->n_identities - 1);

        assert(ids_string != NULL);

        ids_string[0] = 0;

        {
            khm_size i;
            khm_int32 flags;

            for(i=1; i<d->nc->n_identities; i++) {
                if(i>1) {
                    StringCbCat(ids_string, cb_ids_string, L",");
                }

                flags = 0;

                cbbuf = sizeof(id_name);
                kcdb_identity_get_name(d->nc->identities[i], id_name, &cbbuf);
                kcdb_identity_get_flags(d->nc->identities[i], &flags);
                if(flags & KCDB_IDENT_FLAG_INVALID) {
                    LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_INVALID, 
                               id_fmt, (int) ARRAYLENGTH(id_fmt));
                } else if(flags & KCDB_IDENT_FLAG_VALID) {
                    LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_VALID, 
                               id_fmt, (int) ARRAYLENGTH(id_fmt));
                } else {
                    LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_UNCHECKED, 
                               id_fmt, (int) ARRAYLENGTH(id_fmt));
                }

                StringCbPrintf(id_string, sizeof(id_string), id_fmt, id_name);
                StringCbCat(ids_string, cb_ids_string, id_string);
            }

            cbbuf = sizeof(id_name);
            kcdb_identity_get_name(d->nc->identities[0], id_name, &cbbuf);
            kcdb_identity_get_flags(d->nc->identities[0], &flags);
            if(flags & KCDB_IDENT_FLAG_INVALID) {
                LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_INVALID, 
                           id_fmt, (int) ARRAYLENGTH(id_fmt));
            } else if(flags & KCDB_IDENT_FLAG_VALID) {
                LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_VALID, 
                           id_fmt, (int) ARRAYLENGTH(id_fmt));
            } else {
                LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_UNCHECKED, 
                           id_fmt, (int) ARRAYLENGTH(id_fmt));
            }
            StringCbPrintf(id_string, sizeof(id_string), id_fmt, id_name);

            StringCbPrintf(buf, NC_MAXCB_CREDTEXT - cch*sizeof(wchar_t), 
                           main_fmt, id_string, ids_string);

            PFREE(ids_string);
        }
    } else {
        LoadString(khm_hInstance, IDS_NC_CREDTEXT_ID_NONE, 
                   buf, (int)(NC_MAXCCH_CREDTEXT - cch));
    }

    /* now, append the credtext string from each of the cred types */
    {
        khm_size i;
        size_t cb;
        wchar_t * buf;

        cb = NC_MAXCB_CREDTEXT;
        buf = ctbuf;

        for(i=0; i<d->nc->n_types; i++) {
            if(d->nc->types[i]->credtext != NULL) {
                StringCbCatEx(buf, cb, 
                              d->nc->types[i]->credtext,
                              &buf, &cb,
                              0);
            }
        }
    }

    SetDlgItemText(d->dlg_main, IDC_NC_CREDTEXT, ctbuf);

    PFREE(ctbuf);

    /* so depending on whether the primary identity was found to be
       invalid, we need to disable the Ok button and set the title to
       reflect this */

    if(d->nc->n_identities > 0) {
        khm_int32 flags = 0;

        if(KHM_SUCCEEDED(kcdb_identity_get_flags(d->nc->identities[0], 
                                               &flags)) &&
           (flags & KCDB_IDENT_FLAG_VALID)) {
            validId = TRUE;
        }
    }

    if (d->nc->window_title == NULL) {
        if(validId) {
            wchar_t wpostfix[256];
            wchar_t wtitle[KCDB_IDENT_MAXCCH_NAME + 256];
            khm_size cbsize;

            cbsize = sizeof(wtitle);
            kcdb_identity_get_name(d->nc->identities[0], wtitle, &cbsize);

            if (d->nc->subtype == KMSG_CRED_PASSWORD)
                LoadString(khm_hInstance, IDS_WTPOST_PASSWORD,
                           wpostfix, (int) ARRAYLENGTH(wpostfix));
            else
                LoadString(khm_hInstance, IDS_WTPOST_NEW_CREDS, 
                           wpostfix, (int) ARRAYLENGTH(wpostfix));

            StringCbCat(wtitle, sizeof(wtitle), wpostfix);

            SetWindowText(d->nc->hwnd, wtitle);
        } else {
            wchar_t wtitle[256];

            if (d->nc->subtype == KMSG_CRED_PASSWORD)
                LoadString(khm_hInstance, IDS_WT_PASSWORD,
                           wtitle, (int) ARRAYLENGTH(wtitle));
            else
                LoadString(khm_hInstance, IDS_WT_NEW_CREDS, 
                           wtitle, (int) ARRAYLENGTH(wtitle));

            SetWindowText(d->nc->hwnd, wtitle);
        }
    }

    if(validId || d->nc->subtype == KMSG_CRED_PASSWORD) {
        /* TODO: check if all the required fields have valid values
           before enabling the Ok button */
        okEnable = TRUE;
    }

    hw = GetDlgItem(d->dlg_main, IDOK);
    EnableWindow(hw, okEnable);
    hw = GetDlgItem(d->dlg_bb, IDOK);
    EnableWindow(hw, okEnable);
}

#define CW_PARAM DWLP_USER

static void
nc_add_control_row(khui_nc_wnd_data * d, 
                   HWND label,
                   HWND input,
                   khui_control_size size);

static LRESULT 
nc_handle_wm_create(HWND hwnd,
                    UINT uMsg,
                    WPARAM wParam,
                    LPARAM lParam)
{
    LPCREATESTRUCT lpc;
    khui_new_creds * c;
    khui_nc_wnd_data * ncd;
    int x, y;
    int width, height;
    RECT r;

    lpc = (LPCREATESTRUCT) lParam;

    ncd = PMALLOC(sizeof(*ncd));
    ZeroMemory(ncd, sizeof(*ncd));

    c = (khui_new_creds *) lpc->lpCreateParams;
    ncd->nc = c;
    c->hwnd = hwnd;

#pragma warning(push)
#pragma warning(disable: 4244)
    SetWindowLongPtr(hwnd, CW_PARAM, (LONG_PTR) ncd);
#pragma warning(pop)

    /* first try to create the main dialog panel */
    
    assert(c->subtype == KMSG_CRED_NEW_CREDS ||
           c->subtype == KMSG_CRED_PASSWORD);

    ncd->dlg_main = CreateDialogParam(khm_hInstance,
                                      MAKEINTRESOURCE(IDD_NC_PASSWORD),
                                      hwnd,
                                      nc_common_dlg_proc,
                                      (LPARAM) ncd);
#ifdef DEBUG
    assert(ncd->dlg_main);
#endif

    {
        RECT r_main;
        RECT r_area;
        RECT r_row;
        HWND hw;
            
        /* pick out metrics for use by the custom prompter stuff */
        GetWindowRect(ncd->dlg_main, &r_main);

        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_PANEL);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r_area);
        OffsetRect(&r_area,-r_main.left, -r_main.top);
        CopyRect(&ncd->r_area, &r_area);

        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_ROW);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        CopyRect(&r_row, &r);
        OffsetRect(&r,-r.left, -r.top);
        CopyRect(&ncd->r_row, &r);

        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_LABEL);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r,-r_row.left, -r_row.top);
        CopyRect(&ncd->r_n_label, &r);

        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_INPUT);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r, -r_row.left, -r_row.top);
        CopyRect(&ncd->r_n_input, &r);

        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_ROW_LG);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r_row);

        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_LABEL_LG);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r, -r_row.left, -r_row.top);
        CopyRect(&ncd->r_e_label, &r);

        hw = GetDlgItem(ncd->dlg_main, IDC_NC_TPL_INPUT_LG);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r, -r_row.left, -r_row.top);
        CopyRect(&ncd->r_e_input, &r);

        CopyRect(&ncd->r_credtext, &ncd->r_area);
        CopyRect(&ncd->r_idspec, &ncd->r_area);

        ncd->r_idspec.bottom = ncd->r_idspec.top;

        hw = GetDlgItem(ncd->dlg_main, IDC_NC_CREDTEXT);
#ifdef DEBUG
        assert(hw);
#endif
        GetWindowRect(hw, &r);
        OffsetRect(&r, -r_main.left, -r_main.top);
        ncd->r_credtext.bottom = r.bottom;
    }

    /* if the mode is 'mini'*/
    r.left = 0;
    r.top = 0;
    if(c->mode == KHUI_NC_MODE_MINI) {
        r.right = NCDLG_WIDTH;
        r.bottom = NCDLG_HEIGHT;
    } else {
        r.right = NCDLG_WIDTH + NCDLG_BBAR_WIDTH;
        r.bottom = NCDLG_HEIGHT + NCDLG_TAB_HEIGHT;
    }

    MapDialogRect(ncd->dlg_main, &r);

    ncd->r_main.left = 0;
    ncd->r_main.top = 0;
    ncd->r_main.right = NCDLG_WIDTH;
    ncd->r_main.bottom = NCDLG_HEIGHT;

    ncd->r_ts.left = 0;
    ncd->r_ts.top = ncd->r_main.bottom;
    ncd->r_ts.right = ncd->r_main.right;
    ncd->r_ts.bottom = ncd->r_ts.top + NCDLG_TAB_HEIGHT;

    ncd->r_bb.left = ncd->r_main.right;
    ncd->r_bb.top = 0;
    ncd->r_bb.right = ncd->r_bb.left + NCDLG_BBAR_WIDTH;
    ncd->r_bb.bottom = ncd->r_ts.bottom;

    MapDialogRect(ncd->dlg_main, &(ncd->r_main));
    MapDialogRect(ncd->dlg_main, &(ncd->r_ts));
    MapDialogRect(ncd->dlg_main, &(ncd->r_bb));

    /* center the new creds window over the main NetIDMgr window */
    width = r.right - r.left;
    height = r.bottom - r.top;

    /* adjust width and height to accomodate NC area */
    {
        RECT wr,cr;

        GetWindowRect(hwnd, &wr);
        GetClientRect(hwnd, &cr);

        /* the non-client and client areas have already been calculated
           at this point.  We just use the difference to adjust the width
           and height */
        width += (wr.right - wr.left) - (cr.right - cr.left);
        height += (wr.bottom - wr.top) - (cr.bottom - cr.top);
    }

    GetWindowRect(lpc->hwndParent, &r);
    x = (r.right + r.left)/2 - width / 2;
    y = (r.top + r.bottom)/2 - height / 2;

    MoveWindow(hwnd, x, y, width, height, FALSE);

    SetWindowPos(ncd->dlg_main, 
                 NULL, 
                 ncd->r_main.left, 
                 ncd->r_main.top,
                 ncd->r_main.right - ncd->r_main.left,
                 ncd->r_main.bottom - ncd->r_main.top,
                 SWP_DEFERERASE | SWP_NOACTIVATE | SWP_NOOWNERZORDER | 
                 SWP_NOREDRAW | SWP_NOZORDER);

    /* IDD_NC_BBAR is the button bar that sits on the right of the
       dialog when the new creds window is in 'expanded' mode. */

    ncd->dlg_bb = CreateDialogParam(khm_hInstance,
                                    MAKEINTRESOURCE(IDD_NC_BBAR),
                                    hwnd,
                                    nc_common_dlg_proc,
                                    (LPARAM) ncd);

#ifdef DEBUG
    assert(ncd->dlg_bb);
#endif

    SetWindowPos(ncd->dlg_bb, 
                 NULL, 
                 ncd->r_bb.left, 
                 ncd->r_bb.top,
                 ncd->r_bb.right - ncd->r_bb.left,
                 ncd->r_bb.bottom - ncd->r_bb.top,
                 SWP_DEFERERASE | SWP_NOACTIVATE | SWP_NOOWNERZORDER | 
                 SWP_NOREDRAW | SWP_NOZORDER);

    /* IDD_NC_TS is the tab strip that sits below the main panel when
       the new creds window is in 'expanded' mode */

    ncd->dlg_ts = CreateDialogParam(khm_hInstance,
                                    MAKEINTRESOURCE(IDD_NC_TS),
                                    hwnd,
                                    nc_common_dlg_proc,
                                    (LPARAM) ncd);

#ifdef DEBUG
    assert(ncd->dlg_ts);
#endif

    SetWindowPos(ncd->dlg_ts, 
                 NULL, 
                 ncd->r_ts.left, 
                 ncd->r_ts.top,
                 ncd->r_ts.right - ncd->r_ts.left,
                 ncd->r_ts.bottom - ncd->r_ts.top,
                 SWP_DEFERERASE | SWP_NOACTIVATE | SWP_NOOWNERZORDER | 
                 SWP_NOREDRAW | SWP_NOZORDER);

    if(c->mode == KHUI_NC_MODE_MINI) {
        /* hide and show stuff */
        ShowWindow(ncd->dlg_main, SW_SHOW);
        ShowWindow(ncd->dlg_bb, SW_HIDE);
        ShowWindow(ncd->dlg_ts, SW_HIDE);

        nc_position_credtext(ncd);

    } else {
        /* hide and show stuff */
        ShowWindow(ncd->dlg_main, SW_SHOW);
        ShowWindow(ncd->dlg_bb, SW_SHOW);
        ShowWindow(ncd->dlg_ts, SW_SHOW);

        PostMessage(ncd->dlg_main, KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0, WMNC_DIALOG_EXPAND), 0);
    }

    /* Call the identity provider callback to set the identity
       selector controls */
    c->ident_cb(c, WMNC_IDENT_INIT, NULL, 0, 0, (LPARAM) ncd->dlg_main);

#if 0
    {
        HWND hw;
        wchar_t wcaption[64];

        LoadString(khm_hInstance, IDS_NC_SETDEF, wcaption,
                   ARRAYLENGTH(wcaption));

        /* Now create the set as default button */
        hw = CreateWindow
            (L"BUTTON",
             wcaption,
             WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
             0, 0, 100, 100,
             ncd->dlg_main,
             (HMENU) NC_BN_SET_DEF_ID,
             khm_hInstance,
             NULL);

        nc_add_control_row(ncd, NULL, hw, KHUI_CTRLSIZE_HALF);
    }
#endif
    /* we defer the creation of the tab buttons for later */

    /* add this to the dialog chain */
    khm_add_dialog(hwnd);

    return TRUE;
}

static void
nc_add_control_row(khui_nc_wnd_data * d, 
                   HWND label,
                   HWND input,
                   khui_control_size size)
{
    RECT r_row;
    RECT r_label;
    RECT r_input;
    HFONT hf;

    hf = (HFONT) SendMessage(d->dlg_main, WM_GETFONT, 0, 0);
    SendMessage(label, WM_SETFONT, (WPARAM) hf, FALSE);
    SendMessage(input, WM_SETFONT, (WPARAM) hf, FALSE);

    CopyRect(&r_row, &d->r_row);
    OffsetRect(&r_row, d->r_idspec.left, d->r_idspec.bottom);

    if (size == KHUI_CTRLSIZE_SMALL) {
        CopyRect(&r_label, &d->r_n_label);
        CopyRect(&r_input, &d->r_n_input);
        OffsetRect(&r_label, r_row.left, r_row.top);
        OffsetRect(&r_input, r_row.left, r_row.top);
    } else if (size == KHUI_CTRLSIZE_HALF) {
        CopyRect(&r_label, &d->r_e_label);
        CopyRect(&r_input, &d->r_e_input);
        OffsetRect(&r_label, r_row.left, r_row.top);
        OffsetRect(&r_input, r_row.left, r_row.top);
    } else if (size == KHUI_CTRLSIZE_FULL) {
        CopyRect(&r_label, &d->r_n_label);
        r_label.right = d->r_row.right;
        CopyRect(&r_input, &d->r_n_input);
        OffsetRect(&r_input, r_row.left, r_row.top);
        OffsetRect(&r_input, 0, r_input.bottom);
        r_row.bottom += r_input.bottom;
        OffsetRect(&r_label, r_row.left, r_row.top);
    } else {
        SetRectEmpty(&r_label);
        SetRectEmpty(&r_input);
#ifdef DEBUG
        assert(FALSE);
#else
        return;
#endif
    }

    if (label)
        SetWindowPos(label,
                     ((d->hwnd_last_idspec != NULL)?
                      d->hwnd_last_idspec:
                      HWND_TOP),
                     r_label.left, r_label.top,
                     r_label.right - r_label.left,
                     r_label.bottom - r_label.top,
                     SWP_DEFERERASE | SWP_NOACTIVATE |
                     SWP_NOOWNERZORDER);

    if (input)
        SetWindowPos(input,
                     (label ? label : ((d->hwnd_last_idspec != NULL)?
                                       d->hwnd_last_idspec:
                                       HWND_TOP)),
                     r_input.left, r_input.top,
                     r_input.right - r_input.left,
                     r_input.bottom - r_input.top,
                     SWP_DEFERERASE | SWP_NOACTIVATE |
                     SWP_NOOWNERZORDER);

    d->hwnd_last_idspec = input;

    d->r_idspec.bottom = r_row.bottom;

    d->r_credtext.top = r_row.bottom;

    nc_position_credtext(d);
}


static LRESULT 
nc_handle_wm_destroy(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam)
{
    khui_nc_wnd_data * d;
    khm_size i;

    /* remove self from dialog chain */
    khm_del_dialog(hwnd);

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);

    d->nc->ident_cb(d->nc, WMNC_IDENT_EXIT, NULL, 0, 0, 0);

    if(d->hwnd_tc_main)
        DestroyWindow(d->hwnd_tc_main);
    for(i=0;i<d->nc->n_types;i++) {
        if(d->nc->types[i]->hwnd_tc) {
            DestroyWindow(d->nc->types[i]->hwnd_tc);
            d->nc->types[i]->hwnd_tc = NULL;
        }
    }

    if(d->dlg_bb)
        DestroyWindow(d->dlg_bb);
    if(d->dlg_main)
        DestroyWindow(d->dlg_main);
    if(d->dlg_ts)
        DestroyWindow(d->dlg_ts);

    d->dlg_bb = NULL;
    d->dlg_main = NULL;
    d->dlg_ts = NULL;

    PFREE(d);

    return TRUE;
}

static LRESULT 
nc_handle_wm_command(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam)
{
    khui_nc_wnd_data * d;
    int id;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);

    switch(HIWORD(wParam)) {
    case BN_CLICKED:
        switch(LOWORD(wParam)) {

        case IDOK:
            d->nc->result = KHUI_NC_RESULT_PROCESS;

            /* fallthrough */

        case IDCANCEL:
            /* the default value for d->nc->result is set to
               KHUI_NC_RESULT_CANCEL */
            d->nc->response = 0;

            nc_notify_types(d->nc, 
                            KHUI_WM_NC_NOTIFY, 
                            MAKEWPARAM(0,WMNC_DIALOG_PREPROCESS), 
                            0);

            khui_cw_sync_prompt_values(d->nc);

            khm_cred_dispatch_process_message(d->nc);

            /* we won't know whether to abort or not until we get
               feedback from the plugins, even if the command was
               to cancel */
            {
                HWND hw;

                hw = GetDlgItem(d->dlg_main, IDOK);
                EnableWindow(hw, FALSE);
                hw = GetDlgItem(d->dlg_main, IDCANCEL);
                EnableWindow(hw, FALSE);
                hw = GetDlgItem(d->dlg_bb, IDOK);
                EnableWindow(hw, FALSE);
                hw = GetDlgItem(d->dlg_bb, IDCANCEL);
                EnableWindow(hw, FALSE);
            }
            return FALSE;

        case IDC_NC_HELP:
            khm_html_help(hwnd, NULL, HH_HELP_CONTEXT, IDH_ACTION_NEW_ID);
            return FALSE;

        case IDC_NC_OPTIONS: 
            /* the Options button in the main window was clicked.  we
               respond by expanding the dialog. */
            PostMessage(hwnd, KHUI_WM_NC_NOTIFY, 
                        MAKEWPARAM(0, WMNC_DIALOG_EXPAND), 0);
            return FALSE;

        case IDC_NC_CREDTEXT: /* credtext link activated */
            {
                khui_htwnd_link * l;
                wchar_t sid[KHUI_MAXCCH_HTLINK_FIELD];
                wchar_t sparam[KHUI_MAXCCH_HTLINK_FIELD];
                wchar_t * colon;

                l = (khui_htwnd_link *) lParam;

                /* do we have a valid link? */
                if(l->id == NULL || l->id_len >= ARRAYLENGTH(sid))
                    return TRUE; /* nope */

                StringCchCopyN(sid, ARRAYLENGTH(sid), l->id, l->id_len);
                sid[l->id_len] = L'\0'; /* just make sure */

                if(l->param != NULL && 
                   l->param_len < ARRAYLENGTH(sparam) &&
                   l->param_len > 0) {

                    StringCchCopyN(sparam, ARRAYLENGTH(sparam),
                                   l->param, l->param_len);
                    sparam[l->param_len] = L'\0';

                } else {
                    sparam[0] = L'\0';
                }

                /* If the ID is of the form '<credtype>:<link_tag>'
                   and <credtype> is a valid name of a credentials
                   type that is participating in the credentials
                   acquisition process, then we forward the message to
                   the panel that is providing the UI for that cred
                   type.  We also switch to that panel first. */

                colon = wcschr(sid, L':');
                if (colon != NULL) {
                    khm_int32 credtype;
                    khui_new_creds_by_type * t;

                    *colon = L'\0';
                    if (KHM_SUCCEEDED(kcdb_credtype_get_id(sid, &credtype)) &&
                        KHM_SUCCEEDED(khui_cw_find_type(d->nc, credtype, &t))){
                        *colon = L':';

                        if (t->ordinal != d->ctab)
                            PostMessage(hwnd,
                                        KHUI_WM_NC_NOTIFY,
                                        MAKEWPARAM(t->ordinal,
                                                   WMNC_DIALOG_SWITCH_PANEL),
                                        0);

                        return SendMessage(t->hwnd_panel,
                                           KHUI_WM_NC_NOTIFY,
                                           MAKEWPARAM(0, WMNC_CREDTEXT_LINK),
                                           lParam);
                    }
                }

                /* if it was for us, then we need to process the message */
                if(!_wcsicmp(sid, CTLINKID_SWITCH_PANEL)) {
                    khm_int32 credtype;
                    khui_new_creds_by_type * t;

                    if (KHM_SUCCEEDED(kcdb_credtype_get_id(sparam, 
                                                           &credtype)) &&
                        KHM_SUCCEEDED(khui_cw_find_type(d->nc,
                                                        credtype, &t))) {
                        if (t->ordinal != d->ctab)
                            PostMessage(hwnd,
                                        KHUI_WM_NC_NOTIFY,
                                        MAKEWPARAM(t->ordinal,
                                                   WMNC_DIALOG_SWITCH_PANEL),
                                        0);
                    }
                } else if (!_wcsicmp(sid, L"NotDef")) {
                    d->nc->set_default = FALSE;
                    nc_update_credtext(d);
                } else if (!_wcsicmp(sid, L"MakeDef")) {
                    d->nc->set_default = TRUE;
                    nc_update_credtext(d);
                }
            }
            return FALSE;

#if 0
        case NC_BN_SET_DEF_ID:
            {
                d->nc->set_default =
                    (IsDlgButtonChecked(d->dlg_main, NC_BN_SET_DEF_ID)
                     == BST_CHECKED);
            }
            return FALSE;
#endif

        default:
            /* if one of the tab strip buttons were pressed, then
               we should switch to that panel */
            id = LOWORD(wParam);
            if(id >= NC_TS_CTRL_ID_MIN && id <= NC_TS_CTRL_ID_MAX) {
                id -= NC_TS_CTRL_ID_MIN;
                PostMessage(hwnd, KHUI_WM_NC_NOTIFY, 
                            MAKEWPARAM(id, WMNC_DIALOG_SWITCH_PANEL),0);
                return FALSE;
            }
        }
        break;
    }

    return TRUE;
}

static LRESULT nc_handle_wm_moving(HWND hwnd,
                                   UINT uMsg,
                                   WPARAM wParam,
                                   LPARAM lParam)
{
    khui_nc_wnd_data * d;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);

    nc_notify_types(d->nc, KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0, WMNC_DIALOG_MOVE), 0);

    return FALSE;
}

static LRESULT nc_handle_wm_nc_notify(HWND hwnd,
                               UINT uMsg,
                               WPARAM wParam,
                               LPARAM lParam)
{
    khui_nc_wnd_data * d;
    RECT r;
    int width, height;
    khm_size id;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);

    switch(HIWORD(wParam)) {

    case WMNC_DIALOG_SWITCH_PANEL:
        id = LOWORD(wParam);
        if(id >= 0 && id <= d->nc->n_types) {
            /* one of the tab buttons were pressed */
            if(d->ctab == id) {
                return TRUE; /* nothign to do */
            }

            if(d->ctab == 0) {
                ShowWindow(d->dlg_main, SW_HIDE);
                SendMessage(d->hwnd_tc_main, 
                            BM_SETCHECK, BST_UNCHECKED, 0);
            } else {
                ShowWindow(d->nc->types[d->ctab - 1]->hwnd_panel, SW_HIDE);
                SendMessage(d->nc->types[d->ctab - 1]->hwnd_tc, 
                            BM_SETCHECK, BST_UNCHECKED, 0);
            }

            d->ctab = id;

            if(d->ctab == 0) {
                ShowWindow(d->dlg_main, SW_SHOW);
                SendMessage(d->hwnd_tc_main, 
                            BM_SETCHECK, BST_CHECKED, 0);
            } else {
                ShowWindow(d->nc->types[id - 1]->hwnd_panel, SW_SHOW);
                SendMessage(d->nc->types[id - 1]->hwnd_tc, 
                            BM_SETCHECK, BST_CHECKED, 0);
            }
        }

        if(d->nc->mode == KHUI_NC_MODE_EXPANDED)
            return TRUE;
        /*else*/
        /* fallthrough */

    case WMNC_DIALOG_EXPAND:
        /* we are expanding the dialog box */

        /* nothing to do? */
        if (d->nc->mode == KHUI_NC_MODE_EXPANDED)
            break;

        d->nc->mode = KHUI_NC_MODE_EXPANDED;

        r.top = 0;
        r.left = 0;
        r.right = NCDLG_WIDTH + NCDLG_BBAR_WIDTH;
        r.bottom = NCDLG_HEIGHT + NCDLG_TAB_HEIGHT;

        MapDialogRect(d->dlg_main, &r);

        width = r.right - r.left;
        height = r.bottom - r.top;

        /* adjust width and height to accomodate NC area */
        {
            RECT wr,cr;

            GetWindowRect(hwnd, &wr);
            GetClientRect(hwnd, &cr);

            /* the non-client and client areas have already been
               calculated at this point.  We just use the difference
               to adjust the width and height */
            width += (wr.right - wr.left) - (cr.right - cr.left);
            height += (wr.bottom - wr.top) - (cr.bottom - cr.top);
        }

        SendMessage(d->dlg_main, 
                    KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0,WMNC_DIALOG_EXPAND), 
                    0);

        SetWindowPos(hwnd, 
                     NULL, 
                     0, 0, 
                     width, height, 
                     SWP_NOCOPYBITS | SWP_NOMOVE | SWP_NOOWNERZORDER | 
                     SWP_NOZORDER);

        ShowWindow(d->dlg_bb, SW_SHOW);
        ShowWindow(d->dlg_ts, SW_SHOW);
        break;

    case WMNC_DIALOG_SETUP:
        if(d->nc->n_types > 0) {
            khm_size i;
            for(i=0; i < d->nc->n_types;i++) {

                if (d->nc->types[i]->dlg_proc == NULL) {
                    d->nc->types[i]->hwnd_panel = NULL;
                } else {
                    /* Create the dialog panel */
                    d->nc->types[i]->hwnd_panel = 
                        CreateDialogParam(d->nc->types[i]->h_module,
                                          d->nc->types[i]->dlg_template,
                                          d->nc->hwnd,
                                          d->nc->types[i]->dlg_proc,
                                          (LPARAM) d->nc);

#ifdef DEBUG
                    assert(d->nc->types[i]->hwnd_panel);
#endif
                }
            }
        }
        break;

    case WMNC_DIALOG_ACTIVATE:
        {
            int x,y,width,height;
            RECT r;
            int id;
            wchar_t wbuf[256];
            HFONT hf;

            /* now we create all the tab strip controls */
            r.left = 0;
            r.top = 0;
            r.right = NCDLG_TAB_WIDTH;
            r.bottom = NCDLG_TAB_HEIGHT;
            MapDialogRect(d->dlg_main, &r);

            width = r.right - r.left;
            height = r.bottom - r.top;

            x = 0;
            y = 0;

            id = NC_TS_CTRL_ID_MIN;

            khui_cw_lock_nc(d->nc);

            /* first, the control for the main panel */
            LoadString(khm_hInstance, IDS_NC_IDENTITY, 
                       wbuf, ARRAYLENGTH(wbuf));

            d->hwnd_tc_main = 
                CreateWindow(L"BUTTON",
                             wbuf,
                             WS_VISIBLE | WS_CHILD | WS_TABSTOP |
                             BS_PUSHLIKE | BS_CHECKBOX | BS_TEXT,
                             x,y,width,height,
                             d->dlg_ts,
                             (HMENU)(INT_PTR) id,
                             khm_hInstance,
                             NULL);

            hf = (HFONT) SendMessage(d->dlg_main, WM_GETFONT, 0, 0);
            SendMessage(d->hwnd_tc_main, WM_SETFONT, (WPARAM) hf, 0);
            SendMessage(d->hwnd_tc_main, BM_SETCHECK, BST_CHECKED, 0);

            id++;
            x += width;

            if(d->nc->n_types > 0) {
                khm_size i;
                /* we should sort the tabs first */
                qsort(d->nc->types, 
                      d->nc->n_types, 
                      sizeof(*(d->nc->types)), 
                      nc_tab_sort_func);

                for(i=0; i < d->nc->n_types;i++) {
                    wchar_t * name = NULL;

                    d->nc->types[i]->ordinal = i + 1;

                    if(d->nc->types[i]->name)
                        name = d->nc->types[i]->name;
                    else {
                        khm_size cbsize;

                        if(kcdb_credtype_describe
                           (d->nc->types[i]->type, 
                            NULL, 
                            &cbsize, 
                            KCDB_TS_SHORT) == KHM_ERROR_TOO_LONG) {

                            name = PMALLOC(cbsize);
                            kcdb_credtype_describe(d->nc->types[i]->type, 
                                                   name, 
                                                   &cbsize, 
                                                   KCDB_TS_SHORT);
                        } else {
#ifdef DEBUG
                            assert(FALSE);
#else
                            continue;
#endif
                        }
                    }

                    d->nc->types[i]->hwnd_tc = 
                        CreateWindow(L"BUTTON",
                                     name,
                                     WS_VISIBLE | WS_CHILD | WS_TABSTOP |
                                     BS_PUSHLIKE | BS_CHECKBOX | BS_TEXT |
                                     ((d->nc->types[i]->hwnd_panel == NULL)? 
                                      WS_DISABLED : 0),
                                     x,y,width,height,
                                     d->dlg_ts,
                                     (HMENU)(INT_PTR) id,
                                     khm_hInstance,
                                     NULL);

                    SendMessage(d->nc->types[i]->hwnd_tc, WM_SETFONT, 
                                (WPARAM)hf, 0);

#if 0
                    if(d->nc->types[i]->flags & KHUI_NCT_FLAG_DISABLED)
                        SendMessage(d->nc->types[i]->hwnd_tc, 
                                    BM_SETIMAGE, 
                                    IMAGE_ICON, 
                                    LoadIcon(khm_hInstance, MAKEINTRESOURCE(IDI_DISABLED)));
                    else
                        SendMessage(d->nc->types[i]->hwnd_tc, 
                                    BM_SETIMAGE, 
                                    IMAGE_ICON, 
                                    LoadIcon(khm_hInstance, MAKEINTRESOURCE(IDI_ENABLED)));
#endif

                    id++;
                    x += width;

                    if(!(d->nc->types[i]->name))
                        PFREE(name);

                    /* Now set the position of the type panel */
                    ShowWindow(d->nc->types[i]->hwnd_panel, SW_HIDE);
                    SetWindowPos(d->nc->types[i]->hwnd_panel, 
                                 NULL,
                                 d->r_main.left, 
                                 d->r_main.top,
                                 d->r_main.right - d->r_main.left,
                                 d->r_main.bottom - d->r_main.top,
                                 SWP_DEFERERASE | SWP_NOACTIVATE | 
                                 SWP_NOOWNERZORDER | SWP_NOREDRAW | 
                                 SWP_NOZORDER);

                }
            }

            khui_cw_unlock_nc(d->nc);

            nc_update_credtext(d);

            ShowWindow(hwnd, SW_SHOW);
            SetFocus(hwnd);

            if (d->nc->n_identities == 0)
                break;
            /* else */
            /*   fallthrough */
        }

    case WMNC_IDENTITY_CHANGE:
        {
            BOOL okEnable = FALSE;

            nc_notify_types(d->nc, KHUI_WM_NC_NOTIFY,
                            MAKEWPARAM(0, WMNC_IDENTITY_CHANGE), 0);

            if (d->nc->subtype == KMSG_CRED_NEW_CREDS &&
                d->nc->n_identities > 0 &&
                d->nc->identities[0]) {
                khm_int32 f = 0;

                kcdb_identity_get_flags(d->nc->identities[0], &f);

                if (!(f & KCDB_IDENT_FLAG_DEFAULT)) {
                    d->nc->set_default = FALSE;
                }
            }

            nc_update_credtext(d);

        }
        break;

    case WMNC_TYPE_STATE:
        /* fallthrough */
    case WMNC_UPDATE_CREDTEXT:
        nc_update_credtext(d);
        break;

    case WMNC_CLEAR_PROMPTS:
        {
            khm_size i;

            khui_cw_lock_nc(d->nc);

            if(d->hwnd_banner != NULL) {
                DestroyWindow(d->hwnd_banner);
                d->hwnd_banner = NULL;
            }

            if(d->hwnd_name != NULL) {
                DestroyWindow(d->hwnd_name);
                d->hwnd_name = NULL;
            }

            for(i=0;i<d->nc->n_prompts;i++) {
                if(!(d->nc->prompts[i]->flags & 
                     KHUI_NCPROMPT_FLAG_STOCK)) {
                    if(d->nc->prompts[i]->hwnd_static != NULL)
                        DestroyWindow(d->nc->prompts[i]->hwnd_static);

                    if(d->nc->prompts[i]->hwnd_edit != NULL)
                        DestroyWindow(d->nc->prompts[i]->hwnd_edit);
                }

                d->nc->prompts[i]->hwnd_static = NULL;
                d->nc->prompts[i]->hwnd_edit = NULL;
            }

            khui_cw_unlock_nc(d->nc);

            d->r_credtext.top = d->r_idspec.bottom;

            nc_position_credtext(d);
        }
        break;

    case WMNC_SET_PROMPTS:
        {
            khm_size i;
            int  y;
            HWND hw, hw_prev;
            HFONT hf, hfold;
            HDC hdc;

            /* we assume that WMNC_CLEAR_PROMPTS has already been
               received */

            khui_cw_lock_nc(d->nc);

#if 0
            /* special case, we have one prompt and it is a password
               prompt.  very common */
            if(d->nc->n_prompts == 1 && 
               d->nc->prompts[0]->type == KHUI_NCPROMPT_TYPE_PASSWORD) {

                hw = GetDlgItem(d->dlg_main, IDC_NC_PASSWORD);
                EnableWindow(hw, TRUE);

                d->nc->prompts[0]->flags |= KHUI_NCPROMPT_FLAG_STOCK;
                d->nc->prompts[0]->hwnd_edit = hw;
                d->nc->prompts[0]->hwnd_static = NULL; /* don't care */

                khui_cw_unlock_nc(d->nc);
                break;
            }
#endif
            /* for everything else */

            /* hide the stock password controls */
#if 0
            /* TAGREMOVE */
            hw = GetDlgItem(d->dlg_main, IDC_NC_PASSWORD);
            ShowWindow(hw, SW_HIDE);
            hw = GetDlgItem(d->dlg_main, IDC_NC_PASSWORD_LABEL);
            ShowWindow(hw, SW_HIDE);
#endif

            y = d->r_idspec.bottom;

            hf = (HFONT) SendMessage(d->dlg_main, WM_GETFONT, 0, 0);

            if (d->nc->pname != NULL) {
                hw =
                    CreateWindowEx
                    (0,
                     L"STATIC",
                     d->nc->pname,
                     SS_SUNKEN | WS_CHILD,
                     d->r_area.left, y,
                     d->r_row.right, 
                     d->r_n_label.bottom - d->r_n_label.top,
                     d->dlg_main,
                     NULL,
                     khm_hInstance,
                     NULL);

#ifdef DEBUG
                assert(hw);
#endif
                d->hwnd_name = hw;
                SendMessage(hw, WM_SETFONT, (WPARAM)hf, (LPARAM) TRUE);
                ShowWindow(hw, SW_SHOW);

                y += d->r_n_label.bottom - d->r_n_label.top;
            }

            if (d->nc->banner != NULL) {
                hw = 
                    CreateWindowEx
                    (0,
                     L"STATIC",
                     d->nc->banner,
                     WS_CHILD,
                     d->r_area.left, y,
                     d->r_row.right, d->r_row.bottom,
                     d->dlg_main,
                     NULL,
                     khm_hInstance,
                     NULL);
#ifdef DEBUG
                assert(hw);
#endif
                d->hwnd_banner = hw;
                SendMessage(hw, WM_SETFONT, (WPARAM)hf, (LPARAM)TRUE);
                ShowWindow(hw, SW_SHOW);
                y += d->r_row.bottom;
            }

            hw_prev = d->hwnd_last_idspec;

            hdc = GetWindowDC(d->dlg_main);
            hfold = SelectObject(hdc,hf);

            for(i=0; i<d->nc->n_prompts; i++) {
                RECT pr, er;
                SIZE s;
                int dy;

                if(d->nc->prompts[i]->prompt != NULL) {
                    GetTextExtentPoint32(hdc, 
                                         d->nc->prompts[i]->prompt, 
                                         (int) wcslen(d->nc->prompts[i]->prompt),
                                         &s);
                    if(s.cx < d->r_n_label.right - d->r_n_label.left) {
                        CopyRect(&pr, &d->r_n_label);
                        CopyRect(&er, &d->r_n_input);
                        dy = d->r_row.bottom;
                    } else if(s.cx < 
                              d->r_e_label.right - d->r_e_label.left) {
                        CopyRect(&pr, &d->r_e_label);
                        CopyRect(&er, &d->r_e_input);
                        dy = d->r_row.bottom;
                    } else {
                        /* oops. the prompt doesn't fit in our
                           controls.  we need to use up two lines */
                        pr.left = 0;
                        pr.right = d->r_row.right;
                        pr.top = 0;
                        pr.bottom = d->r_n_label.bottom - 
                            d->r_n_label.top;
                        CopyRect(&er, &d->r_n_input);
                        OffsetRect(&er, 0, pr.bottom);
                        dy = er.bottom + (d->r_row.bottom - 
                                          d->r_n_input.bottom);
                    }
                } else {
                    SetRectEmpty(&pr);
                    CopyRect(&er, &d->r_n_input);
                    dy = d->r_row.bottom;
                }

                if(IsRectEmpty(&pr)) {
                    d->nc->prompts[i]->hwnd_static = NULL;
                } else {
                    OffsetRect(&pr, d->r_area.left, y);

                    hw = CreateWindowEx
                        (0,
                         L"STATIC",
                         d->nc->prompts[i]->prompt,
                         WS_CHILD,
                         pr.left, pr.top,
                         pr.right - pr.left, pr.bottom - pr.top,
                         d->dlg_main,
                         NULL,
                         khm_hInstance,
                         NULL);
#ifdef DEBUG
                    assert(hw);
#endif

                    SendMessage(hw, WM_SETFONT, 
                                (WPARAM) hf, (LPARAM) TRUE);

                    SetWindowPos(hw, hw_prev,
                                 0, 0, 0, 0,
                                 SWP_NOACTIVATE | SWP_NOMOVE |
                                 SWP_NOOWNERZORDER | SWP_NOSIZE |
                                 SWP_SHOWWINDOW);

                    d->nc->prompts[i]->hwnd_static = hw;
                    hw_prev = hw;
                }

                OffsetRect(&er, d->r_area.left, y);

                hw = CreateWindowEx
                    (0,
                     L"EDIT",
                     (d->nc->prompts[i]->def ? 
                      d->nc->prompts[i]->def : L""),
                     WS_CHILD | WS_TABSTOP |
                     WS_BORDER |
                     ((d->nc->prompts[i]->flags & 
                       KHUI_NCPROMPT_FLAG_HIDDEN)? ES_PASSWORD:0),
                     er.left, er.top,
                     er.right - er.left, er.bottom - er.top,
                     d->dlg_main,
                     NULL,
                     khm_hInstance,
                     NULL);

#ifdef DEBUG
                assert(hw);
#endif

                SendMessage(hw, WM_SETFONT, 
                            (WPARAM) hf, (LPARAM) TRUE);

                SetWindowPos(hw, hw_prev,
                             0, 0, 0, 0, 
                             SWP_NOACTIVATE | SWP_NOMOVE | 
                             SWP_NOOWNERZORDER | SWP_NOSIZE | 
                             SWP_SHOWWINDOW);

                SendMessage(hw, EM_SETLIMITTEXT,
                            KHUI_MAXCCH_PROMPT_VALUE -1,
                            0);

                d->nc->prompts[i]->hwnd_edit = hw;

                hw_prev = hw;

                y += dy;
            }

            SelectObject(hdc, hfold);
            ReleaseDC(d->dlg_main, hdc);

            khui_cw_unlock_nc(d->nc);

            d->r_credtext.top = y;

            nc_position_credtext(d);
        }
        break;

    case WMNC_DIALOG_PROCESS_COMPLETE:
        {
            khui_new_creds * nc;

            nc = d->nc;

            if(nc->response & KHUI_NC_RESPONSE_NOEXIT) {
                HWND hw;

                /* reset state */
                nc->result = KHUI_NC_RESULT_CANCEL;

                hw = GetDlgItem(d->dlg_main, IDOK);
                EnableWindow(hw, TRUE);
                hw = GetDlgItem(d->dlg_main, IDCANCEL);
                EnableWindow(hw, TRUE);
                hw = GetDlgItem(d->dlg_bb, IDOK);
                EnableWindow(hw, TRUE);
                hw = GetDlgItem(d->dlg_bb, IDCANCEL);
                EnableWindow(hw, TRUE);

                return TRUE;
            }

            DestroyWindow(hwnd);

            kmq_post_message(KMSG_CRED, KMSG_CRED_END, 0, (void *) nc);
        }
        break;

        /* MUST be called with SendMessage */
    case WMNC_ADD_CONTROL_ROW:
        {
            khui_control_row * row;

            row = (khui_control_row *) lParam;

#ifdef DEBUG
            assert(row->label);
            assert(row->input);
#endif

            nc_add_control_row(d, row->label, row->input, row->size);
        }
        break;
    } /* switch(HIWORD(wParam)) */

    return TRUE;
}

static LRESULT nc_handle_wm_help(HWND hwnd,
                                 UINT uMsg,
                                 WPARAM wParam,
                                 LPARAM lParam) {
    static DWORD ctxids[] = {
        NC_TS_CTRL_ID_MIN, IDH_NC_TABMAIN,
        NC_TS_CTRL_ID_MIN + 1, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 2, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 3, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 4, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 5, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 6, IDH_NC_TABBUTTON,
        NC_TS_CTRL_ID_MIN + 7, IDH_NC_TABBUTTON,
        IDOK, IDH_NC_OK,
        IDCANCEL, IDH_NC_CANCEL,
        IDC_NC_HELP, IDH_NC_HELP,
        IDC_NC_OPTIONS, IDH_NC_OPTIONS,
        IDC_NC_CREDTEXT, IDH_NC_CREDWND,
        0
    };

    HELPINFO * hlp;
    HWND hw = NULL;
    HWND hw_ctrl;
    khui_nc_wnd_data * d;

    d = (khui_nc_wnd_data *)(LONG_PTR) GetWindowLongPtr(hwnd, CW_PARAM);

    hlp = (HELPINFO *) lParam;

    if (d->nc->subtype != KMSG_CRED_NEW_CREDS &&
        d->nc->subtype != KMSG_CRED_PASSWORD)
        return TRUE;

    if (hlp->iContextType != HELPINFO_WINDOW)
        return TRUE;

    if (hlp->hItemHandle != NULL &&
        hlp->hItemHandle != hwnd) {
        DWORD id;
        int i;

        hw_ctrl =hlp->hItemHandle;

        id = GetWindowLong(hw_ctrl, GWL_ID);
        for (i=0; ctxids[i] != 0; i += 2)
            if (ctxids[i] == id)
                break;

        if (ctxids[i] != 0)
            hw = khm_html_help(hw_ctrl,
                               ((d->nc->subtype == KMSG_CRED_NEW_CREDS)?
                                L"::popups_newcreds.txt":
                                L"::popups_password.txt"),
                               HH_TP_HELP_WM_HELP,
                               (DWORD_PTR) ctxids);
    }

    if (hw == NULL) {
        khm_html_help(hwnd, NULL, HH_HELP_CONTEXT,
                      ((d->nc->subtype == KMSG_CRED_NEW_CREDS)?
                       IDH_ACTION_NEW_ID: IDH_ACTION_PASSWD_ID));
    }

    return TRUE;
}

static LRESULT CALLBACK nc_window_proc(HWND hwnd,
                                       UINT uMsg,
                                       WPARAM wParam,
                                       LPARAM lParam)
{
    switch(uMsg) {
    case WM_CREATE:
        return nc_handle_wm_create(hwnd, uMsg, wParam, lParam);

    case WM_DESTROY:
        return nc_handle_wm_destroy(hwnd, uMsg, wParam, lParam);

    case WM_COMMAND:
        return nc_handle_wm_command(hwnd, uMsg, wParam, lParam);

    case WM_MOVE:
    case WM_MOVING:
        return nc_handle_wm_moving(hwnd, uMsg, wParam, lParam);

    case WM_HELP:
        return nc_handle_wm_help(hwnd, uMsg, wParam, lParam);

    case KHUI_WM_NC_NOTIFY:
        return nc_handle_wm_nc_notify(hwnd, uMsg, wParam, lParam);
    }

    /* Note that this is technically a dialog box */
    return DefDlgProc(hwnd, uMsg, wParam, lParam);
}

void khm_register_newcredwnd_class(void)
{
    WNDCLASSEX wcx;

    wcx.cbSize = sizeof(wcx);
    wcx.style = CS_DBLCLKS | CS_OWNDC;
    wcx.lpfnWndProc = nc_window_proc;
    wcx.cbClsExtra = 0;
    wcx.cbWndExtra = DLGWINDOWEXTRA + sizeof(LONG_PTR);
    wcx.hInstance = khm_hInstance;
    wcx.hIcon = LoadIcon(khm_hInstance, MAKEINTRESOURCE(IDI_MAIN_APP));
    wcx.hCursor = LoadCursor((HINSTANCE) NULL, IDC_ARROW);
    wcx.hbrBackground = (HBRUSH) (COLOR_BACKGROUND + 1);
    wcx.lpszMenuName = NULL;
    wcx.lpszClassName = KHUI_NEWCREDWND_CLASS;
    wcx.hIconSm = NULL;

    khui_newcredwnd_cls = RegisterClassEx(&wcx);
}

void khm_unregister_newcredwnd_class(void)
{
    UnregisterClass((LPWSTR) khui_newcredwnd_cls, khm_hInstance);
}

HWND khm_create_newcredwnd(HWND parent, khui_new_creds * c)
{
    wchar_t wtitle[256];
    HWND hwnd;

    if (c->window_title == NULL) {
        if (c->subtype == KMSG_CRED_PASSWORD)
            LoadString(khm_hInstance, 
                       IDS_WT_PASSWORD,
                       wtitle,
                       ARRAYLENGTH(wtitle));
        else
            LoadString(khm_hInstance, 
                       IDS_WT_NEW_CREDS,
                       wtitle,
                       ARRAYLENGTH(wtitle));
    }

    hwnd = CreateWindowEx(WS_EX_DLGMODALFRAME | WS_EX_CONTEXTHELP,
                          MAKEINTATOM(khui_newcredwnd_cls),
                          ((c->window_title)?c->window_title: wtitle),
                          WS_DLGFRAME | WS_POPUPWINDOW | WS_CLIPCHILDREN,
                          0,0,400,400,    /* bogus values.  the window
                                             is going to resize and
                                             reposition itself
                                             anyway */
                          parent,
                          NULL,
                          khm_hInstance,
                          (LPVOID) c);

#ifdef DEBUG
    assert(hwnd != NULL);
#endif

    /* note that the window is not visible yet.  That's because, at
       this point we don't know what the panels are */

    return hwnd;
}

void khm_prep_newcredwnd(HWND hwnd)
{
    SendMessage(hwnd, KHUI_WM_NC_NOTIFY, 
                MAKEWPARAM(0, WMNC_DIALOG_SETUP), 0);
}

void khm_show_newcredwnd(HWND hwnd)
{
    /* add all the panels in and prep UI */
    SendMessage(hwnd, KHUI_WM_NC_NOTIFY, 
                MAKEWPARAM(0, WMNC_DIALOG_ACTIVATE), 0);
}
