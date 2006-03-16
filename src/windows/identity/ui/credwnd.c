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
#include<prsht.h>
#include<assert.h>

ATOM khui_credwnd_cls;
khm_int32 khui_cw_flag_id;

khm_int32 attr_to_action[KCDB_ATTR_MAX_ID + 1];

void
cw_refresh_attribs(HWND hwnd) {
    khm_int32 act;
    kcdb_attrib * attrib;
    khui_menu_def * menu;
    khm_int32 i;

    menu = khui_find_menu(KHUI_MENU_COLUMNS);
#ifdef DEBUG
    assert(menu);
#endif

    for (i=0; i <= KCDB_ATTR_MAX_ID; i++) {
        if (KHM_FAILED(kcdb_attrib_get_info(i, &attrib))) {
            if (attr_to_action[i] != 0) {
                /* the action should be removed */
                khui_menu_remove_action(menu, attr_to_action[i]);
                khui_action_delete(attr_to_action[i]);
                attr_to_action[i] = 0;
            }
        } else {
            if (attr_to_action[i] == 0 &&
                !(attrib->flags & KCDB_ATTR_FLAG_HIDDEN) &&
                (attrib->short_desc || attrib->long_desc)) {
                /* new action */
                khm_handle sub = NULL;

                kmq_create_hwnd_subscription(hwnd, &sub);

                act = khui_action_create(attrib->name,
                                         (attrib->short_desc?
                                          attrib->short_desc: attrib->long_desc),
                                         NULL,
                                         (void *)(UINT_PTR) i,
                                         KHUI_ACTIONTYPE_TOGGLE,
                                         sub);

                attr_to_action[i] = act;

                khui_menu_insert_action(menu, 5000, act, 0);
            }

            kcdb_attrib_release_info(attrib);
        }
    }
}

khm_int32 
cw_get_custom_attr_id(wchar_t * s)
{
    if(!wcscmp(s, CW_CANAME_FLAGS))
        return CW_CA_FLAGS;
    if(!wcscmp(s, CW_CANAME_TYPEICON))
        return CW_CA_TYPEICON;
    return 0;
}

const wchar_t *
cw_get_custom_attr_string(khm_int32 attr_id)
{
    if (attr_id == CW_CA_FLAGS)
        return CW_CANAME_FLAGS;
    if (attr_id == CW_CA_TYPEICON)
        return CW_CANAME_TYPEICON;
    return NULL;
}

void
cw_save_view(khui_credwnd_tbl * tbl, wchar_t * view_name) {
    wchar_t * col_list = NULL;
    khm_size cb_col_list;
    khm_handle csp_cw = NULL;
    khm_handle csp_views = NULL;
    khm_handle csp_view = NULL;
    khm_handle csp_cols = NULL;
    khm_size cb;
    int i;

    if (tbl->n_cols == 0)
        return;

    cb_col_list = (KCONF_MAXCB_NAME + 1) * tbl->n_cols;

    col_list = PMALLOC(cb_col_list);
#ifdef DEBUG
    assert(col_list);
#endif

    if (!col_list)
        goto _cleanup;

    multi_string_init(col_list, cb_col_list);

    if (!view_name && (tbl->flags & KHUI_CW_TBL_CUSTVIEW)) {
        view_name = L"Custom_0";
    }

    if (view_name) {
        if (KHM_FAILED(khc_open_space(NULL, L"CredWindow",
                                      KHM_PERM_READ | KHM_PERM_WRITE, &csp_cw)))
            goto _cleanup;

        if (KHM_FAILED(khc_open_space(csp_cw, L"Views", KHM_PERM_READ, &csp_views)))
            goto _cleanup;

        if (KHM_FAILED(khc_open_space(csp_views, view_name,
                                      KHM_PERM_WRITE | KHM_FLAG_CREATE,
                                      &csp_view)))
            goto _cleanup;

        /* if we are switching to a custom view, then we should mark
           that as the default. */
        if (tbl->flags & KHUI_CW_TBL_CUSTVIEW) {
            khc_write_string(csp_cw, L"DefaultView", L"Custom_0");
        }

    } else {
        csp_view = tbl->csp_view;
    }

    if (!csp_view)
        goto _cleanup;

    if (KHM_FAILED(khc_open_space(csp_view, L"Columns",
                                  KHM_PERM_WRITE | KHM_FLAG_CREATE,
                                  &csp_cols)))
        goto _cleanup;

    for (i=0; i < tbl->n_cols; i++) {
        const wchar_t * attr_name;
        kcdb_attrib * attrib = NULL;
        khm_handle csp_col = NULL;

        if (tbl->cols[i].attr_id < 0) {
            attr_name = cw_get_custom_attr_string(tbl->cols[i].attr_id);
        } else {
            if (KHM_FAILED(kcdb_attrib_get_info(tbl->cols[i].attr_id,
                                                &attrib))) {
#ifdef DEBUG
                assert(FALSE);
#endif
                goto _clean_col;
            }

            attr_name = attrib->name;
        }
#ifdef DEBUG
        assert(attr_name);
#endif

        cb = cb_col_list;
        multi_string_append(col_list, &cb, attr_name);

        if (KHM_FAILED(khc_open_space(csp_cols, attr_name,
                                      KHM_PERM_WRITE | KHM_FLAG_CREATE,
                                      &csp_col)))
            goto _clean_col;

        khc_write_int32(csp_col, L"Width", tbl->cols[i].width);
        khc_write_int32(csp_col, L"SortIndex", tbl->cols[i].sort_index);
        khc_write_int32(csp_col, L"Flags", tbl->cols[i].flags);

    _clean_col:

        if (csp_col)
            khc_close_space(csp_col);

        if (attrib)
            kcdb_attrib_release_info(attrib);
    }

    khc_write_multi_string(csp_view, L"ColumnList", col_list);

 _cleanup:

    if (view_name) {
        if (csp_view)
            khc_close_space(csp_view);

        if (csp_views)
            khc_close_space(csp_views);

        if (csp_cw)
            khc_close_space(csp_cw);
    }

    if (csp_cols)
        khc_close_space(csp_cols);

    if (col_list)
        PFREE(col_list);
}

void 
cw_load_view(khui_credwnd_tbl * tbl, wchar_t * view, HWND hwnd) {
    khm_handle hc_cw = NULL;
    khm_handle hc_vs = NULL;
    khm_handle hc_v = NULL;
    khm_handle hc_cs = NULL;
    khm_handle hc_c = NULL;
    wchar_t buf[KCONF_MAXCCH_NAME];
    wchar_t * clist = NULL;
    khm_size cbsize;
    wchar_t * cstr = NULL;
    wchar_t * iter = NULL;
    int i;
    HDC hdc;

    tbl->hwnd = hwnd;

    if(KHM_FAILED(khc_open_space(NULL, L"CredWindow", KHM_PERM_READ | KHM_PERM_WRITE,
                                 &hc_cw)))
        return;

    if(KHM_FAILED(khc_open_space(hc_cw, L"Views", KHM_PERM_READ, &hc_vs)))
        goto _exit;

    if(!view) {
        cbsize = sizeof(buf);
        if(KHM_FAILED(khc_read_string(hc_cw, L"DefaultView", buf, &cbsize)))
            goto _exit;
        view = buf;

        /* in addition, if we are loading the default view, we should
           also check the appropriate menu item */

        if (!wcscmp(view, L"ByIdentity"))
            khui_check_radio_action(khui_find_menu(KHUI_MENU_LAYOUT),
                                    KHUI_ACTION_LAYOUT_ID);
        else if (!wcscmp(view, L"ByLocation"))
            khui_check_radio_action(khui_find_menu(KHUI_MENU_LAYOUT),
                                    KHUI_ACTION_LAYOUT_LOC);
        else if (!wcscmp(view, L"ByType"))
            khui_check_radio_action(khui_find_menu(KHUI_MENU_LAYOUT),
                                    KHUI_ACTION_LAYOUT_TYPE);
        else if (!wcscmp(view, L"Custom_0"))
            khui_check_radio_action(khui_find_menu(KHUI_MENU_LAYOUT),
                                    KHUI_ACTION_LAYOUT_CUST);

        kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);                                
    } else {
        khc_write_string(hc_cw, L"DefaultView", view);
    }

    if(KHM_FAILED(khc_open_space(hc_vs, view, KHM_PERM_READ, &hc_v)))
        goto _exit;

    tbl->csp_view = hc_v;

    if(KHM_FAILED(khc_open_space(hc_v, L"Columns", KHM_PERM_READ, &hc_cs)))
        goto _exit;

    cbsize = 0;
    if(khc_read_multi_string(hc_v, L"ColumnList", NULL, &cbsize) != KHM_ERROR_TOO_LONG)
        goto _exit;

    /* temporary */
    clist = PMALLOC(cbsize);

    if(KHM_FAILED(khc_read_multi_string(hc_v, L"ColumnList", clist, &cbsize)))
        goto _exit;

    tbl->n_cols = (int) multi_string_length_n(clist);
    tbl->n_total_cols = UBOUNDSS(tbl->n_cols,
                                 KHUI_CW_COL_INITIAL, KHUI_CW_COL_INCREMENT);
    tbl->cols = PMALLOC(sizeof(khui_credwnd_col) * tbl->n_total_cols);
    ZeroMemory(tbl->cols, sizeof(khui_credwnd_col) * tbl->n_total_cols);

    tbl->flags &= ~(KHUI_CW_TBL_CUSTVIEW | KHUI_CW_TBL_COLSKIP);

    iter = clist;
    i = 0;
    while(iter) {
        khm_int32 attr_id;

        attr_id = cw_get_custom_attr_id(iter);
        if(!attr_id) {
            /* a KCDB attribute */
            if(KHM_FAILED(kcdb_attrib_get_id(iter, &attr_id))) {
                tbl->flags |= KHUI_CW_TBL_COLSKIP;
                goto _skip_col;
            }

            if(kcdb_attrib_describe(attr_id, NULL,
                                    &cbsize, KCDB_TS_SHORT) != KHM_ERROR_TOO_LONG ||
               cbsize == 0) {
                tbl->flags |= KHUI_CW_TBL_COLSKIP;
                goto _skip_col;
            }

            tbl->cols[i].title = PMALLOC(cbsize);
            kcdb_attrib_describe(attr_id, tbl->cols[i].title, &cbsize, KCDB_TS_SHORT);

            if (attr_id >= 0 &&
                attr_id <= KCDB_ATTR_MAX_ID &&
                attr_to_action[attr_id]) {
                khui_check_action(attr_to_action[attr_id], TRUE);
            }

        } else {
            /* All current custom attributes are represented by icons,
               not names */
            tbl->cols[i].title = NULL;
        }

        tbl->cols[i].attr_id = attr_id;

        if(KHM_SUCCEEDED(khc_open_space(hc_cs, iter, KHM_PERM_READ, &hc_c))) {
            if(KHM_FAILED(khc_read_int32(hc_c, L"Flags", &(tbl->cols[i].flags))))
                tbl->cols[i].flags = 0;
            if(KHM_FAILED(khc_read_int32(hc_c, L"Width", &(tbl->cols[i].width))))
                tbl->cols[i].width = 100;
            if(KHM_FAILED(khc_read_int32(hc_c, L"SortIndex",
                                         &(tbl->cols[i].sort_index))))
                tbl->cols[i].sort_index = -1;
            khc_close_space(hc_c);
            hc_c = NULL;
        } else {
            tbl->cols[i].flags = 0;
            tbl->cols[i].width = -1;
            tbl->cols[i].sort_index = -1;
        }
        i++;
_skip_col:
        iter = multi_string_next(iter);
    }

    /* refresh the menus since we checked a few items */
    kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);

    /* adjust the number of columns.  We may have skipped columns due to
       inconsistencies above */
    tbl->n_cols = i;

    /* now that all the columns have been loaded, load the view
       parameters */
    if(KHM_FAILED(khc_read_int32(hc_v, L"PaddingHorizontal", &(tbl->hpad))))
        khc_read_int32(hc_cw, L"PaddingHorizontal", &(tbl->hpad));
    if(KHM_FAILED(khc_read_int32(hc_v, L"PaddingVertical", &(tbl->vpad))))
        khc_read_int32(hc_cw, L"PaddingVertical", &(tbl->vpad));
    if(KHM_FAILED(khc_read_int32(hc_v, L"PaddingHeader", &(tbl->hpad_h))))
        khc_read_int32(hc_cw, L"PaddingHeader", &(tbl->hpad_h));
    if(KHM_FAILED(khc_read_int32(hc_v, L"WarnThreshold", &(tbl->threshold_warn))))
        khc_read_int32(hc_cw, L"WarnThreshold", &(tbl->threshold_warn));
    if(KHM_FAILED(khc_read_int32(hc_v, L"CriticalThreshold",
                                 &(tbl->threshold_critical))))
        khc_read_int32(hc_cw, L"CriticalThreshold",
                       &(tbl->threshold_critical));

    /* and the font resources and stuff */

    tbl->flags |= KHUI_CW_TBL_INITIALIZED | KHUI_CW_TBL_COL_DIRTY | KHUI_CW_TBL_ACTIVE;

    /*TODO: the graphics objects should be customizable */

    hdc = GetWindowDC(hwnd);

    tbl->hf_header =
        CreateFont(-MulDiv(8, GetDeviceCaps(hdc, LOGPIXELSY), 72),0, /* width/height */
                   0,0, /* escapement */
                   FW_THIN,
                   FALSE,
                   FALSE,
                   FALSE,
                   DEFAULT_CHARSET,
                   OUT_DEFAULT_PRECIS,
                   CLIP_DEFAULT_PRECIS,
                   DEFAULT_QUALITY,
                   FF_SWISS,
                   L"MS Shell Dlg");

    if(tbl->hf_header && tbl->hwnd_header)
        SendMessage(tbl->hwnd_header, WM_SETFONT, (WPARAM) tbl->hf_header, 0);

    tbl->hf_bold_header =
        CreateFont(-MulDiv(8, GetDeviceCaps(hdc, LOGPIXELSY), 72),0, /* width/height */
                   0,0, /* escapement */
                   FW_BOLD,
                   FALSE,
                   FALSE,
                   FALSE,
                   DEFAULT_CHARSET,
                   OUT_DEFAULT_PRECIS,
                   CLIP_DEFAULT_PRECIS,
                   DEFAULT_QUALITY,
                   FF_SWISS,
                   L"MS Shell Dlg");

    tbl->hf_normal =
        CreateFont(-MulDiv(8, GetDeviceCaps(hdc, LOGPIXELSY), 72),0, /* width/height */
                   0,0, /* escapement */
                   FW_THIN,
                   FALSE,
                   FALSE,
                   FALSE,
                   DEFAULT_CHARSET,
                   OUT_DEFAULT_PRECIS,
                   CLIP_DEFAULT_PRECIS,
                   DEFAULT_QUALITY,
                   FF_SWISS,
                   L"MS Shell Dlg");

    tbl->hf_bold =
        CreateFont(-MulDiv(8, GetDeviceCaps(hdc, LOGPIXELSY), 72),0, /* width/height */
                   0,0, /* escapement */
                   FW_BOLD,
                   FALSE,
                   FALSE,
                   FALSE,
                   DEFAULT_CHARSET,
                   OUT_DEFAULT_PRECIS,
                   CLIP_DEFAULT_PRECIS,
                   DEFAULT_QUALITY,
                   FF_SWISS,
                   L"MS Shell Dlg");

    ReleaseDC(hwnd, hdc);

    khui_bitmap_from_hbmp(&(tbl->kbm_logo_shade),
                          LoadImage(khm_hInstance,
                                    MAKEINTRESOURCE(IDB_LOGO_SHADE),
                                    IMAGE_BITMAP,
                                    0,
                                    0,
                                    LR_DEFAULTCOLOR));

    tbl->hb_normal =        CreateSolidBrush(RGB(255,255,255));
    tbl->hb_grey =          CreateSolidBrush(RGB(240,240,240));
    tbl->hb_sel =           CreateSolidBrush(RGB(230,230,255));
    tbl->hb_hdr_bg =        CreateSolidBrush(RGB(230,230,230));
    tbl->hb_hdr_bg_sel =    CreateSolidBrush(RGB(0,0,255));
    tbl->hb_hdr_bg_crit =   CreateSolidBrush(RGB(240,133,117));
    tbl->hb_hdr_bg_warn =   CreateSolidBrush(RGB(251,199,77));
    tbl->hb_hdr_bg_exp =    CreateSolidBrush(RGB(255,144,144));
    tbl->hb_hdr_bg_def =    CreateSolidBrush(RGB(186,254,184));

    tbl->cr_normal = RGB(0,0,0);
    tbl->cr_sel = RGB(0,0,0);
    tbl->cr_hdr_outline = RGB(0,0,0);
    tbl->cr_hdr_normal = RGB(0,0,0);
    tbl->cr_hdr_sel = RGB(255,255,255);

    tbl->ilist = khui_create_ilist(KHUI_SMICON_CX, KHUI_SMICON_CY-1, 20, 8, 0);
    {
        HBITMAP hbm;

#define ADD_BITMAP(i) \
        hbm = LoadImage(khm_hInstance, MAKEINTRESOURCE(i), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR); \
        if(hbm) { \
            khui_ilist_add_masked_id(tbl->ilist, hbm, KHUI_TOOLBAR_BGCOLOR, i); \
            DeleteObject(hbm); \
        }

        ADD_BITMAP(IDB_WDG_COLLAPSE);
        ADD_BITMAP(IDB_WDG_EXPAND);
        ADD_BITMAP(IDB_ID_SM);
        ADD_BITMAP(IDB_ID_DIS_SM);

        ADD_BITMAP(IDB_TK_NEW_SM);
        ADD_BITMAP(IDB_TK_REFRESH_SM);
        ADD_BITMAP(IDB_WDG_COLLAPSE_HI);
        ADD_BITMAP(IDB_WDG_EXPAND_HI);

        ADD_BITMAP(IDB_WDG_FLAG);
        ADD_BITMAP(IDB_WDG_CREDTYPE);
        ADD_BITMAP(IDB_FLAG_WARN);
        ADD_BITMAP(IDB_FLAG_EXPIRED);

        ADD_BITMAP(IDB_FLAG_CRITICAL);
        ADD_BITMAP(IDB_FLAG_RENEW);
        ADD_BITMAP(IDB_WDG_STUCK);
        ADD_BITMAP(IDB_WDG_STUCK_HI);

        ADD_BITMAP(IDB_WDG_STICK);
        ADD_BITMAP(IDB_WDG_STICK_HI);
        ADD_BITMAP(IDB_TK_SM);

#undef ADD_BITMAP
    }

    tbl->cursor_row = -1;
    tbl->scr_left = 0;
    tbl->scr_top = 0;
    tbl->ext_height = 0;
    tbl->ext_width = 0;

_exit:
    if(hc_cw)
        khc_close_space(hc_cw);
    if(hc_vs)
        khc_close_space(hc_vs);
    if(hc_cs)
        khc_close_space(hc_cs);
    if(clist)
        PFREE(clist);
    /* we leave hc_v held, because tbl->csp_view is the same handle.
       We keep that open until the view is unloaded. */
}

void 
cw_update_creds(khui_credwnd_tbl * tbl)
{
    kcdb_cred_comp_field * fields;
    kcdb_cred_comp_order comp_order;
    int i;
    khm_int32 n;
    khm_int32 delta;
    khm_handle hc;
    khm_int32 flags;

    if(!tbl->credset) {
        if(KHM_FAILED(kcdb_credset_create(&(tbl->credset))))
            return;
    }

    kcdb_credset_purge(tbl->credset);

    kcdb_identity_refresh_all();

    kcdb_credset_collect(
        tbl->credset,
        NULL,
        NULL,
        KCDB_CREDTYPE_ALL,
        &delta);

    /* now we need to figure out how to sort the credentials */
    fields = PMALLOC(sizeof(kcdb_cred_comp_field) * tbl->n_cols);
    ZeroMemory(fields, sizeof(kcdb_cred_comp_field) * tbl->n_cols);

    for(i=0, n=0; i<tbl->n_cols; i++) {
        if((tbl->cols[i].flags & KHUI_CW_COL_SORT_INC) ||
           (tbl->cols[i].flags & KHUI_CW_COL_SORT_DEC) ||
           (tbl->cols[i].flags & KHUI_CW_COL_GROUP)) {
            int si;
            /* we need to sort by this column */
            si = tbl->cols[i].sort_index;

            if(si < 0 || si >= (int) tbl->n_cols)
            {
                /* this shouldn't happen */
                tbl->cols[i].flags &= ~(KHUI_CW_COL_SORT_INC | 
                                        KHUI_CW_COL_SORT_DEC | 
                                        KHUI_CW_COL_GROUP);
                continue;
            }

            fields[si].attrib = tbl->cols[i].attr_id;
            if(tbl->cols[i].flags & KHUI_CW_COL_SORT_DEC)
                fields[si].order = KCDB_CRED_COMP_DECREASING;
            else
                fields[si].order = KCDB_CRED_COMP_INCREASING;

            /* special case.  if we are sorting by name, we group
               initial tickets before non-initial tickets.

               Also, if we are sorting by credential type name, then
               we allow the primary credential type first before
               others. */

            if (fields[si].attrib == KCDB_ATTR_NAME ||
                fields[si].attrib == KCDB_ATTR_TYPE_NAME)
                fields[si].order |= KCDB_CRED_COMP_INITIAL_FIRST;

            if(si >= n)
                n = si+1;
        }
    }

    /* we assume that the sort order is sane */
    /*TODO: don't assume; check if the sort order is sane */

    comp_order.nFields = n;
    comp_order.fields = fields;

    kcdb_credset_sort(tbl->credset, 
                      kcdb_cred_comp_generic, 
                      (void *) &comp_order);

    /* also, if new credentials were added, initialize the UI flag
       attribute to 0 */
    if(delta & KCDB_DELTA_ADD) {
        khm_size s;

        kcdb_credset_get_size(tbl->credset, &s);
        for(i=0;i< (int) s;i++) {
            if(KHM_FAILED(kcdb_credset_get_cred(tbl->credset,
                                                (khm_int32) i, &hc)))
                continue; /* lost a race */
            if(KHM_FAILED(kcdb_cred_get_attr(hc, khui_cw_flag_id, NULL, 
                                             NULL, NULL))) {
                flags = 0;
                kcdb_cred_set_attr(hc, khui_cw_flag_id, &flags, sizeof(flags));
            }
            kcdb_cred_release(hc);
        }
    }

    if (fields)
        PFREE(fields);
}

void 
cw_del_outline(khui_credwnd_outline *o) {
    khui_credwnd_outline * c;
    if(!o)
        return;

    /* the outline object is still in a list */
    if(o->next || o->prev)
        return;

    if(o->header)
        PFREE(o->header);

    if ((o->flags & KHUI_CW_O_DATAALLOC) &&
        o->data)
        PFREE(o->data);

    if ((o->flags & KHUI_CW_O_STICKY) &&
        o->data)
        kcdb_identity_release((khm_handle) o->data);

    LPOP(&(o->children), &c);
    while(c) {
        cw_del_outline(c);
        LPOP(&(o->children), &c);
    }

    PFREE(o);
}

khui_credwnd_outline * 
cw_new_outline_node(wchar_t * heading) {
    khui_credwnd_outline * o;
    size_t cblen;

    o = PMALLOC(sizeof(khui_credwnd_outline));
    ZeroMemory(o, sizeof(khui_credwnd_outline));
    
    if(SUCCEEDED(StringCbLength(heading, KHUI_MAXCB_HEADING, &cblen))) {
        cblen += sizeof(wchar_t);
        o->header = PMALLOC(cblen);
        StringCbCopy(o->header, cblen, heading);
    }

    return o;
}

khm_int32 
cw_get_cred_exp_flags(khui_credwnd_tbl * tbl, khm_handle cred)
{
    khm_int32 flags;
    long s;
    FILETIME ft;
    khm_size cbsize;

    cbsize = sizeof(ft);
    if(KHM_FAILED(kcdb_cred_get_attr(cred, KCDB_ATTR_TIMELEFT, NULL, &ft, &cbsize)))
        return 0;

    s = FtIntervalToSeconds(&ft);

    flags = 0;
    if(s < 0)
        flags = CW_EXPSTATE_EXPIRED;
    else if(s < tbl->threshold_critical)
        flags = CW_EXPSTATE_CRITICAL;
    else if(s < tbl->threshold_warn)
        flags = CW_EXPSTATE_WARN;
    else
        flags = CW_EXPSTATE_NONE;

    return flags;
}

void cw_update_outline(khui_credwnd_tbl * tbl);

VOID CALLBACK 
cw_timer_proc(HWND hwnd,
              UINT uMsg,
              UINT_PTR idEvent,
              DWORD dwTime)
{
    khui_credwnd_tbl * tbl;
    khui_credwnd_row * r;
    khm_int32 nflags;
    int nr;
    long ms;
    FILETIME ft;
    khm_size cbsize;

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);
    r = (khui_credwnd_row *) idEvent;

    nr = (int)(r - tbl->rows);

    if(nr < 0 || nr >= tbl->n_rows)
        return;

    if(!(r->flags & KHUI_CW_ROW_CRED))
        return; /* we only know what to do with cred rows */

    nflags = cw_get_cred_exp_flags(tbl, (khm_handle) r->data);
    if((r->flags & CW_EXPSTATE_MASK) != nflags) {
        /* flags have changed */
        /* the outline needs to be updated */
        cw_update_outline(tbl);
        InvalidateRect(tbl->hwnd, NULL, FALSE);
    } else {
        /* just invalidate the row */
        RECT r,rr,ri;

        GetClientRect(tbl->hwnd, &r);
        r.top += tbl->header_height;
        rr.top = r.top + (long)nr * tbl->cell_height - tbl->scr_top;
        rr.bottom = rr.top + tbl->cell_height;
        rr.left = r.left;
        rr.right = r.right;

        if(IntersectRect(&ri, &r, &rr))
            InvalidateRect(tbl->hwnd, &ri, FALSE);
    }

    cbsize = sizeof(ft);
    if(KHM_SUCCEEDED(kcdb_cred_get_attr((khm_handle) r->data,
                                        KCDB_ATTR_TIMELEFT, NULL,
                                        &ft, &cbsize))) {
        ms = FtIntervalMsToRepChange(&ft);
        if(ms > 0) {
            SetTimer(tbl->hwnd, (UINT_PTR) r, ms + 100, cw_timer_proc);
        }
    }
}

void 
cw_set_tbl_row_cred(khui_credwnd_tbl * tbl, 
                    int row, 
                    khm_handle cred, 
                    int col)
{
    FILETIME ft;
    long ms;
    khm_size cbsize;

    if((int) tbl->n_total_rows <= row) {
        /* we need to resize the allocation */
        khui_credwnd_row * newrows;
        int newsize;

        newsize = UBOUNDSS(row+1,KHUI_CW_ROW_INITIAL, KHUI_CW_ROW_INCREMENT);
        newrows = PMALLOC(sizeof(khui_credwnd_row) * newsize);
        memcpy(newrows, tbl->rows, sizeof(khui_credwnd_row) * tbl->n_rows);
        PFREE(tbl->rows);
        tbl->rows = newrows;
        tbl->n_total_rows = newsize;
    }

    tbl->rows[row].col = col;
    tbl->rows[row].data = cred;
    tbl->rows[row].flags = KHUI_CW_ROW_CRED;

    /* Set any required timer events */
    cbsize = sizeof(ft);
    if(KHM_SUCCEEDED(kcdb_cred_get_attr(cred, KCDB_ATTR_TIMELEFT, NULL, &ft, &cbsize))) {
        ms = FtIntervalMsToRepChange(&ft);
        if(ms > 0) {
            SetTimer(tbl->hwnd, (UINT_PTR) &(tbl->rows[row]), ms + 100, cw_timer_proc);
            tbl->rows[row].flags |= KHUI_CW_ROW_TIMERSET;
        }
    }
}

void 
cw_set_tbl_row_header(khui_credwnd_tbl * tbl, 
                      int row, int col, 
                      khui_credwnd_outline * o)
{
    if((int) tbl->n_total_rows <= row) {
        /* we need to resize the allocation */
        khui_credwnd_row * newrows;
        int newsize;

        newsize = UBOUNDSS(row+1,KHUI_CW_ROW_INITIAL, KHUI_CW_ROW_INCREMENT);
        newrows = PMALLOC(sizeof(khui_credwnd_row) * newsize);
        memcpy(newrows, tbl->rows, sizeof(khui_credwnd_row) * tbl->n_rows);
        PFREE(tbl->rows);
        tbl->rows = newrows;
        tbl->n_total_rows = newsize;
    }

    tbl->rows[row].col = col;
    tbl->rows[row].data = (khm_handle) o;
    tbl->rows[row].flags = KHUI_CW_ROW_HEADER;
    if(o->flags & KHUI_CW_O_SELECTED)
        tbl->rows[row].flags |= KHUI_CW_ROW_SELECTED;
}

static int 
iwcscmp(const void * p1, const void * p2) {
    const wchar_t * s1 = *(wchar_t **) p1;
    const wchar_t * s2 = *(wchar_t **) p2;

    return wcscmp(s1, s2);
}

void 
cw_update_outline(khui_credwnd_tbl * tbl)
{
    int i,j,n_rows;
    int level;
    int visible;
    khm_size n_creds = 0;
    khm_handle prevcred = NULL;
    khm_handle thiscred = NULL;
    /* grouping[0..n_grouping-1] are the columns that we are going to
       group the display by.  Say we are grouping by identity and then
       by type, then grouping[0]=col# of identity and grouping[1]=col#
       of type */
    khm_int32 * grouping = NULL;
    khui_credwnd_outline * ol = NULL;
    int n_grouping;
    wchar_t buf[256];
    khm_size cbbuf;
    khm_int32 flags;
    int selected;
    khm_int32 expstate = 0;

    /*  this is called after calling cw_update_creds, so we assume
        that the credentials are all loaded and sorted according to
        grouping rules  */

    /* if the columns have changed, then any outline info we have
       cached are unreliable */
    if(tbl->flags & KHUI_CW_TBL_COL_DIRTY) {
        khui_credwnd_outline * o;
        LPOP(&(tbl->outline), &o);
        while(o) {
            cw_del_outline(o);
            LPOP(&(tbl->outline), &o);
        }
        tbl->n_rows = 0;
    }

    /* Otherwise, we should reset the outline indices.  Just the first
       level is enough */
    if (tbl->outline) {
        khui_credwnd_outline * o;

        o = tbl->outline;
        while(o) {
            o->start = -1;
            o = LNEXT(o);
        }
    }

    /* determine the grouping order */
    grouping = PMALLOC(sizeof(khm_int32) * tbl->n_cols);
    for(i=0; i < (int) tbl->n_cols; i++)
        grouping[i] = -1;
    n_grouping = 0;

    for(i=0; i < (int) tbl->n_cols; i++) {
        /* since cw_update_creds has run, the KHUI_CW_COL_GROUP flag
           only exists for columns that has a valid sort_index */
        if(tbl->cols[i].flags & KHUI_CW_COL_GROUP) {
            grouping[tbl->cols[i].sort_index] = i;
            if(n_grouping <= tbl->cols[i].sort_index)
                n_grouping = tbl->cols[i].sort_index + 1;
        }
    }

    /* if we have sorted by an index without grouping by it, we can't
       establish any grouping beyond that index. */
    for(i=0; i < n_grouping; i++) {
        if(grouping[i] == -1)
            break;
    }
    n_grouping = i;

    if(!tbl->rows) {
        /* we haven't allocated memory yet */
        tbl->n_total_rows = KHUI_CW_ROW_INITIAL;
        tbl->n_rows = 0;
        tbl->rows = PMALLOC(sizeof(khui_credwnd_row) * tbl->n_total_rows);
    } else {
        /* kill any pending timers */
        for(i=0; i < (int) tbl->n_rows; i++) 
            if(tbl->rows[i].flags & KHUI_CW_ROW_TIMERSET)
            {
                KillTimer(tbl->hwnd, (UINT_PTR) &(tbl->rows[i]));
                tbl->rows[i].flags &= ~KHUI_CW_ROW_TIMERSET;
            }
    }

    if(KHM_FAILED(kcdb_credset_get_size(tbl->credset, &n_creds)))
        goto _exit;

    n_rows = 0;
    prevcred = NULL;
    ol = NULL;

    for(i=0; i < (int) n_creds; i++) {
        if(KHM_FAILED(kcdb_credset_get_cred(tbl->credset, i, &thiscred)))
            continue;

        /* if this credential appears to be the same as another for
           this view, we skip it */
        if(prevcred) {
            for(j=0; j < (int) tbl->n_cols; j++) {
                if(kcdb_creds_comp_attr(prevcred, thiscred,
                                        tbl->cols[j].attr_id))
                    break;
            }

            if(j >= (int) tbl->n_cols) {
                if (n_rows > 0) {
                    tbl->rows[n_rows - 1].idx_end = i;
                }
                continue;
            }
        }

        if(!prevcred)
            level = 0;
        else {
            for(j=0; j < n_grouping; j++) {
                /* determine the grouping level at which thiscred
                   differs from prevcred */
                if(kcdb_creds_comp_attr(prevcred,thiscred,
                                        tbl->cols[grouping[j]].attr_id))
                    break;
            }
            level = j;
        }

        /* now we have to walk up until we get to the parent of the
           outline level we should be in */
        while(ol && ol->level >= level) {
            ol->length = n_rows - ol->start;
            ol->idx_end = i - 1;
            ol = TPARENT(ol);
        }

        if(ol) {
            visible = (ol->flags & KHUI_CW_O_VISIBLE) && 
                (ol->flags & KHUI_CW_O_EXPAND);
            selected = (ol->flags & KHUI_CW_O_SELECTED);
        } else {
            visible = TRUE;
            selected = FALSE;
        }

        /* now ol points to an outline node at the next highest level
           or is NULL if level = 0 */

        for(j=level; j < n_grouping; j++) {
            khui_credwnd_outline * to;
            /*  now we search for an outline object at the next level
                which matches the heading */
            cbbuf = sizeof(buf);
            buf[0] = L'\0';
            if(KHM_FAILED
               (kcdb_cred_get_attr_string(thiscred, 
                                          tbl->cols[grouping[j]].attr_id, 
                                          buf, &cbbuf, 0))) {
                cbbuf = sizeof(wchar_t);
                buf[0] = L'\0';
            }

            if(ol)
                to = TFIRSTCHILD(ol);
            else
                to = tbl->outline;

            while(to) {
                if(!wcscmp(buf, to->header))
                    break;
                to = LNEXT(to);
            }

            if(to) {
                /* found it */
                ol = to;
            } else {
                /* not found. create */
                to = cw_new_outline_node(buf);
                if(ol) {
                    TADDCHILD(ol, to);
                } else {
                    LPUSH(&(tbl->outline), to);
                }
                ol = to;
                ol->flags = KHUI_CW_O_EXPAND;
                ol->level = j;
                ol->col = grouping[j];

                if(tbl->cols[grouping[j]].attr_id == KCDB_ATTR_ID_NAME) {
                    khm_handle h;
                    if(KHM_SUCCEEDED(kcdb_identity_create(buf, 0, &h))) {
                        ol->attr_id = KCDB_ATTR_ID;
                        ol->data = (void *) h;

                        /* the outline only lasts as long as the
                           credential, and the credential has a hold
                           on the identity. */
                        kcdb_identity_release(h);
                    }
                    else
                        ol->data = 0;
                } else if(tbl->cols[grouping[j]].attr_id == 
                          KCDB_ATTR_TYPE_NAME) {
                    khm_int32 t;

                    ol->attr_id = KCDB_ATTR_TYPE;
                    if(KHM_SUCCEEDED(kcdb_cred_get_type(thiscred, &t)))
                        ol->data = (void *)(ssize_t) t;
                    else
                        ol->data = (void *)(ssize_t) KCDB_CREDTYPE_INVALID;
                } else {
                    khm_int32 rv;
                    khm_int32 alt_id;
                    kcdb_attrib * attrib;

                    rv = 
                        kcdb_attrib_get_info(tbl->cols[grouping[j]].attr_id,
                                             &attrib);
                    assert(KHM_SUCCEEDED(rv));

                    if (attrib->flags & KCDB_ATTR_FLAG_ALTVIEW)
                        alt_id = attrib->alt_id;
                    else
                        alt_id = tbl->cols[grouping[j]].attr_id;

                    ol->attr_id = alt_id;

                    kcdb_attrib_release_info(attrib);

                    rv = kcdb_cred_get_attr(thiscred,
                                            alt_id,
                                            NULL,
                                            NULL,
                                            &cbbuf);
                    if (rv != KHM_ERROR_TOO_LONG || cbbuf == 0) {
                        ol->data = NULL;
                    } else {
                        ol->data = PMALLOC(cbbuf);
                        assert(ol->data);
                        rv = kcdb_cred_get_attr(thiscred,
                                                alt_id,
                                                NULL,
                                                ol->data,
                                                &cbbuf);
                        assert(KHM_SUCCEEDED(rv));
                        ol->cb_data = cbbuf;
                        ol->flags |= KHUI_CW_O_DATAALLOC;
                    }
                }
            }

            /* now ol points at the node at level j we want to be
               in */
            ol->start = n_rows;
            ol->idx_start = i;
            ol->length = 0;
            ol->flags &= ~CW_EXPSTATE_MASK;
            ol->flags &= ~KHUI_CW_O_SHOWFLAG;
            ol->flags &= ~KHUI_CW_O_STICKY;

            if(selected) {
                ol->flags |= KHUI_CW_O_SELECTED;
            }
            if(visible) {
                cw_set_tbl_row_header(tbl, n_rows, grouping[j], ol);
                n_rows ++;
                ol->flags |= KHUI_CW_O_VISIBLE;
            } else {
                ol->flags &= ~KHUI_CW_O_VISIBLE;
            }
            visible = visible && (ol->flags & KHUI_CW_O_EXPAND);
            selected = (selected || (ol->flags & KHUI_CW_O_SELECTED));
        }
        
        /* we need to do this here too just in case we were already at
           the level we were supposed to be in */
        if (ol)
            visible = visible && (ol->flags & KHUI_CW_O_EXPAND);

        flags = cw_get_cred_exp_flags(tbl, thiscred);
        expstate |= flags;

        if(visible) {
            khm_int32 c_flags;

            cw_set_tbl_row_cred(tbl, n_rows, thiscred, 
                                grouping[n_grouping-1]);
            kcdb_cred_get_flags(thiscred, &c_flags);
            if(flags) {
                tbl->rows[n_rows].flags |= flags;
            }
            if(selected ||
               (c_flags & KCDB_CRED_FLAG_SELECTED))
                tbl->rows[n_rows].flags |= KHUI_CW_ROW_SELECTED;
            tbl->rows[n_rows].idx_start = i;
            tbl->rows[n_rows].idx_end = i;

            n_rows++;
        } else if(flags) {
            khui_credwnd_outline *to;
            /* the row that is flagged is not visible.  We need to send
               the flag upstream until we hit a visible outline node */
            to = ol;
            while(to && !(to->flags & KHUI_CW_O_VISIBLE)) {
                to = TPARENT(to);
            }
            if(to) {
                to->flags |= KHUI_CW_O_SHOWFLAG;
            }
        }

        /* and we propagate the flags upstream */
        if(flags) {
            khui_credwnd_outline *to;

            to = ol;
            while(to) {
                if((to->flags & CW_EXPSTATE_MASK) < flags) {
                    to->flags = (to->flags & ~CW_EXPSTATE_MASK) | flags;
                }
                to = TPARENT(to);
            }
        }

        if(prevcred)
            kcdb_cred_release(prevcred);
        prevcred = thiscred;
    }

    while(ol) {
        ol->length = n_rows - ol->start;
        ol->idx_end = i - 1;
        ol = TPARENT(ol);
    }

    if(prevcred) {
        kcdb_cred_release(prevcred);
        prevcred = NULL;
    }

    /* Add any sticky identities that we haven't seen yet */
    if (n_grouping > 0 && 
        tbl->cols[grouping[0]].attr_id == KCDB_ATTR_ID_NAME) {

        khui_credwnd_outline * o;
        wchar_t * idnames = NULL;
        wchar_t * t;
        khm_size n_idents;
        khm_size cb_names;
        wchar_t ** idarray = NULL;
        int i;

        if (kcdb_identity_enum(KCDB_IDENT_FLAG_STICKY,
                               KCDB_IDENT_FLAG_STICKY,
                               NULL,
                               &cb_names,
                               &n_idents) != KHM_ERROR_TOO_LONG ||
            n_idents == 0 ||
            cb_names == 0)
            goto _cleanup_sticky;

        idnames = PMALLOC(cb_names);
        idarray = PMALLOC(n_idents * sizeof(*idarray));
#ifdef DEBUG
        assert(idnames);
        assert(idarray);
#endif

        if (KHM_FAILED(kcdb_identity_enum(KCDB_IDENT_FLAG_STICKY,
                                          KCDB_IDENT_FLAG_STICKY,
                                          idnames,
                                          &cb_names,
                                          &n_idents)))
            goto _cleanup_sticky;

        for (i=0, t=idnames; t && *t; t = multi_string_next(t), i++) {
            idarray[i] = t;
        }

        qsort(idarray, n_idents, sizeof(*idarray), iwcscmp);

        for (i=0; i < (int) n_idents; i++) {
            khm_handle h;

            if (KHM_FAILED(kcdb_identity_create(idarray[i], 
                                                KCDB_IDENT_FLAG_CREATE, &h)))
                continue;

            for (o = tbl->outline; o; o = LNEXT(o)) {
                if (!wcscmp(idarray[i], o->header))
                    break;
            }

            if (o) {
                /* found it */
                if (o->start != -1) /* already visible? */
                    continue;
                o->flags &= KHUI_CW_O_STICKY;
                o->flags |= KHUI_CW_O_VISIBLE;
            } else {
                /* not found.  create */
                o = cw_new_outline_node(idarray[i]);
                o->flags = KHUI_CW_O_VISIBLE;
                o->level = 0;
                o->col = grouping[0];
                o->data = (void *) h;
            }

            if (o->flags & KHUI_CW_O_STICKY)
                kcdb_identity_release(h);
            else
                /* leave identity held in this case */
                o->flags |= KHUI_CW_O_STICKY;

            o->flags &= ~KHUI_CW_O_EXPAND;
            o->start = n_rows;
            o->length = 1;
            o->idx_start = -1;

            cw_set_tbl_row_header(tbl, n_rows, grouping[0], o);

            n_rows ++;
        }

    _cleanup_sticky:
        if (idnames)
            PFREE(idnames);
        if (idarray)
            PFREE(idarray);
    }

    tbl->n_rows = n_rows;
    tbl->flags |= KHUI_CW_TBL_ROW_DIRTY;

    tbl->flags &= ~KHUI_CW_TBL_COL_DIRTY;

    if (tbl->cursor_row >= tbl->n_rows)
        tbl->cursor_row = tbl->n_rows - 1;
    if (tbl->cursor_row < 0)
        tbl->cursor_row = 0;
_exit:
    if(grouping)
        PFREE(grouping);

    if (n_creds == 0)
        khm_notify_icon_expstate(KHM_NOTIF_EMPTY);
    else if (expstate & CW_EXPSTATE_EXPIRED)
        khm_notify_icon_expstate(KHM_NOTIF_EXP);
    else if ((expstate & CW_EXPSTATE_WARN) ||
             (expstate & CW_EXPSTATE_CRITICAL))
        khm_notify_icon_expstate(KHM_NOTIF_WARN);
    else
        khm_notify_icon_expstate(KHM_NOTIF_OK);
}

void 
cw_unload_view(khui_credwnd_tbl * tbl)
{
#define SafeDeleteObject(o) \
    do { \
        if(o) { \
            DeleteObject(o); \
            o = NULL; \
        } \
    } while(0)

    SafeDeleteObject(tbl->hf_header);
    SafeDeleteObject(tbl->hf_normal);
    SafeDeleteObject(tbl->hf_bold);
    SafeDeleteObject(tbl->hf_bold_header);
    SafeDeleteObject(tbl->hb_grey);
    SafeDeleteObject(tbl->hb_normal);
    SafeDeleteObject(tbl->hb_sel);
    SafeDeleteObject(tbl->hb_hdr_bg);
    SafeDeleteObject(tbl->hb_hdr_bg_sel);
    SafeDeleteObject(tbl->hb_hdr_bg_crit);
    SafeDeleteObject(tbl->hb_hdr_bg_exp);
    SafeDeleteObject(tbl->hb_hdr_bg_warn);
    SafeDeleteObject(tbl->hb_hdr_bg_def);

#undef SafeDeleteObject

    if(tbl->credset) {
        kcdb_credset_delete(tbl->credset);
        tbl->credset = NULL;
    }
    if(tbl->ilist) {
        khui_delete_ilist(tbl->ilist);
        tbl->ilist = NULL;
    }

    if(tbl->cols) {
        int i;

        for(i=0; i < tbl->n_cols; i++) {
            if(tbl->cols[i].title)
                PFREE(tbl->cols[i].title);
            Header_DeleteItem(tbl->hwnd_header, 0);

            if (tbl->cols[i].attr_id >= 0 &&
                tbl->cols[i].attr_id <= KCDB_ATTR_MAX_ID &&
                attr_to_action[tbl->cols[i].attr_id]) {

                khui_check_action(attr_to_action[tbl->cols[i].attr_id], FALSE);

            }
        }
        PFREE(tbl->cols);
        tbl->cols = NULL;
        tbl->n_cols = 0;
        tbl->n_total_cols = 0;

        kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);
    }

    if(tbl->rows) {
        PFREE(tbl->rows);
        tbl->rows = NULL;
        tbl->n_rows = 0;
        tbl->n_total_rows = 0;
    }

    khui_delete_bitmap(&tbl->kbm_logo_shade);

    if (tbl->csp_view) {
        khc_close_space(tbl->csp_view);
        tbl->csp_view = NULL;
    }
}

void 
cw_hditem_from_tbl_col(khui_credwnd_col * col, HDITEM *phi)
{
    size_t cchsize;

    phi->mask = HDI_FORMAT | HDI_LPARAM | HDI_WIDTH;
    if(cw_is_custom_attr(col->attr_id)) {
        if(col->attr_id == CW_CA_FLAGS) {
            phi->fmt = 0;
        } else if(col->attr_id == CW_CA_TYPEICON) {
            phi->fmt = 0;
        } else {
            /* what the? */
            /*TODO: throw up and die */
        }
    } else {
        phi->mask |= HDI_TEXT;
        phi->pszText = col->title;
        StringCchLength(col->title, KCDB_MAXCCH_SHORT_DESC, &cchsize);
        phi->cchTextMax = (int) cchsize;
        phi->fmt = HDF_CENTER | HDF_STRING;
    }
    phi->lParam = col->attr_id;
#if (_WIN32_WINNT >= 0x501)
    if (IS_COMMCTL6()) {
        if(col->flags & KHUI_CW_COL_SORT_INC) {
            phi->fmt |= HDF_SORTUP;
        } else if(col->flags & KHUI_CW_COL_SORT_DEC) {
            phi->fmt |= HDF_SORTDOWN;
        }
    }
#endif
    if(col->width < 0) {
        /*TODO: come up with a better way to handle this case */
        col->width = 200;
    }
    phi->cxy = col->width;
}

/* returns a bitmask indicating which measures were changed */
int 
cw_update_extents(khui_credwnd_tbl * tbl, 
                  khm_boolean update_scroll) {
    int ext_x, ext_y;
    int i;

    ext_x = 0;
    for(i=0; i < (int) tbl->n_cols; i++) {
        tbl->cols[i].x = ext_x;
        ext_x += tbl->cols[i].width;
    }

    if(!tbl->cell_height) {
        HDC dc;
        HFONT hfold;
        SIZE size;
        size_t cbbuf;
        wchar_t buf[64];

        dc = GetWindowDC(tbl->hwnd);
        if(tbl->hf_normal)
            hfold = SelectFont(dc, tbl->hf_normal);

        LoadString(khm_hInstance, IDS_SAMPLE_STRING, buf, sizeof(buf)/sizeof(buf[0]));
        StringCchLength(buf, sizeof(buf)/sizeof(buf[0]), &cbbuf);
        GetTextExtentPoint32(dc, buf, (int) cbbuf, &size);

        if(tbl->hf_normal)
            SelectFont(dc,hfold);
        ReleaseDC(tbl->hwnd, dc);

        tbl->cell_height = size.cy + tbl->vpad * 2;
    }

    ext_y = (int) tbl->n_rows * tbl->cell_height;

    tbl->ext_width = ext_x;
    tbl->ext_height = ext_y;

    /* useful in the future when implementing variable height rows.
       The KHUI_CW_TBL_ROW_DIRTY bit indicates that the rows have
       changed and that the y extent has to be recalculated. */
    tbl->flags &= ~KHUI_CW_TBL_ROW_DIRTY;

    if(update_scroll) {
        RECT r;
        int cl_w;
        int cl_h;
        SCROLLINFO si;
        WINDOWPOS pw;
        HDLAYOUT hdl;

        /* update the header control first */

    retry_update_scroll:
        GetClientRect(tbl->hwnd, &r);

        cl_w = r.right - r.left;
        cl_h = (r.bottom - r.top);
        cl_h -= tbl->header_height;

        if(tbl->scr_top < 0 || tbl->ext_height < cl_h)
            tbl->scr_top = 0;
        else if(tbl->scr_top > tbl->ext_height - cl_h)
            tbl->scr_top = tbl->ext_height - cl_h;
        if(tbl->scr_left < 0 || tbl->ext_width < cl_w)
            tbl->scr_left = 0;
        else if(tbl->scr_left > tbl->ext_width - cl_w)
            tbl->scr_left = tbl->ext_width - cl_w;

        /* adjustments for scrolling */
        r.left -= tbl->scr_left;
        r.right = max(tbl->ext_width + r.left, r.right);

        hdl.prc = &r;
        hdl.pwpos = &pw;

        Header_Layout(tbl->hwnd_header, &hdl);

        if(tbl->header_height == 0) {
            tbl->header_height = pw.cy;
            goto retry_update_scroll;
        } else
            tbl->header_height = pw.cy;

        SetWindowPos(
            tbl->hwnd_header, 
            pw.hwndInsertAfter, 
            pw.x, 
            pw.y, 
            pw.cx, 
            pw.cy, 
            pw.flags);

        si.cbSize = sizeof(si);
        si.nMin = 0;
        si.nMax = tbl->ext_height;
        si.nPage = cl_h;
        si.nPos = tbl->scr_top;
        si.fMask = SIF_ALL | SIF_DISABLENOSCROLL;
        SetScrollInfo(tbl->hwnd, SB_VERT, &si, TRUE);

        si.cbSize = sizeof(si);
        si.nMin = 0;
        si.nMax = tbl->ext_width;
        si.nPage = cl_w;
        si.nPos = tbl->scr_left;
        si.fMask = SIF_ALL | SIF_DISABLENOSCROLL;
        SetScrollInfo(tbl->hwnd, SB_HORZ, &si, TRUE);
    }

    return 0;
}

void 
cw_insert_header_cols(khui_credwnd_tbl * tbl) {
    HWND hdr;
    HDITEM hi;
    int i;

    hdr = tbl->hwnd_header;
    
    for(i=0; i < (int) tbl->n_cols; i++) {
        cw_hditem_from_tbl_col(&(tbl->cols[i]), &hi);
        Header_InsertItem(hdr, 512, &hi);
    }
}

#define CW_ER_BLANK 0
#define CW_ER_GREY  1
#define CW_ER_SEL   2

void 
cw_erase_rect(HDC hdc, 
              khui_credwnd_tbl * tbl, 
              RECT * r_wnd, 
              RECT * r_erase, 
              int type)
{
    RECT rlogo;
    RECT ri;
    RECT t;
    BOOL rie;
    HBRUSH hbr;

    if(RectVisible(hdc, r_erase)) {

        switch(type) {
        case CW_ER_BLANK:
            hbr = tbl->hb_normal;
            break;

        case CW_ER_GREY:
            hbr = tbl->hb_grey;
            break;

        case CW_ER_SEL:
            hbr = tbl->hb_sel;
            break;

        default:
                return;
        }

        if(tbl->kbm_logo_shade.cx != -1 && type == CW_ER_BLANK) {
            rlogo.left = r_wnd->right - tbl->kbm_logo_shade.cx;
            rlogo.right = r_wnd->right;
            rlogo.top = r_wnd->bottom - tbl->kbm_logo_shade.cy;
            rlogo.bottom = r_wnd->bottom;
            rie = IntersectRect(&ri, r_erase, &rlogo);
        } else {
            rie = FALSE;
        }

        if(!rie) {
            FillRect(hdc, r_erase, hbr);
        } else {
            HDC hdcb = CreateCompatibleDC(hdc);
            HBITMAP hbmold = SelectObject(hdcb, tbl->kbm_logo_shade.hbmp);

            BitBlt(hdc, ri.left, ri.top, ri.right - ri.left, ri.bottom - ri.top,
                hdcb, ri.left - rlogo.left, ri.top - rlogo.top, SRCCOPY);
            
            SelectObject(hdcb, hbmold);
            DeleteDC(hdcb);

            if(r_erase->top < ri.top && r_erase->left < ri.left) {
                t.left = r_erase->left;
                t.top = r_erase->top;
                t.right = ri.left;
                t.bottom = ri.top;
                FillRect(hdc, &t, hbr);
            }

            if(r_erase->left < ri.left) {
                t.left = r_erase->left;
                t.top = ri.top;
                t.right = ri.left;
                t.bottom = ri.bottom;
                FillRect(hdc, &t, hbr);
            }

            if(r_erase->top < ri.top) {
                t.left = ri.left;
                t.top = r_erase->top;
                t.right = ri.right;
                t.bottom = ri.top;
                FillRect(hdc, &t, hbr);
            }
        }
    }
}

void 
cw_draw_header(HDC hdc, 
               khui_credwnd_tbl * tbl, 
               int row, 
               RECT * r)
{
    int colattr;
    HPEN pl, pold;
    khui_credwnd_row * cr;
    khui_credwnd_outline * o;
    int selected = 0;
    khm_int32 idf = 0;

    /* each header consists of a couple of widgets and some text */
    /* we need to figure out the background color first */
    
    cr = &(tbl->rows[row]);
    o = (khui_credwnd_outline *) cr->data;

    colattr = tbl->cols[cr->col].attr_id;

    if (colattr == KCDB_ATTR_ID_NAME) {
        khm_handle ident = o->data;

        kcdb_identity_get_flags(ident, &idf);
    }

    selected = o->flags & KHUI_CW_O_SELECTED;

    {
        HBRUSH hbr;
        if(selected)
            hbr = tbl->hb_hdr_bg_sel;
        else if ((o->flags & CW_EXPSTATE_MASK) == CW_EXPSTATE_EXPIRED)
            hbr = tbl->hb_hdr_bg_exp;
        else if ((o->flags & CW_EXPSTATE_MASK) == CW_EXPSTATE_CRITICAL)
            hbr = tbl->hb_hdr_bg_crit;
        else if ((o->flags & CW_EXPSTATE_MASK) == CW_EXPSTATE_WARN)
            hbr = tbl->hb_hdr_bg_warn;
        else if (idf & KCDB_IDENT_FLAG_DEFAULT)
            hbr = tbl->hb_hdr_bg_def;
        else
            hbr = tbl->hb_hdr_bg;

        FillRect(hdc, r, hbr);
    }

    pl = CreatePen(PS_SOLID, 0, tbl->cr_hdr_outline);
    pold = SelectObject(hdc, pl);
    MoveToEx(hdc, r->left, r->bottom - 1, NULL);
    LineTo(hdc,r->right,r->bottom - 1);
    SelectObject(hdc, pold);
    DeleteObject(pl);

    if (o->flags & KHUI_CW_O_STICKY) {
        /* khui_ilist_draw_id(tbl->ilist, IDB_TK_NEW_SM, hdc, 
           r->left, r->bottom - KHUI_SMICON_CY, 0); */
    } else if((tbl->mouse_state & CW_MOUSE_WOUTLINE) && 
              tbl->mouse_row == row) {
        if(o->flags & KHUI_CW_O_EXPAND) {
            khui_ilist_draw_id(tbl->ilist, IDB_WDG_EXPAND_HI,
                               hdc, r->left, r->bottom - KHUI_SMICON_CY, 0);
        } else {
            khui_ilist_draw_id(tbl->ilist, IDB_WDG_COLLAPSE_HI,
                               hdc, r->left, r->bottom - KHUI_SMICON_CY, 0);
        }
    } else {
        if(o->flags & KHUI_CW_O_EXPAND) {
            khui_ilist_draw_id(tbl->ilist, IDB_WDG_EXPAND,
                               hdc, r->left, r->bottom - KHUI_SMICON_CY, 0);
        } else {
            khui_ilist_draw_id(tbl->ilist, IDB_WDG_COLLAPSE,
                               hdc, r->left, r->bottom - KHUI_SMICON_CY, 0);
        }
    }

    r->left += KHUI_SMICON_CX * 3 / 2;

    /* try to draw the icon, if there is one */
    if(colattr == KCDB_ATTR_ID_NAME) {

        khui_ilist_draw_id(tbl->ilist,
                           (((tbl->mouse_state & CW_MOUSE_WSTICKY) &&
                             tbl->mouse_row == row)?
                            ((idf & KCDB_IDENT_FLAG_STICKY)?
                             IDB_WDG_STUCK_HI:
                             IDB_WDG_STICK_HI):
                            ((idf & KCDB_IDENT_FLAG_STICKY)?
                             IDB_WDG_STUCK:
                             IDB_WDG_STICK)),
                           hdc,
                           r->left, r->bottom - KHUI_SMICON_CY,
                           0);

        r->left += KHUI_SMICON_CX * 3 / 2;

        khui_ilist_draw_id(tbl->ilist, 
                           ((o->flags & KHUI_CW_O_STICKY)?
                            IDB_ID_DIS_SM:
                            IDB_ID_SM), 
                           hdc, 
                           r->left, r->bottom - KHUI_SMICON_CY, 
                           0);
        r->left += KHUI_SMICON_CX * 3 / 2 ;
    }

    /* ok, now o->header contains the string representation of the
       outline value */
    /* for now just write out the value */
    SetTextAlign(hdc, TA_BOTTOM | TA_LEFT);

    if(selected)
        SetTextColor(hdc, tbl->cr_hdr_sel);
    else
        SetTextColor(hdc, tbl->cr_hdr_normal);

    TextOut(hdc, r->left, r->bottom - tbl->vpad, o->header, (int) wcslen(o->header));

    if (colattr == KCDB_ATTR_ID_NAME &&
        (idf & KCDB_IDENT_FLAG_DEFAULT)) {
        wchar_t defstr[64];
        SIZE size;

        LoadString(khm_hInstance, IDS_CW_DEFAULT,
                   defstr, ARRAYLENGTH(defstr));

        GetTextExtentPoint32(hdc, o->header, (int) wcslen(o->header),
                             &size);

        r->left += size.cx + KHUI_SMICON_CX * 2;

        TextOut(hdc, r->left, r->bottom - tbl->vpad, 
                defstr, (int) wcslen(defstr));
    }
}

LRESULT 
cw_handle_header_msg(khui_credwnd_tbl * tbl, LPNMHEADER ph) {
    RECT r;
    HDITEM hi;

    switch(ph->hdr.code) {
        /*TODO:Make it track smoother */
    case HDN_BEGINTRACK:
        {
            ZeroMemory(&hi, sizeof(hi));
            hi.mask = HDI_ORDER;
            Header_GetItem(tbl->hwnd_header, ph->iItem, &hi);

            if(tbl->cols[hi.iOrder].flags & KHUI_CW_COL_FIXED_WIDTH)
                return TRUE;
            else
                return FALSE;
        }

    case HDN_TRACK:
    case HDN_ENDTRACK:
        {
            int width;
            hi.mask = HDI_ORDER;
            Header_GetItem(ph->hdr.hwndFrom, ph->iItem, &hi);
            Header_GetItemRect(ph->hdr.hwndFrom, ph->iItem, &r);
            width = r.right - r.left;
            if(width != tbl->cols[hi.iOrder].width) {
                tbl->cols[hi.iOrder].width = width;
                cw_update_extents(tbl, TRUE);
                InvalidateRect(tbl->hwnd, NULL, FALSE);
            }
        }
        break;

    case HDN_BEGINDRAG:
        {

            ZeroMemory(&hi, sizeof(hi));
            hi.mask = HDI_ORDER;
            Header_GetItem(tbl->hwnd_header, ph->iItem, &hi);

            if (tbl->cols[hi.iOrder].flags & KHUI_CW_COL_FIXED_WIDTH) {
                return TRUE;
            } else {
                return FALSE;
            }
        }
        break;

    case HDN_ENDDRAG:
        {
            int drag_start_index;
            int drag_end_index;
            int i;
            khui_credwnd_col tcol;
            int sort_index = 0;
            khm_int32 old_flags;

            if (ph->pitem == NULL)
                return TRUE;

            hi.mask = HDI_ORDER;
            Header_GetItem(tbl->hwnd_header, ph->iItem, &hi);
            drag_start_index = hi.iOrder;
            drag_end_index = ph->pitem->iOrder;

            /* the user dragged the column which was at drag_start_index
               to drag_end_index. */

            if (drag_end_index == drag_start_index)
                return TRUE;

            /* we don't allow dragging in to the "fixed" area. */
            for (i=0; i < tbl->n_cols; i++) {
                if (tbl->cols[i].attr_id >= 0)
                    break;
            }

            if (drag_end_index <= i)
                return TRUE;
 
            tcol = tbl->cols[drag_start_index];
            if (drag_end_index < drag_start_index) {
                MoveMemory(&tbl->cols[drag_end_index + 1],
                           &tbl->cols[drag_end_index],
                           sizeof(tbl->cols[0]) *
                           (drag_start_index - drag_end_index));
            } else {
                MoveMemory(&tbl->cols[drag_start_index],
                           &tbl->cols[drag_start_index + 1],
                           sizeof(tbl->cols[0]) *
                           (drag_end_index - drag_start_index));
            }
            tbl->cols[drag_end_index] = tcol;

            old_flags = tbl->cols[drag_end_index].flags;

            if (drag_end_index < tbl->n_cols - 1) {
                khm_int32 tflags = tbl->cols[drag_end_index + 1].flags;

                if (tflags & KHUI_CW_COL_GROUP) {
                    tbl->cols[drag_end_index].flags |= KHUI_CW_COL_GROUP;
                }

                if ((tflags & (KHUI_CW_COL_SORT_INC | KHUI_CW_COL_SORT_DEC)) &&
                    !(old_flags & (KHUI_CW_COL_SORT_INC | KHUI_CW_COL_SORT_DEC)))
                    tbl->cols[drag_end_index].flags |= KHUI_CW_COL_SORT_INC;
            }

            if (drag_end_index > 0) {
                khm_int32 tflags = tbl->cols[drag_end_index - 1].flags;

                if (!(tflags & KHUI_CW_COL_GROUP))
                    tbl->cols[drag_end_index].flags &= ~KHUI_CW_COL_GROUP;

                if (!(tflags & (KHUI_CW_COL_SORT_INC | KHUI_CW_COL_SORT_DEC)))
                    tbl->cols[drag_end_index].flags &=
                        ~(KHUI_CW_COL_SORT_INC | KHUI_CW_COL_SORT_DEC);
            }

            if (old_flags != tbl->cols[drag_end_index].flags) {
                cw_hditem_from_tbl_col(&tbl->cols[drag_end_index], &hi);
                hi.mask = HDI_FORMAT;
                Header_SetItem(tbl->hwnd_header, ph->iItem, &hi);
            }

            if ((old_flags ^ tbl->cols[drag_end_index].flags) &
                KHUI_CW_COL_GROUP)
                tbl->flags |= KHUI_CW_TBL_COL_DIRTY;

            for (i=0; i < tbl->n_cols; i++) {
                if (tbl->cols[i].attr_id < 0)
                    continue;

                if (tbl->cols[i].flags &
                    (KHUI_CW_COL_GROUP |
                     KHUI_CW_COL_SORT_INC |
                     KHUI_CW_COL_SORT_DEC))
                    tbl->cols[i].sort_index = sort_index++;
                else
                    break;
            }

            tbl->flags |= KHUI_CW_TBL_CUSTVIEW;

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, TRUE);

            InvalidateRect(tbl->hwnd, NULL, FALSE);

            return FALSE;
        }
        break;

    case HDN_ITEMCLICK:
        {
            int idx;
            int hidx;

            hi.mask = HDI_ORDER;
            Header_GetItem(tbl->hwnd_header, ph->iItem, &hi);
            idx = hi.iOrder;

            if (idx == 0 || idx >= tbl->n_cols)
                return FALSE;

            if (tbl->cols[idx].flags &
                (KHUI_CW_COL_SORT_INC | KHUI_CW_COL_SORT_DEC)) {

                tbl->cols[idx].flags ^=
                    (KHUI_CW_COL_SORT_INC | KHUI_CW_COL_SORT_DEC);

                cw_hditem_from_tbl_col(&tbl->cols[idx], &hi);
                hi.mask = HDI_FORMAT;
                Header_SetItem(tbl->hwnd_header, ph->iItem, &hi);

            } else {
                int i;
                int sort_idx = 0;

                for (i=0; i <= idx; i++) {
                    if (tbl->cols[i].attr_id < 0)
                        continue;

                    if (!(tbl->flags &
                          (KHUI_CW_COL_SORT_INC | KHUI_CW_COL_SORT_DEC))) {
                        tbl->cols[i].flags |= KHUI_CW_COL_SORT_INC;

                        cw_hditem_from_tbl_col(&tbl->cols[i], &hi);
                        hi.mask = HDI_FORMAT;
                        hidx = Header_OrderToIndex(tbl->hwnd_header, i);
                        Header_SetItem(tbl->hwnd_header, hidx, &hi);
                    }

                    tbl->cols[i].sort_index = sort_idx++;
                }
            }

            tbl->flags |= KHUI_CW_TBL_CUSTVIEW;

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, TRUE);

            InvalidateRect(tbl->hwnd, NULL, FALSE);

        }
        break;

    case HDN_ITEMDBLCLICK:
        {
            int idx;
            int hidx;

            hi.mask = HDI_ORDER;
            Header_GetItem(tbl->hwnd_header, ph->iItem, &hi);
            idx = hi.iOrder;

            if (idx == 0 || idx >= tbl->n_cols)
                return FALSE;

            if (tbl->cols[idx].flags & KHUI_CW_COL_GROUP) {
                /* we are removing grouping from this level */

                int i;

                for (i=idx; i < tbl->n_cols; i++) {
                    if (!(tbl->cols[i].flags &
                          (KHUI_CW_COL_GROUP |
                           KHUI_CW_COL_SORT_INC |
                           KHUI_CW_COL_SORT_DEC)))
                        break;

                    tbl->cols[i].flags &=
                        ~(KHUI_CW_COL_GROUP |
                          KHUI_CW_COL_SORT_DEC |
                          KHUI_CW_COL_SORT_INC);

                    cw_hditem_from_tbl_col(&tbl->cols[idx], &hi);
                    hi.mask = HDI_FORMAT;
                    hidx = Header_OrderToIndex(tbl->hwnd_header, i);
                    Header_SetItem(tbl->hwnd_header, hidx, &hi);
                }

            } else {
                int i;
                int sort_index = 0;

                for (i=0; i <= idx; i++) {
                    if (tbl->cols[i].attr_id < 0)
                        continue;

                    if (!(tbl->cols[i].flags & KHUI_CW_COL_GROUP)) {
                        tbl->cols[i].flags |= KHUI_CW_COL_GROUP;

                        if (!(tbl->cols[i].flags &
                              (KHUI_CW_COL_SORT_INC |
                               KHUI_CW_COL_SORT_DEC)))
                            tbl->cols[i].flags |= KHUI_CW_COL_SORT_INC;

                        cw_hditem_from_tbl_col(&tbl->cols[i], &hi);
                        hi.mask = HDI_FORMAT;
                        hidx = Header_OrderToIndex(tbl->hwnd_header, i);
                        Header_SetItem(tbl->hwnd_header, hidx, &hi);
                    }

                    tbl->cols[i].sort_index = sort_index++;
                }
            }

            tbl->flags |= KHUI_CW_TBL_COL_DIRTY;
            tbl->flags |= KHUI_CW_TBL_CUSTVIEW;

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, TRUE);

            InvalidateRect(tbl->hwnd, NULL, FALSE);
        }
        break;

    case NM_CUSTOMDRAW:
        {
            LPNMCUSTOMDRAW cd;
            int idx;

            cd = (LPNMCUSTOMDRAW) ph;
            switch(cd->dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;

            case CDDS_ITEMPREPAINT:
                return CDRF_NOTIFYPOSTPAINT;

            case CDDS_ITEMPOSTPAINT:
                if(cd->lItemlParam == CW_CA_FLAGS)
                    idx = IDB_WDG_FLAG;
                else if(cd->lItemlParam == CW_CA_TYPEICON)
                    idx = IDB_WDG_CREDTYPE;
                else
                    idx = -1;

                khui_ilist_draw_id(tbl->ilist, idx, cd->hdc, cd->rc.left, cd->rc.top, 0);
                return 0;
            }
        }
        break;
    }
    return 0;
}

LRESULT 
cw_wm_create(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    khui_credwnd_tbl * tbl;

    kmq_subscribe_hwnd(KMSG_CRED, hwnd);
    kmq_subscribe_hwnd(KMSG_KCDB, hwnd);
    kmq_subscribe_hwnd(KMSG_KMM, hwnd);

    /* freed in cw_wm_destroy  */
    tbl = PMALLOC(sizeof(*tbl));
    ZeroMemory(tbl, sizeof(*tbl));

    /* some versions of VC generate portability warnings for
       SetWindowLongPtr */
#pragma warning(push)
#pragma warning(disable: 4244)
    SetWindowLongPtr(hwnd, 0, (LONG_PTR) tbl);
#pragma warning(pop)

    cw_refresh_attribs(hwnd);

    tbl->hwnd_header = CreateWindowEx(
        0,
        WC_HEADER,
        (LPWSTR) NULL,
        WS_CHILD | HDS_BUTTONS |
        HDS_FULLDRAG | HDS_HORZ | HDS_HOTTRACK |
        HDS_DRAGDROP
#if (_WIN32_WINNT >= 0x501)
        | ((IS_COMMCTL6())?HDS_FLAT:0)
#endif
        ,
        0,0,0,0,hwnd, (HMENU) 0, khm_hInstance, NULL);

    cw_load_view(tbl, NULL /* default view */, hwnd);
    cw_insert_header_cols(tbl);

    cw_update_creds(tbl);
    cw_update_outline(tbl);
    cw_update_extents(tbl, FALSE);

    {
        RECT rect;
        WINDOWPOS pw;
        HDLAYOUT hdl;

        hdl.prc = &rect;
        hdl.pwpos = &pw;
        GetClientRect(hwnd, &rect);

        Header_Layout(tbl->hwnd_header, &hdl);

        SetWindowPos(
            tbl->hwnd_header, 
            pw.hwndInsertAfter, 
            pw.x, 
            pw.y, 
            pw.cx, 
            pw.cy, 
            pw.flags | SWP_SHOWWINDOW);
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT
cw_wm_destroy(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    khui_credwnd_tbl * tbl;

    kmq_unsubscribe_hwnd(KMSG_CRED, hwnd);
    kmq_unsubscribe_hwnd(KMSG_KCDB, hwnd);
    kmq_unsubscribe_hwnd(KMSG_KMM, hwnd);

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

    cw_save_view(tbl, NULL);

    cw_unload_view(tbl);

    PFREE(tbl);
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT 
cw_wm_paint(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    khui_credwnd_tbl * tbl;
    HDC hdc;
    PAINTSTRUCT ps;
    RECT r,rh;
    HFONT hf_old;
    int row_s, row_e;
    int col_s, col_e;
    int i,j,x,y,xs,xe,ys,ye;
    int flag_col = -1;
    int d_x = -1;
    int selected = 0;

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

    if(!GetUpdateRect(hwnd, &r, FALSE))
        goto _exit;

    hdc = BeginPaint(hwnd, &ps);
    if(tbl->hf_normal)
        hf_old = SelectFont(hdc, tbl->hf_normal);
    SetTextAlign(hdc, TA_LEFT | TA_TOP | TA_NOUPDATECP);
    SetBkMode(hdc, TRANSPARENT);

    GetClientRect(hwnd,&r);
    r.top += tbl->header_height;

    if(tbl->n_rows) {
        /* remove the notification window if there is one */
        if(tbl->hwnd_notif) {
            DestroyWindow(tbl->hwnd_notif);
            tbl->hwnd_notif = NULL;
        }
        /* we compute the visible area in terms of rows and columns */
        /* row_s : first visible row */
        /* col_s : first visible column */
        /* row_e : last visible row */
        /* col_e : last visible column */
        /* ys    : top edge of first visible row */
        /* xs    : left edge of first visible column */

        /* We *NEED* all the meta columns to be on the left */

        row_s = tbl->scr_top / tbl->cell_height;
        ys = row_s * tbl->cell_height;
        row_e = (tbl->scr_top + (r.bottom - r.top)) / tbl->cell_height + 1;
        if(row_e > (int) tbl->n_rows)
            row_e = (int) tbl->n_rows;
        x = 0;
        col_s = -1;
        col_e = -1;
        xs = 0;
        for(i=0; i < (int) tbl->n_cols; i++) {
            if(col_e == -1 && x >= tbl->scr_left + (r.right - r.left)) {
                col_e = i;
            }
            if(tbl->cols[i].attr_id == CW_CA_FLAGS)
                flag_col = i;
            if(d_x == -1 && !cw_is_custom_attr(tbl->cols[i].attr_id))
                d_x = x;
            x += tbl->cols[i].width;
            if(col_s == -1 && x > tbl->scr_left) {
                col_s = i;
                xs = tbl->cols[i].x;
            }
        }

        if(col_e == -1)
            col_e = i;

        if(col_s == -1)
            col_s = i;

        if(d_x != -1)
            d_x += r.left - tbl->scr_left;

        xs += r.left - tbl->scr_left;
        ys += r.top - tbl->scr_top;
        xe = r.left + tbl->ext_width - tbl->scr_left;
        ye = r.top + tbl->ext_height - tbl->scr_top;

        /* now draw */
        y = ys;
        for(i=row_s; i < row_e; i++) {
            selected = tbl->rows[i].flags & KHUI_CW_ROW_SELECTED;

            if(tbl->cursor_row == i)
                SelectFont(hdc, tbl->hf_bold);

            x = xs;
            if(tbl->rows[i].flags & KHUI_CW_ROW_HEADER) {
                rh.left = xs;
                rh.right = xs;
                for(j=col_s; j < tbl->rows[i].col; j++)
                    rh.right += tbl->cols[j].width;
                rh.top = y;
                rh.bottom = y + tbl->cell_height;
                if(rh.right > rh.left) {
                    cw_erase_rect(hdc, tbl, &r, &rh, (selected)?CW_ER_SEL:CW_ER_BLANK);
                }
                rh.left = rh.right;
                rh.right = xe;

                cw_draw_header(hdc, tbl, i, &rh);
            }
            
            if(selected)
                SetTextColor(hdc, tbl->cr_sel);
            else
                SetTextColor(hdc, tbl->cr_normal);

            x = xs;
            rh.top = y;
            rh.bottom = y + tbl->cell_height;
            for(j=col_s; j < col_e; x += tbl->cols[j++].width) {
                wchar_t buf[256];
                khm_size cbbuf;

                rh.left = x;
                rh.right = x + tbl->cols[j].width;

                if(!RectVisible(hdc, &rh))
                    continue;

                if(!cw_is_custom_attr(tbl->cols[j].attr_id)) {
                    if(!(tbl->rows[i].flags & KHUI_CW_ROW_HEADER)) {
                        cw_erase_rect(hdc, tbl, &r, &rh, (selected)?CW_ER_SEL:CW_ER_BLANK);

                        if(j > tbl->rows[i].col) {
                            cbbuf = sizeof(buf);
                            if(KHM_FAILED(kcdb_cred_get_attr_string((khm_handle) tbl->rows[i].data,
                                                                    tbl->cols[j].attr_id, buf,
                                                                    &cbbuf, KCDB_TS_SHORT)))
                                continue;

                            rh.left += tbl->hpad;
                            rh.right -= tbl->hpad;

                            SetTextAlign(hdc, 0);
                            DrawText(hdc, buf, (int)((cbbuf / sizeof(wchar_t)) - 1), &rh,
                                     DT_LEFT | DT_VCENTER | DT_NOCLIP | DT_SINGLELINE | DT_END_ELLIPSIS);
                            //TextOut(hdc, x, y + tbl->vpad, buf, (cbbuf / sizeof(wchar_t)) - 1);
                        }
                    }
                } else {
                    cw_erase_rect(hdc, tbl, &r, &rh, (selected)?CW_ER_SEL:CW_ER_BLANK);

                    if(tbl->cols[j].attr_id == CW_CA_FLAGS) {
                        khui_credwnd_outline * o;
                        khm_int32 flag;

                        if(tbl->rows[i].flags & KHUI_CW_ROW_HEADER) {
                            o = ((khui_credwnd_outline *) tbl->rows[i].data);
                            if(o->flags & KHUI_CW_O_SHOWFLAG)
                                flag = o->flags;
                            else
                                flag = 0;
                        } else {
                            flag = tbl->rows[i].flags;
                        }

                        flag &= CW_EXPSTATE_MASK;

                        if(flag == CW_EXPSTATE_WARN) {
                            khui_ilist_draw_id(tbl->ilist, IDB_FLAG_WARN, hdc, x, y, 0);
                        } else if(flag == CW_EXPSTATE_CRITICAL) {
                            khui_ilist_draw_id(tbl->ilist, IDB_FLAG_CRITICAL, hdc, x, y, 0);
                        } else if(flag == CW_EXPSTATE_EXPIRED) {
                            khui_ilist_draw_id(tbl->ilist, IDB_FLAG_EXPIRED, hdc, x, y, 0);
                        } else if(!(tbl->rows[i].flags & KHUI_CW_ROW_HEADER)) {
                            khm_int32 flags;

                            if (KHM_SUCCEEDED(kcdb_cred_get_flags((khm_handle) tbl->rows[i].data, &flags)) &&
                                (flags & KCDB_CRED_FLAG_RENEWABLE)) {
                                khui_ilist_draw_id(tbl->ilist,
                                                   IDB_FLAG_RENEW,
                                                   hdc,
                                                   x, y, 0);
                            } else {
                                khui_ilist_draw_id(tbl->ilist,
                                                   IDB_TK_SM,
                                                   hdc,
                                                   x, y, 0);
                            }
                        }
                    }
                }
            }

            if(tbl->cursor_row == i) {
                rh.left = tbl->scr_left;
                rh.right = tbl->scr_left + tbl->ext_width;

                DrawFocusRect(hdc, &rh);

                SelectFont(hdc, tbl->hf_normal);
            }

            y += tbl->cell_height;

        }

        if(xe < r.right) {
            rh.left = xe;
            rh.right = r.right;
            rh.top = r.top;
            rh.bottom = r.bottom;

            cw_erase_rect(hdc, tbl, &r, &rh, CW_ER_BLANK);
        }

        if(ye < r.bottom) {
            rh.left = r.left;
            rh.right = (xe < r.right)?xe:r.right;
            rh.top = ye;
            rh.bottom = r.bottom;

            cw_erase_rect(hdc, tbl, &r, &rh, CW_ER_BLANK);
        }

    } else {
        wchar_t buf[512];
        cw_erase_rect(hdc, tbl, &r, &r, CW_ER_BLANK);

        if(tbl->hwnd_notif == NULL) {
            LoadString(khm_hInstance, IDS_NO_CREDS, buf, sizeof(buf)/sizeof(buf[0]));
            tbl->hwnd_notif = khm_create_htwnd(
                tbl->hwnd,
                buf,
                r.left,r.top,r.right - r.left,(r.bottom - r.top) /2,
                WS_EX_TRANSPARENT,
                WS_VISIBLE);
            if(tbl->hwnd_notif) {
                SendMessage(tbl->hwnd_notif, WM_SETFONT, (WPARAM) tbl->hf_normal, (LPARAM) FALSE);
                ShowWindow(tbl->hwnd_notif, SW_SHOW);
            }
        }
    }

    if(tbl->hf_normal)
        SelectFont(hdc, hf_old);

    EndPaint(hwnd,&ps);
_exit:
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT 
cw_wm_size(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    RECT rect;
    khui_credwnd_tbl * tbl;

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

    cw_update_extents(tbl, TRUE);

    GetClientRect(hwnd, &rect);

    if(tbl->hwnd_notif) {
        SetWindowPos(
            tbl->hwnd_notif,
            tbl->hwnd_header,
            rect.left,
            tbl->header_height,
            rect.right - rect.left,
            (rect.bottom - tbl->header_height) / 2,
            0);
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT 
cw_wm_notify(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    khui_credwnd_tbl * tbl;
    LPNMHDR pnmh;

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);
    pnmh = (LPNMHDR) lParam;
    if(pnmh->hwndFrom == tbl->hwnd_header) {
        LPNMHEADER ph;
        ph = (LPNMHEADER) lParam;
        return cw_handle_header_msg(tbl, ph);
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

static void cw_pp_begin(khui_property_sheet * s);
static void cw_pp_precreate(khui_property_sheet * s);
static void cw_pp_end(khui_property_sheet * s);
static void cw_pp_destroy(khui_property_sheet *ps);

LRESULT 
cw_kmq_wm_dispatch(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    kmq_message * m;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khui_credwnd_tbl * tbl;

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0); 

    kmq_wm_begin(lParam, &m);

    if(m->type == KMSG_CRED) {
        switch (m->subtype) {
        case KMSG_CRED_ROOTDELTA:
            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, TRUE);
            InvalidateRect(hwnd, NULL, FALSE);
            break;

        case KMSG_CRED_PP_BEGIN:
            cw_pp_begin((khui_property_sheet *) m->vparam);
            break;

        case KMSG_CRED_PP_PRECREATE:
            cw_pp_precreate((khui_property_sheet *) m->vparam);
            break;

        case KMSG_CRED_PP_END:
            cw_pp_end((khui_property_sheet *) m->vparam);
            break;

        case KMSG_CRED_PP_DESTROY:
            cw_pp_destroy((khui_property_sheet *) m->vparam);
            break;
        }
    } else if (m->type == KMSG_KCDB) {
        if (m->subtype == KMSG_KCDB_IDENT &&
            m->uparam == KCDB_OP_MODIFY) {

            cw_update_outline(tbl);
            cw_update_extents(tbl, TRUE);
            InvalidateRect(hwnd, NULL, FALSE);
        }
        else if (m->subtype == KMSG_KCDB_IDENT && 
                 m->uparam == KCDB_OP_NEW_DEFAULT) {

            InvalidateRect(hwnd, NULL, FALSE);
        }
        else if (m->subtype == KMSG_KCDB_ATTRIB &&
                 (m->uparam == KCDB_OP_INSERT ||
                  m->uparam == KCDB_OP_DELETE)) {
            cw_refresh_attribs(hwnd);
        }
    } else if (m->type == KMSG_KMM &&
               m->subtype == KMSG_KMM_I_DONE) {

        if (tbl->flags & KHUI_CW_TBL_COLSKIP) {
            wchar_t cname[KCONF_MAXCCH_NAME];
            khm_size cb;

            cname[0] = L'\0';

            if (tbl->csp_view) {
                cb = sizeof(cname);
                khc_get_config_space_name(tbl->csp_view,
                                          cname,
                                          &cb);
            }

            cw_unload_view(tbl);

            cw_load_view(tbl, ((cname[0])?cname: NULL), hwnd);
            cw_insert_header_cols(tbl);

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, TRUE);

            InvalidateRect(tbl->hwnd, NULL, TRUE);
        }

    } else if (m->type == KMSG_ACT &&
               m->subtype == KMSG_ACT_ACTIVATE) {
        /* a column selector menu item was activated */

        khm_int32 attr_id;
        khm_int32 action;
        khui_action * paction;
        int i;
        int first_non_fixed = -1;

        action = m->uparam;
        paction = khui_find_action(action);

        if (paction == NULL)
            goto _skip_action;

        attr_id = (khm_int32)(INT_PTR) paction->data;

        if (attr_id < 0 || attr_id > KCDB_ATTR_MAX_ID)
            goto _skip_action;

        for (i=0; i < tbl->n_cols; i++) {
            if (tbl->cols[i].attr_id >= 0 &&
                first_non_fixed == -1)
                first_non_fixed = i;

            if (tbl->cols[i].attr_id == attr_id)
                break;
        }

        if (first_non_fixed == i &&
            i == tbl->n_cols - 1) {
            /* this is the only non-fixed column.  We don't allow
               deleting it, althoguh there's nothing wrong with doing
               so other than not being very useful. */
            goto _skip_action;
        }

        if (i < tbl->n_cols) {
            khm_int32 sort_index;

            /* we need to remove a column */

            Header_DeleteItem(tbl->hwnd_header, i);
            sort_index = tbl->cols[i].sort_index;

            if (tbl->cols[i].title)
                PFREE(tbl->cols[i].title);
            tbl->cols[i].title = NULL;

            if (i < tbl->n_cols - 1) {
                MoveMemory(&tbl->cols[i], &tbl->cols[i+1],
                           sizeof(tbl->cols[0]) * (tbl->n_cols - (i + 1)));
            }
            tbl->n_cols--;

            /* fix the sort index */
            if (sort_index >= 0) {
                for (i=0; i < tbl->n_cols; i++) {
                    if (tbl->cols[i].sort_index > sort_index)
                        tbl->cols[i].sort_index--;
                }
            }

            tbl->flags |= KHUI_CW_TBL_COL_DIRTY;

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, TRUE);

            InvalidateRect(tbl->hwnd, NULL, TRUE);

            khui_check_action(attr_to_action[attr_id], FALSE);

            tbl->flags |= KHUI_CW_TBL_CUSTVIEW;

        } else {
            /* we need to add a column */
            wchar_t buf[KCDB_MAXCCH_SHORT_DESC];
            khm_size cb;
            khm_int32 idx = tbl->n_cols;
            HDITEM hi;

            /* for now, we only allow KHUI_CW_COL_INITIAL columns */
            if (tbl->n_rows == tbl->n_total_rows)
                goto _skip_action;

            cb = sizeof(buf);
            if (KHM_FAILED(kcdb_attrib_describe(attr_id,
                                                buf,
                                                &cb,
                                                KCDB_TS_SHORT)))
                goto _skip_action;

            tbl->cols[idx].attr_id = attr_id;
            tbl->cols[idx].width = 100;
            tbl->cols[idx].x = -1;
            tbl->cols[idx].flags = 0;
            tbl->cols[idx].sort_index = -1;
            tbl->cols[idx].title = PMALLOC(cb);
#ifdef DEBUG
            assert(tbl->cols[idx].title);
#endif
            if (!tbl->cols[idx].title)
                goto _skip_action;

            StringCbCopy(tbl->cols[idx].title,
                         cb,
                         buf);

            tbl->n_cols++;

            cw_hditem_from_tbl_col(&(tbl->cols[idx]), &hi);
            Header_InsertItem(tbl->hwnd_header, 512, &hi);

            tbl->flags |= KHUI_CW_TBL_COL_DIRTY;

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, TRUE);

            InvalidateRect(tbl->hwnd, NULL, TRUE);

            khui_check_action(attr_to_action[attr_id], TRUE);

            tbl->flags |= KHUI_CW_TBL_CUSTVIEW;
        }

        kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);

    _skip_action:
        ;
    }

    return kmq_wm_end(m, rv);
}

static void 
cw_select_outline_level(khui_credwnd_outline * o,
                        BOOL select)
{
    while(o) {
        if (select)
            o->flags |= KHUI_CW_O_SELECTED;
        else
            o->flags &= ~KHUI_CW_O_SELECTED;
        cw_select_outline_level(TFIRSTCHILD(o), select);
        o = LNEXT(o);
    }
}

static void
cw_select_outline(khui_credwnd_outline * o,
                  BOOL select)
{
    if (select)
        o->flags |= KHUI_CW_O_SELECTED;
    else
        o->flags &= ~KHUI_CW_O_SELECTED;
}

static void 
cw_unselect_all(khui_credwnd_tbl * tbl)
{
    int i;

    for(i=0; i<tbl->n_rows; i++) {
        tbl->rows[i].flags &= ~KHUI_CW_ROW_SELECTED;
        if (!(tbl->rows[i].flags & KHUI_CW_ROW_HEADER))
            kcdb_cred_set_flags((khm_handle) tbl->rows[i].data,
                                0,
                                KCDB_CRED_FLAG_SELECTED);
    }

    cw_select_outline_level(tbl->outline, FALSE);
}

static void
cw_update_outline_selection_state(khui_credwnd_tbl * tbl,
                                  khui_credwnd_outline * o)
{
    BOOL select = TRUE;
    int j;

    for (j = o->start + 1; j < o->start + o->length; j++) {
        if (tbl->rows[j].flags & KHUI_CW_ROW_HEADER) {
            cw_update_outline_selection_state(tbl,
                                              (khui_credwnd_outline *)
                                              tbl->rows[j].data);
        }

        if (!(tbl->rows[j].flags & KHUI_CW_ROW_SELECTED)) {
            select = FALSE;
        }

        if (tbl->rows[j].flags & KHUI_CW_ROW_HEADER) {
            j += ((khui_credwnd_outline *) tbl->rows[j].data)->length - 1;
        }
    }

    /* special case : the header has been collapsed and we are just
       using one row.  In this case, the for loop above will do
       nothing. */

    if (o->length == 1) {
        select = (tbl->rows[o->start].flags & KHUI_CW_ROW_SELECTED);
    }

    cw_select_outline(o, select);

    if (select) {
        tbl->rows[o->start].flags |= KHUI_CW_ROW_SELECTED;
    } else {
        tbl->rows[o->start].flags &= ~KHUI_CW_ROW_SELECTED;
    }
}

static void 
cw_update_selection_state(khui_credwnd_tbl * tbl)
{
    int i;

    cw_select_outline_level(tbl->outline, FALSE);

    for (i=0; i < tbl->n_rows; i++) {
        if (tbl->rows[i].flags & KHUI_CW_ROW_HEADER) {
            khui_credwnd_outline * o;

            o = (khui_credwnd_outline *) tbl->rows[i].data;

            cw_update_outline_selection_state(tbl, o);

            i += o->length - 1;
        }
    }
}

/* Examine the current row and set the UI context */
static void 
cw_set_row_context(khui_credwnd_tbl * tbl, int row)
{
    khui_credwnd_outline * o;
    BOOL set_context = TRUE;

    if (row < 0 || row >= (int) tbl->n_rows) {
        if (tbl->n_rows > 0)
            row = 0;
        else {
            khui_context_reset();
            return;
        }
    }

    if (tbl->rows[row].flags & KHUI_CW_ROW_HEADER) {

        o = (khui_credwnd_outline *) tbl->rows[row].data;

        if (tbl->cols[o->col].attr_id == KCDB_ATTR_ID_NAME) {
            if (TPARENT(o) == NULL) { /* selected an identity */
                khui_context_set(KHUI_SCOPE_IDENT,
                                 (khm_handle) o->data,
                                 KCDB_CREDTYPE_INVALID,
                                 NULL,
                                 NULL,
                                 0,
                                 tbl->credset);
            } else {
                khui_credwnd_outline * op;

                op = TPARENT(o);

                if (tbl->cols[op->col].attr_id == KCDB_ATTR_TYPE_NAME &&
                    TPARENT(op) == NULL) {
                    /* selected a credential type */
                    khui_context_set(KHUI_SCOPE_CREDTYPE,
                                     (khm_handle) o->data,
                                     (khm_int32) (DWORD_PTR) op->data,
                                     NULL,
                                     NULL,
                                     0,
                                     tbl->credset);
                } else {
                    set_context = FALSE;
                }
            }
        } else if (tbl->cols[o->col].attr_id == KCDB_ATTR_TYPE_NAME) {
            if (TPARENT(o) == NULL) {
                /* selected an entire cred type */
                khui_context_set(KHUI_SCOPE_CREDTYPE,
                                 NULL,
                                 (khm_int32) (DWORD_PTR) o->data,
                                 NULL,
                                 NULL,
                                 0,
                                 tbl->credset);
            } else {
                khui_credwnd_outline * op;

                op = TPARENT(o);
                if (tbl->cols[op->col].attr_id == KCDB_ATTR_ID_NAME &&
                    TPARENT(op) == NULL) {
                    /* credtype under an identity */
                    khui_context_set(KHUI_SCOPE_CREDTYPE,
                                     (khm_handle) op->data,
                                     (khm_int32) (DWORD_PTR) o->data,
                                     NULL,
                                     NULL,
                                     0,
                                     tbl->credset);
                } else {
                    set_context = FALSE;
                }
            }
        } else {
            set_context = FALSE;
        }

        if (!set_context) {
            /* woohoo. cred group. yay. */
            khui_header headers[KHUI_MAX_HEADERS];
            khm_size n_headers = 0;

            do {
                headers[n_headers].attr_id =
                    o->attr_id;
                if (tbl->cols[o->col].attr_id == 
                    KCDB_ATTR_ID_NAME) {
                    headers[n_headers].data = &(o->data);
                    headers[n_headers].cb_data = sizeof(khm_handle);
                } else if (tbl->cols[o->col].attr_id == 
                           KCDB_ATTR_TYPE_NAME) {
                    headers[n_headers].data = &(o->data);
                    headers[n_headers].cb_data = sizeof(khm_int32);
                } else {
                    headers[n_headers].data = o->data;
                    headers[n_headers].cb_data = o->cb_data;
                }

                n_headers++;

                o = TPARENT(o);
            } while(o);

            khui_context_set(KHUI_SCOPE_GROUP,
                             NULL,
                             KCDB_CREDTYPE_INVALID,
                             NULL,
                             headers,
                             n_headers,
                             tbl->credset);
        }

    } else {
        khm_handle cred;

        cred = (khm_handle) tbl->rows[row].data;

        khui_context_set(KHUI_SCOPE_CRED,
                         NULL,
                         KCDB_CREDTYPE_INVALID,
                         cred,
                         NULL,
                         0,
                         tbl->credset);
    }
}

static void
cw_select_all(khui_credwnd_tbl * tbl)
{
    int i;

    for(i=0; i<tbl->n_rows; i++) {
        tbl->rows[i].flags |= KHUI_CW_ROW_SELECTED;
        if (!(tbl->rows[i].flags & KHUI_CW_ROW_HEADER))
            kcdb_cred_set_flags((khm_handle) tbl->rows[i].data,
                                KCDB_CRED_FLAG_SELECTED,
                                KCDB_CRED_FLAG_SELECTED);
    }

    cw_select_outline_level(tbl->outline, TRUE);

    cw_update_selection_state(tbl);

    cw_set_row_context(tbl, tbl->cursor_row);

    InvalidateRect(tbl->hwnd, NULL, FALSE);
}

static void 
cw_select_row(khui_credwnd_tbl * tbl, int row, WPARAM wParam)
{
    int i;
    BOOL toggle;
    BOOL extend;
    int group_begin;
    int group_end;

    if (wParam & MK_CONTROL) {
        toggle = TRUE;
        extend = FALSE;
    } else if (wParam & MK_SHIFT) {
        toggle = FALSE;
        extend = TRUE;
    } else {
        toggle = FALSE;
        extend = FALSE;
    }

    if (row < 0 || row >= (int) tbl->n_rows)
        return;

    if (tbl->rows[row].flags & KHUI_CW_ROW_HEADER) {
        khui_credwnd_outline * o;

        o = (khui_credwnd_outline *) tbl->rows[row].data;

        group_begin = o->start;
        group_end = o->start + o->length - 1;
    } else {
        group_begin = row;
        group_end = row;
    }

    if (!toggle && !extend) {
        /* selecting a single row */
        cw_unselect_all(tbl);

        tbl->cursor_row = row;
        tbl->anchor_row = row;

        for (i = group_begin; i <= group_end; i++) {
            tbl->rows[i].flags |= KHUI_CW_ROW_SELECTED;
            if (!(tbl->rows[i].flags & KHUI_CW_ROW_HEADER)) {
                kcdb_cred_set_flags((khm_handle) tbl->rows[i].data,
                                    KCDB_CRED_FLAG_SELECTED,
                                    KCDB_CRED_FLAG_SELECTED);
            }
        }
    } else if (toggle) {
        BOOL select;

        tbl->cursor_row = row;
        tbl->anchor_row = row;

        select = !(tbl->rows[row].flags & KHUI_CW_ROW_SELECTED);

        for (i = group_begin; i <= group_end; i++) {
            if (select)
                tbl->rows[i].flags |= KHUI_CW_ROW_SELECTED;
            else
                tbl->rows[i].flags &= ~KHUI_CW_ROW_SELECTED;

            if (!(tbl->rows[i].flags & KHUI_CW_ROW_HEADER)) {
                kcdb_cred_set_flags((khm_handle) tbl->rows[i].data,
                                    (select)?KCDB_CRED_FLAG_SELECTED:0,
                                    KCDB_CRED_FLAG_SELECTED);
            }
        }
    } else if (extend) {
        int range_begin;
        int range_end;

        cw_unselect_all(tbl);

        range_begin = min(row, tbl->anchor_row);
        range_end = max(row, tbl->anchor_row);

        for (i = range_begin; i <= range_end; i++) {
            tbl->rows[i].flags |= KHUI_CW_ROW_SELECTED;

            if (!(tbl->rows[i].flags & KHUI_CW_ROW_HEADER)) {
                kcdb_cred_set_flags((khm_handle) tbl->rows[i].data,
                                    KCDB_CRED_FLAG_SELECTED,
                                    KCDB_CRED_FLAG_SELECTED);
            }
        }

        tbl->cursor_row = row;
    }

    cw_update_selection_state(tbl);

    cw_set_row_context(tbl, tbl->cursor_row);

    InvalidateRect(tbl->hwnd, NULL, FALSE);
}

static void
cw_toggle_outline_state(khui_credwnd_tbl * tbl,
                        khui_credwnd_outline * o) {

    int old_range_begin;
    int old_range_end;
    int new_range_begin;
    int new_range_end;

    old_range_begin = o->start;
    old_range_end = o->start + o->length - 1;

    o->flags ^= KHUI_CW_O_EXPAND;

    cw_update_outline(tbl);
    cw_update_extents(tbl, TRUE);

    new_range_begin = o->start;
    new_range_end = o->start + o->length - 1;

    if (tbl->cursor_row > old_range_end) {
        tbl->cursor_row -= old_range_end - new_range_end;
    } else if (tbl->cursor_row >= old_range_begin &&
               tbl->cursor_row <= old_range_end) {
        tbl->cursor_row = new_range_begin;
    }

    if (tbl->anchor_row > old_range_end) {
        tbl->anchor_row -= old_range_end - new_range_end;
    } else if (tbl->anchor_row >= old_range_begin &&
               tbl->anchor_row <= old_range_end) {
        tbl->anchor_row = new_range_begin;
    }

    InvalidateRect(tbl->hwnd, NULL, TRUE);

}

LRESULT cw_properties(HWND hwnd);

LRESULT 
cw_wm_mouse(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    khui_credwnd_tbl * tbl;
    int x,y;
    RECT r;
    int row;
    int col;
    int i;
    int nm_state,nm_row,nm_col;

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

    /* we are basically trying to capture events where the mouse is
       hovering over one of the 'hotspots'.  There are two kinds of
       hotspots one is the little widget thinggy that you click on to
       expand or collapse an outline.  The other is a text cell that
       is partially concealed. */

    x = GET_X_LPARAM(lParam);
    y = GET_Y_LPARAM(lParam);
    x += tbl->scr_left;
    y += tbl->scr_top - tbl->header_height;

    row = y / tbl->cell_height;
    col = -1;
    nm_state = CW_MOUSE_NONE;
    nm_row = nm_col = -1;

    for(i=0; i < (int) tbl->n_cols; i++) {
        if(x >= tbl->cols[i].x &&
           x < tbl->cols[i].x + tbl->cols[i].width) {
            col = i;
            break;
        }
    }

    if(wParam & MK_LBUTTON)
        nm_state = CW_MOUSE_LDOWN;

    if(row >= 0 && row < (int) tbl->n_rows) {
        nm_state |= CW_MOUSE_ROW;
        nm_row = row;
        nm_col = col;
        if(tbl->rows[row].flags & KHUI_CW_ROW_HEADER) {
            /* are we on a widget then? */
            x -= tbl->cols[tbl->rows[row].col].x;
            if(x >= 0 && x < KHUI_SMICON_CX) /* hit */ {
                nm_state |= CW_MOUSE_WOUTLINE | CW_MOUSE_WIDGET;
            } else if (tbl->cols[tbl->rows[row].col].attr_id == 
                       KCDB_ATTR_ID_NAME &&
                       col == tbl->rows[row].col &&
                       x >= KHUI_SMICON_CX * 3 / 2 &&
                       x < KHUI_SMICON_CX * 5 / 2){
                nm_state |= CW_MOUSE_WSTICKY | CW_MOUSE_WIDGET;
            } else if (tbl->cols[tbl->rows[row].col].attr_id ==
                       KCDB_ATTR_ID_NAME &&
                       col == tbl->rows[row].col &&
                       x >= KHUI_SMICON_CX * 3 &&
                       x < KHUI_SMICON_CX * 4) {
                nm_state |= CW_MOUSE_WICON | CW_MOUSE_WIDGET;
            }
        }
    }

    /* did the user drag the cursor off the current row? */
    if((tbl->mouse_state & CW_MOUSE_LDOWN) &&
       (nm_row != tbl->mouse_row)) {
        nm_state &= ~CW_MOUSE_WMASK;
    }

    if(!(nm_state & CW_MOUSE_LDOWN) && 
       (tbl->mouse_state & CW_MOUSE_LDOWN) &&
       tbl->mouse_row == nm_row) {

        if((nm_state & CW_MOUSE_WOUTLINE) &&
           (tbl->mouse_state & CW_MOUSE_WOUTLINE)) {
            /* click on an outline widget */
            khui_credwnd_outline * o;

            o = (khui_credwnd_outline *) tbl->rows[nm_row].data;
            tbl->mouse_state = CW_MOUSE_WIDGET | CW_MOUSE_WOUTLINE;

            cw_toggle_outline_state(tbl, o);

            return 0;
        } else if ((nm_state & CW_MOUSE_WSTICKY) &&
                   (tbl->mouse_state & CW_MOUSE_WSTICKY)) {

            khui_credwnd_outline * o;
            khm_handle ident;
            khm_int32 idf = 0;

            o = tbl->rows[nm_row].data;
            ident = o->data;

            kcdb_identity_get_flags(ident, &idf);
            idf &= KCDB_IDENT_FLAG_STICKY;
            kcdb_identity_set_flags(ident, (idf ^ KCDB_IDENT_FLAG_STICKY),
                                    KCDB_IDENT_FLAG_STICKY);

            tbl->mouse_state = CW_MOUSE_WIDGET | CW_MOUSE_WSTICKY;

            return 0;
        } else if ((nm_state & CW_MOUSE_WICON) &&
                   (tbl->mouse_state & CW_MOUSE_WICON)) {
            /* click on an row icon */
            cw_select_row(tbl, nm_row, wParam);
            cw_properties(hwnd);
        } else {
            /* click on a row */
            cw_select_row(tbl, nm_row, wParam);

            if (tbl->mouse_col == nm_col &&
                nm_col >= 0 &&
                tbl->cols[nm_col].attr_id == CW_CA_FLAGS &&
                !(tbl->rows[nm_row].flags & KHUI_CW_ROW_HEADER)) {
                /* clicked on a cred icon */

                cw_properties(hwnd);
            }
        }
    }

    /* ok, now if we are changing state, we need to invalidate a few
       regions */
    if (((tbl->mouse_state ^ nm_state) & (CW_MOUSE_WIDGET |
                                          CW_MOUSE_WOUTLINE |
                                          CW_MOUSE_WSTICKY)) ||
        tbl->mouse_row != nm_row) {

        if(tbl->mouse_state & CW_MOUSE_WOUTLINE) {
            r.left = tbl->cols[tbl->mouse_col].x - tbl->scr_left;
            r.top = tbl->mouse_row * tbl->cell_height + 
                tbl->header_height - tbl->scr_top;
            r.right = r.left + KHUI_SMICON_CX;
            r.bottom = r.top + tbl->cell_height;
            InvalidateRect(tbl->hwnd, &r, TRUE);
        }
        if(tbl->mouse_state & CW_MOUSE_WSTICKY) {
            r.left = KHUI_SMICON_CX * 3 / 2 + 
                tbl->cols[tbl->mouse_col].x - tbl->scr_left;
            r.top = tbl->mouse_row * tbl->cell_height + 
                tbl->header_height - tbl->scr_top;
            r.right = r.left + KHUI_SMICON_CX;
            r.bottom = r.top + tbl->cell_height;
            InvalidateRect(tbl->hwnd, &r, TRUE);
        }

        if ((tbl->mouse_state & nm_state) & CW_MOUSE_LDOWN) {
            if (tbl->mouse_row == nm_row)
                tbl->mouse_col = nm_col;
        } else {
            tbl->mouse_col = nm_col;
            tbl->mouse_row = nm_row;
        }
        tbl->mouse_state = nm_state;

        /* same code block as above */
        if(tbl->mouse_state & CW_MOUSE_WOUTLINE) {
            r.left = tbl->cols[tbl->mouse_col].x - tbl->scr_left;
            r.top = tbl->mouse_row * tbl->cell_height + 
                tbl->header_height - tbl->scr_top;
            r.right = r.left + KHUI_SMICON_CX;
            r.bottom = r.top + tbl->cell_height;
            InvalidateRect(tbl->hwnd, &r, TRUE);
        }
        if(tbl->mouse_state & CW_MOUSE_WSTICKY) {
            r.left = KHUI_SMICON_CX * 3 / 2 + 
                tbl->cols[tbl->mouse_col].x - tbl->scr_left;
            r.top = tbl->mouse_row * tbl->cell_height + 
                tbl->header_height - tbl->scr_top;
            r.right = r.left + KHUI_SMICON_CX;
            r.bottom = r.top + tbl->cell_height;
            InvalidateRect(tbl->hwnd, &r, TRUE);
        }
    } else if(tbl->mouse_state != nm_state) {

        if ((tbl->mouse_state & nm_state) & CW_MOUSE_LDOWN) {
            if (tbl->mouse_row == nm_row) {
                tbl->mouse_col = nm_col;
                tbl->mouse_state = nm_state;
            }
        } else {
            tbl->mouse_col = nm_col;
            tbl->mouse_row = nm_row;
            tbl->mouse_state = nm_state;
        }
    }

    /* if it was a double click, also show the property
       window */
    if (uMsg == WM_LBUTTONDBLCLK) {
        cw_properties(hwnd);
    }

    return 0;
}

LRESULT 
cw_wm_hscroll(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    khui_credwnd_tbl * tbl;
    SCROLLINFO si;
    RECT cr;
    RECT lr;
    RECT sr;
    int dx;
    int newpos;

    tbl = (khui_credwnd_tbl *) (LONG_PTR) GetWindowLongPtr(hwnd, 0);
    GetClientRect(hwnd, &cr);
    dx = tbl->scr_left;

    switch(LOWORD(wParam)) {
        case SB_LEFT:
            newpos = 0;
            break;

        case SB_RIGHT:
            newpos = tbl->ext_width;
            break;

        case SB_LINELEFT:
            newpos = tbl->scr_left - (tbl->ext_width / 12);
            break;

        case SB_LINERIGHT:
            newpos = tbl->scr_left + (tbl->ext_width / 12);
            break;

        case SB_PAGELEFT:
            newpos = tbl->scr_left - (cr.right - cr.left);
            break;

        case SB_PAGERIGHT:
            newpos = tbl->scr_left + (cr.right - cr.left);
            break;

        case SB_THUMBTRACK:
        case SB_THUMBPOSITION:
            ZeroMemory(&si, sizeof(si));
            si.cbSize = sizeof(si);
            si.fMask = SIF_TRACKPOS;
            GetScrollInfo(hwnd, SB_HORZ, &si);

            newpos = si.nTrackPos;
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    //cr.top += tbl->header_height;
    tbl->scr_left = newpos;
    cw_update_extents(tbl, TRUE);

    dx -= tbl->scr_left;

    /* exclude the watermark */
    lr.bottom = cr.bottom;
    lr.right = cr.right;
    lr.top = max(cr.bottom - tbl->kbm_logo_shade.cy, cr.top);
    lr.left = max(cr.right - tbl->kbm_logo_shade.cx, cr.left);

    if(cr.top < lr.top && cr.left < cr.right) {
        sr.left = cr.left;
        sr.right = cr.right;
        sr.top = cr.top;
        sr.bottom = lr.top;
        ScrollWindowEx(
            hwnd, 
            dx, 
            0, 
            &sr, 
            &sr, 
            NULL, 
            NULL, 
            SW_INVALIDATE | SW_SCROLLCHILDREN);
    }

    if(cr.left < lr.left && lr.top < lr.bottom) {
        sr.left = cr.left;
        sr.right = lr.left;
        sr.top = lr.top;
        sr.bottom = lr.bottom;
        ScrollWindowEx(
            hwnd, 
            dx, 
            0, 
            &sr, 
            &sr, 
            NULL, 
            NULL, 
            SW_INVALIDATE | SW_SCROLLCHILDREN);
    }

    if(lr.top < lr.bottom && lr.left < lr.right) {
        InvalidateRect(hwnd, &lr, FALSE);
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

static void
cw_vscroll_to_pos(HWND hwnd, khui_credwnd_tbl * tbl, int newpos) {
    RECT cr;
    RECT sr;
    RECT lr;
    int dy;

    GetClientRect(hwnd, &cr);
    cr.top += tbl->header_height;
    dy = tbl->scr_top;

    tbl->scr_top = newpos;
    cw_update_extents(tbl, TRUE);

    dy -= tbl->scr_top;

    /* exclude watermark */
    lr.bottom = cr.bottom;
    lr.right = cr.right;
    lr.top = max(cr.bottom - tbl->kbm_logo_shade.cy, cr.top);
    lr.left = max(cr.right - tbl->kbm_logo_shade.cx, cr.left);

    if(cr.left < lr.left && cr.top < cr.bottom) {
        sr.left = cr.left;
        sr.right = lr.left;
        sr.top = cr.top;
        sr.bottom = cr.bottom;
        ScrollWindowEx(
            hwnd, 
            0, 
            dy, 
            &sr, 
            &sr, 
            NULL, 
            NULL, 
            SW_INVALIDATE);
    }

    if(lr.left < lr.right && cr.top < lr.top) {
        sr.left = lr.left;
        sr.right = lr.right;
        sr.top = cr.top;
        sr.bottom = lr.top;
        ScrollWindowEx(
            hwnd, 
            0, 
            dy, 
            &sr, 
            &sr, 
            NULL, 
            NULL, 
            SW_INVALIDATE);
    }

    if(lr.top < lr.bottom && lr.left < lr.right) {
        InvalidateRect(hwnd, &lr, FALSE);
    }
}

LRESULT 
cw_wm_vscroll(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    khui_credwnd_tbl * tbl;
    SCROLLINFO si;
    int newpos;
    RECT cr;

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

    GetClientRect(hwnd, &cr);
    cr.top += tbl->header_height;

    switch(LOWORD(wParam)) {
        case SB_LEFT:
            newpos = 0;
            break;

        case SB_BOTTOM:
            newpos = tbl->ext_height;
            break;

        case SB_LINEUP:
            newpos = tbl->scr_top - (tbl->ext_height / 12);
            break;

        case SB_LINEDOWN:
            newpos = tbl->scr_top + (tbl->ext_height / 12);
            break;

        case SB_PAGEUP:
            newpos = tbl->scr_top - (cr.bottom - cr.top);
            break;

        case SB_PAGEDOWN:
            newpos = tbl->scr_top + (cr.bottom - cr.top);
            break;

        case SB_THUMBTRACK:
        case SB_THUMBPOSITION:
            ZeroMemory(&si, sizeof(si));
            si.cbSize = sizeof(si);
            si.fMask = SIF_TRACKPOS;
            GetScrollInfo(hwnd, SB_VERT, &si);

            newpos = si.nTrackPos;
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    cw_vscroll_to_pos(hwnd, tbl, newpos);

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

static void
cw_ensure_row_visible(HWND hwnd, khui_credwnd_tbl * tbl, int row) {
    RECT r;
    int newpos;

    if (row < 0)
        row = 0;
    else if (row >= (int) tbl->n_rows)
        row = (int) tbl->n_rows - 1;

    GetClientRect(hwnd, &r);
    r.top += tbl->header_height;

    if (row * tbl->cell_height < tbl->scr_top) {
        newpos = row * tbl->cell_height;
    } else if ((row + 1) * tbl->cell_height
             > tbl->scr_top + (r.bottom - r.top)) {
        newpos = ((row + 1) * tbl->cell_height) - (r.bottom - r.top);
    } else
        return;

    cw_vscroll_to_pos(hwnd, tbl, newpos);
}

static INT_PTR CALLBACK 
cw_pp_ident_proc(HWND hwnd,
                 UINT uMsg,
                 WPARAM wParam,
                 LPARAM lParam)
{
    khui_property_sheet * s;

    switch(uMsg) {
    case WM_INITDIALOG:
        {
            PROPSHEETPAGE * p;
            khm_handle ident;
            wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
            khm_size t;
            khm_int32 i;

            p = (PROPSHEETPAGE *) lParam;
            s = (khui_property_sheet *) p->lParam;

#pragma warning(push)
#pragma warning(disable: 4244)
            SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) s);
#pragma warning(pop)

            ident = s->identity;

            t = sizeof(idname);
            kcdb_identity_get_name(ident, idname, &t);
            SetDlgItemText(hwnd, IDC_PP_IDNAME, idname);

            kcdb_identity_get_flags(ident, &i);

            CheckDlgButton(hwnd, IDC_PP_IDDEF,
                           ((i & KCDB_IDENT_FLAG_DEFAULT)?BST_CHECKED:
                            BST_UNCHECKED));

            /* if it's default, you can't change it further */
            if (i & KCDB_IDENT_FLAG_DEFAULT) {
                EnableWindow(GetDlgItem(hwnd, IDC_PP_IDDEF), FALSE);
            }

            CheckDlgButton(hwnd, IDC_PP_IDSEARCH,
                           ((i & KCDB_IDENT_FLAG_SEARCHABLE)?BST_CHECKED:
                            BST_UNCHECKED));

            CheckDlgButton(hwnd, IDC_PP_STICKY,
                           ((i & KCDB_IDENT_FLAG_STICKY)?BST_CHECKED:
                            BST_UNCHECKED));

            khui_property_wnd_set_record(GetDlgItem(hwnd, IDC_PP_PROPLIST),
                                         ident);
        }
        return TRUE;

    case WM_COMMAND:
        s = (khui_property_sheet *) (LONG_PTR) 
            GetWindowLongPtr(hwnd, DWLP_USER);

        switch(wParam) {
        case MAKEWPARAM(IDC_PP_IDDEF, BN_CLICKED):
            /* fallthrough */
        case MAKEWPARAM(IDC_PP_STICKY, BN_CLICKED):

            if (s->status != KHUI_PS_STATUS_NONE)
                PropSheet_Changed(s->hwnd, hwnd);
            return TRUE;

        case MAKEWPARAM(IDC_PP_CONFIG, BN_CLICKED):
            {
                khui_config_node cfg_id = NULL;
                khui_config_node cfg_ids = NULL;
                wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
                khm_size cb;
                khm_int32 rv;

                khm_refresh_config();

                rv = khui_cfg_open(NULL,
                                   L"KhmIdentities",
                                   &cfg_ids);

                if (KHM_FAILED(rv))
                    return TRUE;

                cb = sizeof(idname);
                if (KHM_SUCCEEDED(kcdb_identity_get_name(s->identity,
                                                         idname,
                                                         &cb))) {
                    rv = khui_cfg_open(cfg_ids,
                                       idname,
                                       &cfg_id);
                }

                if (cfg_id)
                    khm_show_config_pane(cfg_id);
                else
                    khm_show_config_pane(cfg_ids);

                if (cfg_ids)
                    khui_cfg_release(cfg_ids);
                if (cfg_id)
                    khui_cfg_release(cfg_id);
            }
            return TRUE;
        }
        return FALSE;

    case WM_NOTIFY:
        {
            LPPSHNOTIFY lpp;
            khm_int32 flags;

            lpp = (LPPSHNOTIFY) lParam;
            s = (khui_property_sheet *) (LONG_PTR) 
                GetWindowLongPtr(hwnd, DWLP_USER);

            switch(lpp->hdr.code) {
            case PSN_APPLY:
                flags = 0;
                if (IsDlgButtonChecked(hwnd, IDC_PP_STICKY) == BST_CHECKED)
                    flags |= KCDB_IDENT_FLAG_STICKY;
                if (IsDlgButtonChecked(hwnd, IDC_PP_IDDEF) == BST_CHECKED)
                    flags |= KCDB_IDENT_FLAG_DEFAULT;

                kcdb_identity_set_flags(s->identity, flags,
                                        KCDB_IDENT_FLAG_STICKY |
                                        KCDB_IDENT_FLAG_DEFAULT);
                return TRUE;

            case PSN_RESET:
                kcdb_identity_get_flags(s->identity, &flags);

                CheckDlgButton(hwnd, 
                               IDC_PP_IDDEF, 
                               ((flags & KCDB_IDENT_FLAG_DEFAULT)?BST_CHECKED:
                                BST_UNCHECKED));

                /* if it's default, you can't change it further */
                if (flags & KCDB_IDENT_FLAG_DEFAULT) {
                    EnableWindow(GetDlgItem(hwnd, IDC_PP_IDDEF), FALSE);
                }

                CheckDlgButton(hwnd, IDC_PP_IDSEARCH,
                               ((flags & KCDB_IDENT_FLAG_SEARCHABLE)?BST_CHECKED:BST_UNCHECKED));

                CheckDlgButton(hwnd, IDC_PP_STICKY,
                               ((flags & KCDB_IDENT_FLAG_STICKY)?BST_CHECKED:BST_UNCHECKED));
                return TRUE;
            }
        }
        break;
    }
    return FALSE;
}

static INT_PTR CALLBACK 
cw_pp_cred_proc(HWND hwnd,
                UINT uMsg,
                WPARAM wParam,
                LPARAM lParam
                )
{
    switch(uMsg) {
        case WM_INITDIALOG:
            {
                khui_property_sheet * s;
                PROPSHEETPAGE * p;
                khm_handle cred;

                p = (PROPSHEETPAGE *) lParam;
                s = (khui_property_sheet *) p->lParam;

#pragma warning(push)
#pragma warning(disable: 4244)
                SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) s);
#pragma warning(pop)

                cred = s->cred;

                khui_property_wnd_set_record(
                    GetDlgItem(hwnd, IDC_PP_CPROPLIST),
                    cred);
            }
            return TRUE;
    }
    return FALSE;
}

static void 
cw_pp_begin(khui_property_sheet * s)
{
    PROPSHEETPAGE *p;

    if(s->identity) {
        p = PMALLOC(sizeof(*p));
        ZeroMemory(p, sizeof(*p));

        p->dwSize = sizeof(*p);
        p->dwFlags = 0;
        p->hInstance = khm_hInstance;
        p->pszTemplate = MAKEINTRESOURCE(IDD_PP_IDENT);
        p->pfnDlgProc = cw_pp_ident_proc;
        p->lParam = (LPARAM) s;

        khui_ps_add_page(s, KHUI_PPCT_IDENTITY, 129, p, NULL);
    }

    if(s->cred) {
        p = PMALLOC(sizeof(*p));
        ZeroMemory(p, sizeof(*p));

        p->dwSize = sizeof(*p);
        p->dwFlags = 0;
        p->hInstance = khm_hInstance;
        p->pszTemplate = MAKEINTRESOURCE(IDD_PP_CRED);
        p->pfnDlgProc = cw_pp_cred_proc;
        p->lParam = (LPARAM) s;

        khui_ps_add_page(s, KHUI_PPCT_CREDENTIAL, 128, p, NULL);
    }
}

static void 
cw_pp_precreate(khui_property_sheet * s)
{
    khui_ps_show_sheet(khm_hwnd_main, s);

    khm_add_property_sheet(s);
}

static void 
cw_pp_end(khui_property_sheet * s)
{
    khui_property_page * p = NULL;

    khui_ps_find_page(s, KHUI_PPCT_IDENTITY, &p);
    if(p) {
        PFREE(p->p_page);
        p->p_page = NULL;
    }

    p = NULL;

    khui_ps_find_page(s, KHUI_PPCT_CREDENTIAL, &p);
    if(p) {
        PFREE(p->p_page);
        p->p_page = NULL;
    }
}

static void 
cw_pp_destroy(khui_property_sheet *ps)
{
    if(ps->ctx.scope == KHUI_SCOPE_CRED) {
        if(ps->header.pszCaption)
            PFREE((LPWSTR) ps->header.pszCaption);
    }

    khui_context_release(&ps->ctx);

    khui_ps_destroy_sheet(ps);

    /* this is pretty weird because ps gets freed when
       khui_ps_destroy_sheet() is called.  However, since destroying
       ps involves sending a WM_DESTROY message to the property sheet,
       we still need to keep it on the property sheet chain (or else
       the messages will not be delivered).  This is only safe because
       we are not relinquishing the thread in-between destroying ps
       and removing it from the chain. */

    /* TODO: fix this */
    khm_del_property_sheet(ps);
}

LRESULT
cw_properties(HWND hwnd)
{
    /* show a property sheet of some sort */
    khui_action_context ctx;
    khui_property_sheet * ps;
    khui_credwnd_tbl * tbl;

    khui_context_get(&ctx);
    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

    if(ctx.scope == KHUI_SCOPE_NONE) {
        khui_context_release(&ctx);
        return FALSE;

        /* While it seems like a good idea, doing this is not */
#if 0
        /* try to establish a context based on the current cursor
           position */
        if(tbl->cursor_row >= 0 && tbl->cursor_row < (int) tbl->n_rows) {
            if(tbl->rows[tbl->cursor_row].flags & KHUI_CW_ROW_HEADER) {
                if(tbl->cols[tbl->rows[tbl->cursor_row].col].attr_id == KCDB_ATTR_ID_NAME) {
                    /* identity context */
                    ctx.ctx = KHUI_SCOPE_IDENT;
                    ctx.identity = (khm_handle) 
                        ((khui_credwnd_outline *) tbl->rows[tbl->cursor_row].data)->data;
                } else if(tbl->cols[tbl->rows[tbl->cursor_row].col].attr_id == KCDB_ATTR_TYPE_NAME) {
                    ctx.ctx = KHUI_SCOPE_CREDTYPE;
                    ctx.cred_type = (khm_int32) (DWORD_PTR) 
                        ((khui_credwnd_outline *) tbl->rows[tbl->cursor_row].data)->data;
                } else {
                    ctx.ctx = KHUI_SCOPE_GROUP;
                    //ctx.parm = (khm_lparm) tbl->rows[tbl->cursor_row].data;
                    /* TODO: Figure out method of establishing a credgroup */
                }
            } else {
                /* a credential context */
                ctx.ctx = KHUI_SCOPE_CRED;
                ctx.cred = (khm_handle) tbl->rows[tbl->cursor_row].data;
            }
        }
#endif
    }

    /* if still no context, then we can't show a property sheet */
    if(ctx.scope == KHUI_SCOPE_NONE) {
        khui_context_release(&ctx);
        return FALSE;
    }

    khui_ps_create_sheet(&ps);

    if(ctx.scope == KHUI_SCOPE_IDENT) {
        khm_handle ident;
        khm_size t;

        ident = ctx.identity;

        ps->header.hInstance = khm_hInstance;
        ps->header.pszIcon = MAKEINTRESOURCE(IDI_MAIN_APP);

        kcdb_identity_get_name(ident, NULL, &t);

        if(t > 0) {
            ps->header.pszCaption = PMALLOC(t);
            kcdb_identity_get_name(ident,
                                   (wchar_t *) ps->header.pszCaption, &t);
        } else {
            ps->header.pszCaption = NULL;
        }

        ps->ctx = ctx;
        ps->identity = ident;
        ps->credtype = KCDB_CREDTYPE_INVALID;

        kmq_post_message(KMSG_CRED, KMSG_CRED_PP_BEGIN, 0, (void *) ps);

    } else if(ctx.scope == KHUI_SCOPE_CREDTYPE) {
        khm_size t = 0;
        khm_int32 cred_type;

        cred_type = ctx.cred_type;

        ps->header.hInstance = khm_hInstance;
        ps->header.pszIcon = MAKEINTRESOURCE(IDI_MAIN_APP);

        ps->ctx = ctx;
        ps->credtype = cred_type;

        if(ctx.identity) {
            ps->identity = ctx.identity;
            /* also, if there is an associated identity, we assume that
               the properties are for the specified credentials type
               specific to the identity.  Hence we change the title to
               something else */
            kcdb_identity_get_name(ctx.identity, NULL, &t);
            if (t > 0) {
                ps->header.pszCaption = PMALLOC(t);
                kcdb_identity_get_name(ctx.identity, (wchar_t *) ps->header.pszCaption, &t);
            } else {
                ps->header.pszCaption = NULL;
            }
        } else {
            kcdb_credtype_describe(cred_type, NULL, &t, KCDB_TS_LONG);
            if(t > 0) {
                ps->header.pszCaption = PMALLOC(t);
                kcdb_credtype_describe(cred_type, (wchar_t *) ps->header.pszCaption, &t, KCDB_TS_LONG);
            } else {
                ps->header.pszCaption = NULL;
            }
        }

        kmq_post_message(KMSG_CRED, KMSG_CRED_PP_BEGIN, 0, (void *) ps);
    } else if(ctx.scope == KHUI_SCOPE_CRED) {
        khm_handle cred;
        khm_size t;

        cred = ctx.cred;

        ps->header.hInstance = khm_hInstance;
        ps->header.pszIcon = MAKEINTRESOURCE(IDI_MAIN_APP);
        ps->ctx = ctx;

        kcdb_cred_get_name(cred, NULL, &t);
        ps->header.pszCaption = PMALLOC(t);
        kcdb_cred_get_name(cred, (LPWSTR) ps->header.pszCaption, &t);

        kcdb_cred_get_identity(cred, &ps->identity);
        kcdb_cred_get_type(cred, &ps->credtype);
        ps->cred = cred;

        kmq_post_message(KMSG_CRED, KMSG_CRED_PP_BEGIN, 0, (void *) ps);
    } else {
        khui_context_release(&ctx);
        khui_ps_destroy_sheet(ps);
    }

    /* by the way, if we are actually opening a property sheet, we
       leave ctx held (which is now copied to ps->ctx).  it will be
       released when the property sheet is destroyed */

    return TRUE;
}

LRESULT 
cw_wm_command(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    khui_credwnd_tbl * tbl;

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

    if(HIWORD(wParam) == BN_CLICKED && 
       LOWORD(wParam) == KHUI_HTWND_CTLID) {

        wchar_t wid[256];
        /* a hyperlink was activated */
        khui_htwnd_link * l;
        l = (khui_htwnd_link *) lParam;
        wcsncpy(wid, l->id, l->id_len);
        wid[l->id_len] = 0;

        if(!wcscmp(wid, L"NewCreds")) {
            PostMessage(khm_hwnd_main, WM_COMMAND, 
                        MAKEWPARAM(KHUI_ACTION_NEW_CRED,0), 0);
        }
        return TRUE;
    }

    switch(LOWORD(wParam)) 
    {
    case KHUI_PACTION_ENTER:
        /* enter key is a synonym for the default action, on the
        context, which is to lauch a property sheet */
        /* fallthrough */
    case KHUI_ACTION_PROPERTIES:
        {
            return cw_properties(hwnd);
        }
        break;

    case KHUI_ACTION_LAYOUT_ID:
        {
            cw_save_view(tbl, NULL);
            cw_unload_view(tbl);

            cw_load_view(tbl, L"ByIdentity", hwnd);
            cw_insert_header_cols(tbl);

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, FALSE);

            InvalidateRect(tbl->hwnd, NULL, TRUE);

            khui_check_radio_action(khui_find_menu(KHUI_MENU_LAYOUT), KHUI_ACTION_LAYOUT_ID);
            kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);
        }
        break;

    case KHUI_ACTION_LAYOUT_LOC:
        {
            cw_save_view(tbl, NULL);
            cw_unload_view(tbl);

            cw_load_view(tbl, L"ByLocation", hwnd);
            cw_insert_header_cols(tbl);

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, FALSE);

            InvalidateRect(tbl->hwnd, NULL, TRUE);

            khui_check_radio_action(khui_find_menu(KHUI_MENU_LAYOUT), 
                                    KHUI_ACTION_LAYOUT_LOC);
            kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);
        }
        break;

    case KHUI_ACTION_LAYOUT_TYPE:
        {
            cw_save_view(tbl, NULL);
            cw_unload_view(tbl);

            cw_load_view(tbl, L"ByType", hwnd);
            cw_insert_header_cols(tbl);

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, FALSE);

            InvalidateRect(tbl->hwnd, NULL, TRUE);

            khui_check_radio_action(khui_find_menu(KHUI_MENU_LAYOUT), 
                                    KHUI_ACTION_LAYOUT_TYPE);
            kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);
        }
        break;

    case KHUI_ACTION_LAYOUT_CUST:
        {
            cw_save_view(tbl, NULL);
            cw_unload_view(tbl);

            cw_load_view(tbl, L"Custom_0", hwnd);
            cw_insert_header_cols(tbl);

            cw_update_creds(tbl);
            cw_update_outline(tbl);
            cw_update_extents(tbl, FALSE);

            InvalidateRect(tbl->hwnd, NULL, TRUE);

            khui_check_radio_action(khui_find_menu(KHUI_MENU_LAYOUT),
                                    KHUI_ACTION_LAYOUT_CUST);
            kmq_post_message(KMSG_ACT, KMSG_ACT_REFRESH, 0, 0);
        }
        break;

    case KHUI_PACTION_UP:
    case KHUI_PACTION_UP_EXTEND:
    case KHUI_PACTION_UP_TOGGLE:
        { /* cursor up */
            khm_int32 new_row;
            WPARAM wp;

            new_row = tbl->cursor_row - 1;

            /* checking both bounds.  we make no assumption about the
               value of cursor_row before this message */
            if(new_row < 0)
                new_row = 0;
            if(new_row >= (int) tbl->n_rows)
                new_row = (int) tbl->n_rows - 1;

            if (LOWORD(wParam) == KHUI_PACTION_UP)
                wp = 0;
            else if (LOWORD(wParam) == KHUI_PACTION_UP_EXTEND)
                wp = MK_SHIFT;
            else if (LOWORD(wParam) == KHUI_PACTION_UP_TOGGLE)
                wp = 0; //MK_CONTROL;
#ifdef DEBUG
            else
                assert(FALSE);
#endif

            cw_select_row(tbl, new_row, wp);
            cw_ensure_row_visible(hwnd, tbl, new_row);
        }
        break;

    case KHUI_PACTION_PGUP_EXTEND:
    case KHUI_PACTION_PGUP:
        {
            khm_int32 new_row;
            WPARAM wp;
            RECT r;

            if (LOWORD(wParam) == KHUI_PACTION_PGUP_EXTEND)
                wp = MK_SHIFT;
            else
                wp = 0;

            GetClientRect(hwnd, &r);

            new_row = tbl->cursor_row -
                ((r.bottom - r.top) - tbl->header_height) / tbl->cell_height;

            if (new_row < 0)
                new_row = 0;
            if (new_row >= (int) tbl->n_rows)
                new_row = (int) tbl->n_rows - 1;

            cw_select_row(tbl, new_row, wp);
            cw_ensure_row_visible(hwnd, tbl, new_row);
        }
        break;

    case KHUI_PACTION_DOWN:
    case KHUI_PACTION_DOWN_EXTEND:
    case KHUI_PACTION_DOWN_TOGGLE:
        { /* cursor down */
            khm_int32 new_row;
            WPARAM wp;

            new_row = tbl->cursor_row + 1;

            /* checking both bounds.  we make no assumption about the
               value of cursor_row before this message */
            if(new_row < 0)
                new_row = 0;
            if(new_row >= (int) tbl->n_rows)
                new_row = (int) tbl->n_rows - 1;

            if (LOWORD(wParam) == KHUI_PACTION_DOWN)
                wp = 0;
            else if (LOWORD(wParam) == KHUI_PACTION_DOWN_EXTEND)
                wp = MK_SHIFT;
            else if (LOWORD(wParam) == KHUI_PACTION_DOWN_TOGGLE)
                wp = 0; //MK_CONTROL;
#ifdef DEBUG
            else
                assert(FALSE);
#endif
            cw_select_row(tbl, new_row, wp);
            cw_ensure_row_visible(hwnd, tbl, new_row);
        }
        break;

    case KHUI_PACTION_PGDN_EXTEND:
    case KHUI_PACTION_PGDN:
        {
            khm_int32 new_row;
            RECT r;
            WPARAM wp;

            if (LOWORD(wParam) == KHUI_PACTION_PGDN_EXTEND)
                wp = MK_SHIFT;
            else
                wp = 0;

            GetClientRect(hwnd, &r);

            new_row = tbl->cursor_row +
                ((r.bottom - r.top) - tbl->header_height) / tbl->cell_height;

            if (new_row < 0)
                new_row = 0;
            if (new_row >= (int) tbl->n_rows)
                new_row = (int) tbl->n_rows - 1;

            cw_select_row(tbl, new_row, wp);
            cw_ensure_row_visible(hwnd, tbl, new_row);
        }
        break;

    case KHUI_PACTION_SELALL:
        {
            cw_select_all(tbl);
        }
        break;

    case KHUI_PACTION_LEFT:
        { /* collapse and up*/
            khui_credwnd_outline * o;
            int r;

            if(tbl->cursor_row < 0 || tbl->cursor_row >= (int) tbl->n_rows) {
                cw_select_row(tbl, 0, 0);
                break;
            }

            for(r = tbl->cursor_row; 
                (r >= 0 && !(tbl->rows[r].flags & KHUI_CW_ROW_HEADER));
                r--);
            
            if(r < 0)
                break;

            /* If we were not on a header, we collapse the innermost
               outline. Otherwise, we collpase up to the parent
               outline level */

            if(r != tbl->cursor_row) {
                o = (khui_credwnd_outline *) tbl->rows[r].data;

                cw_toggle_outline_state(tbl, o);
            } else {
                o = (khui_credwnd_outline *) tbl->rows[r].data;

                if(o->flags & KHUI_CW_O_EXPAND) {
                    cw_toggle_outline_state(tbl, o);
                } else {
                    o = TPARENT(o);
                    if(o) {
                        cw_toggle_outline_state(tbl, o);
                        r = o->start;
                    } else if(r > 0)
                        r--;
                }
            }

            cw_select_row(tbl, r, 0);
        }
        break;

    case KHUI_PACTION_RIGHT:
        { /* expand and down*/
            khui_credwnd_outline * o;
            int r;

            if(tbl->cursor_row < 0 || 
               tbl->cursor_row >= (int) tbl->n_rows) {
                cw_select_row(tbl, 0, 0);
                break;
            }

            r = tbl->cursor_row;

            if(tbl->rows[r].flags & KHUI_CW_ROW_HEADER) {
                o = (khui_credwnd_outline *) tbl->rows[r].data;
                if(!(o->flags & KHUI_CW_O_EXPAND)) {
                    cw_toggle_outline_state(tbl, o);
                }
            }

            r++;
            if (r >= (int) tbl->n_rows)
                r = (int)tbl->n_rows - 1;

            cw_select_row(tbl, r, 0);
        }
        break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT 
cw_wm_contextmenu(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    RECT r;
    int x,y;
    int row;
    khui_credwnd_tbl * tbl;

    tbl = (khui_credwnd_tbl *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);

    GetWindowRect(hwnd, &r);

    x = GET_X_LPARAM(lParam);
    y = GET_Y_LPARAM(lParam);

    x += tbl->scr_left - r.left;
    y += tbl->scr_top - tbl->header_height - r.top;

    if (y < 0) {
        /* context menu for header control */
        khm_menu_show_panel(KHUI_MENU_CWHEADER_CTX,
                            GET_X_LPARAM(lParam),
                            GET_Y_LPARAM(lParam));

        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    row = y / tbl->cell_height;

    if(row < 0 || row >= (int) tbl->n_rows)
        return FALSE;

    cw_set_row_context(tbl, row);

    if((tbl->rows[row].flags & KHUI_CW_ROW_HEADER) &&
        (tbl->cols[tbl->rows[row].col].attr_id == KCDB_ATTR_ID_NAME))
    {
        khm_menu_show_panel(KHUI_MENU_IDENT_CTX, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
        //khui_context_reset();
    } else {
        khm_menu_show_panel(KHUI_MENU_TOK_CTX, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
        //khui_context_reset();
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

/* copy and paste template */
#if 0
LRESULT 
cw_wm_msg(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
#endif

LRESULT CALLBACK 
khm_credwnd_proc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) 
{
    switch(uMsg) {
    case WM_COMMAND:
        return cw_wm_command(hwnd, uMsg, wParam, lParam);

    case WM_CREATE:
        return cw_wm_create(hwnd, uMsg, wParam, lParam);

    case WM_DESTROY:
        return cw_wm_destroy(hwnd, uMsg, wParam, lParam);

    case WM_ERASEBKGND:
        /* we don't bother wasting cycles erasing the background
           because the foreground elements completely cover the
           client area */
        return TRUE;

    case WM_PAINT:
        return cw_wm_paint(hwnd, uMsg, wParam, lParam);

    case WM_SIZE:
        return cw_wm_size(hwnd, uMsg, wParam, lParam);

    case WM_NOTIFY:
        return cw_wm_notify(hwnd, uMsg, wParam, lParam);

    case WM_HSCROLL:
        return cw_wm_hscroll(hwnd, uMsg, wParam, lParam);

    case WM_VSCROLL:
        return cw_wm_vscroll(hwnd, uMsg, wParam, lParam);

    case KMQ_WM_DISPATCH:
        return cw_kmq_wm_dispatch(hwnd, uMsg, wParam, lParam);

    case WM_LBUTTONDBLCLK:
    case WM_LBUTTONDOWN:
    case WM_MOUSEMOVE:
    case WM_LBUTTONUP:
        return cw_wm_mouse(hwnd, uMsg, wParam, lParam);

    case WM_CONTEXTMENU:
        return cw_wm_contextmenu(hwnd, uMsg, wParam, lParam);
    }

    return DefWindowProc(hwnd,uMsg,wParam,lParam);
}

void 
khm_register_credwnd_class(void) {
    WNDCLASSEX wcx;
    kcdb_attrib attrib;
    khm_int32 attr_id;

    wcx.cbSize = sizeof(wcx);
    wcx.style = CS_DBLCLKS | CS_OWNDC;
    wcx.lpfnWndProc = khm_credwnd_proc;
    wcx.cbClsExtra = 0;
    wcx.cbWndExtra = sizeof(LONG_PTR);
    wcx.hInstance = khm_hInstance;
    wcx.hIcon = NULL;
    wcx.hCursor = LoadCursor((HINSTANCE) NULL, IDC_ARROW);
    wcx.hbrBackground = (HBRUSH) (COLOR_BACKGROUND + 1);
    wcx.lpszMenuName = NULL;
    wcx.lpszClassName = KHUI_CREDWND_CLASS_NAME;
    wcx.hIconSm = NULL;

    khui_credwnd_cls = RegisterClassEx(&wcx);

    /* while we are at it, register the credwnd attribute type as well, and
    obtain the type ID */
    if(KHM_FAILED(kcdb_attrib_get_id(KHUI_CREDWND_FLAG_ATTRNAME, &attr_id))) {
        ZeroMemory(&attrib, sizeof(attrib));
        attrib.id = KCDB_ATTR_INVALID;
        attrib.flags = KCDB_ATTR_FLAG_HIDDEN;
        attrib.type = KCDB_TYPE_INT32;
        attrib.name = KHUI_CREDWND_FLAG_ATTRNAME;

        kcdb_attrib_register(&attrib, &attr_id);
    }

    khui_cw_flag_id = attr_id;
}

void 
khm_unregister_credwnd_class(void) {
    UnregisterClass(MAKEINTATOM(khui_credwnd_cls), khm_hInstance);
}

HWND 
khm_create_credwnd(HWND parent) {
    RECT r;
    HWND hwnd;

    ZeroMemory(attr_to_action, sizeof(attr_to_action));

    GetClientRect(parent, &r);

    hwnd = CreateWindowEx
        (0,
         MAKEINTATOM(khui_credwnd_cls),
         L"",
         WS_CHILD | WS_VISIBLE | WS_HSCROLL | WS_VSCROLL,
         r.left,
         r.top,
         r.right - r.left,
         r.bottom - r.top,
         parent,
         NULL,
         khm_hInstance,
         NULL);

    return hwnd;
}
