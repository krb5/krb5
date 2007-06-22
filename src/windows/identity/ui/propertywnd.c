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

typedef struct tag_pw_data {
    khm_handle record;
    HWND    hwnd_lv;
} pw_data;

ATOM khui_propertywnd_cls;

#define ID_LISTVIEW 1

#define PW_WM_SET_RECORD WM_USER

void pw_update_property_data(HWND hw, pw_data * d)
{
    HWND hwnd_lv;
    khm_int32 * attrs = NULL;

    hwnd_lv = d->hwnd_lv;

    if(hwnd_lv == NULL)
        return;

    ListView_DeleteAllItems(hwnd_lv);

    if(d->record != NULL) {
        wchar_t * buffer;
        khm_size attr_count;
        khm_size i;
        khm_size cb_buf;
        khm_size t;
        LVITEM lvi;
        int idx;

        if(KHM_FAILED(kcdb_attrib_get_count(
            KCDB_ATTR_FLAG_VOLATILE |
            KCDB_ATTR_FLAG_HIDDEN,
            0,
            &attr_count)))
            return;

        attrs = PMALLOC(sizeof(khm_int32) * attr_count);
        assert(attrs != NULL);

        kcdb_attrib_get_ids(
            KCDB_ATTR_FLAG_VOLATILE |
            KCDB_ATTR_FLAG_HIDDEN,
            0,
            attrs,
            &attr_count);

        cb_buf = sizeof(wchar_t) * 2048;
        buffer = PMALLOC(cb_buf);
        assert(buffer != NULL);

        for(i=0; i<attr_count; i++) {
            if(KHM_FAILED(kcdb_buf_get_attr(d->record, attrs[i], NULL, NULL, NULL)))
                continue;

            ZeroMemory(&lvi, sizeof(lvi));
            lvi.mask = LVIF_TEXT | LVIF_PARAM;
            lvi.iItem = (int) i;
            lvi.iSubItem = 0;
            lvi.pszText = buffer;
            lvi.lParam = (LPARAM) attrs[i];

            t = cb_buf;
            kcdb_attrib_describe(attrs[i], buffer, &t, KCDB_TS_SHORT);

            idx = ListView_InsertItem(hwnd_lv, &lvi);

            ZeroMemory(&lvi, sizeof(lvi));
            lvi.mask = LVIF_TEXT;
            lvi.iItem = idx;
            lvi.iSubItem = 1;
            lvi.pszText = buffer;

            t = cb_buf;
            kcdb_buf_get_attr_string(d->record, attrs[i], buffer, &t, 0);

            ListView_SetItem(hwnd_lv, &lvi);
        }

        PFREE(attrs);
        PFREE(buffer);
    }
}

LRESULT CALLBACK khui_property_wnd_proc(
    HWND hwnd,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam)
{
    BOOL child_msg = FALSE;
    pw_data * child;

    switch(msg) {
        case WM_CREATE: 
            {
                CREATESTRUCT * cs;
                LVCOLUMN lvc;
                wchar_t sz_title[256];

                cs = (CREATESTRUCT *) lParam;

                child = PMALLOC(sizeof(*child));
                ZeroMemory(child, sizeof(*child));

#pragma warning(push)
#pragma warning(disable:4244)
                SetWindowLongPtr(hwnd, 0, (LONG_PTR) child);
#pragma warning(pop)

                child->hwnd_lv = CreateWindow(
                    WC_LISTVIEW, 
                    L"",
                    WS_CHILD | WS_VISIBLE | WS_HSCROLL | WS_VSCROLL |
                    LVS_REPORT | LVS_SORTASCENDING,
                    0, 0,
                    cs->cx, cs->cy,
                    hwnd, 
                    (HMENU) ID_LISTVIEW, 
                    khm_hInstance, 
                    NULL);

                ListView_SetExtendedListViewStyle(child->hwnd_lv, 
                    LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

                ZeroMemory(&lvc, sizeof(lvc));
                lvc.mask = LVCF_FMT | LVCF_ORDER | LVCF_TEXT | LVCF_WIDTH;
                lvc.fmt = LVCFMT_LEFT;
                lvc.cx = (cs->cx * 2)/ 5;
                lvc.pszText = sz_title;
                lvc.iSubItem = 0;
                lvc.iOrder = 0;
                LoadString(khm_hInstance, IDS_PROP_COL_PROPERTY, sz_title, ARRAYLENGTH(sz_title));

                ListView_InsertColumn(child->hwnd_lv, 0, &lvc);

                ZeroMemory(&lvc, sizeof(lvc));
                lvc.mask = LVCF_FMT | LVCF_ORDER | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
                lvc.fmt = LVCFMT_LEFT;
                lvc.cx = (cs->cx * 3)/ 5;
                lvc.pszText = sz_title;
                lvc.iSubItem = 1;
                lvc.iOrder = 1;
                LoadString(khm_hInstance, IDS_PROP_COL_VALUE, sz_title, ARRAYLENGTH(sz_title));

                ListView_InsertColumn(child->hwnd_lv, 1, &lvc);

                if(cs->lpCreateParams != NULL) {
                    child->record = cs->lpCreateParams;
                    kcdb_buf_hold(child->record);
                    pw_update_property_data(hwnd, child);
                }
            }
            break;

        case PW_WM_SET_RECORD:
            {
                child = (pw_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);
                if (child == NULL)
                    break;

                kcdb_buf_release(child->record);
                child->record = (khm_handle) lParam;
                kcdb_buf_hold(child->record);
                pw_update_property_data(hwnd, child);
            }
            return 0;

        case WM_DESTROY:
            {
                child = (pw_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);
                if (child) {
                    kcdb_buf_release(child->record);
                    PFREE(child);
                    SetWindowLongPtr(hwnd, 0, 0);
                }
            }
            break;

        case WM_PAINT:
            break;

        default:
            child = (pw_data *)(LONG_PTR) GetWindowLongPtr(hwnd, 0);
            child_msg = TRUE;
    }

    /*
    if(child_msg && child && child->hwnd_lv)
        return SendMessage(child->hwnd_lv, msg, wParam, lParam);
    else
    */
        return DefWindowProc(hwnd, msg, wParam, lParam);
}

khm_int32 khm_register_propertywnd_class(void)
{
    WNDCLASSEX wcx;

    wcx.cbSize = sizeof(wcx);
    wcx.style = CS_DBLCLKS;
    wcx.lpfnWndProc = khui_property_wnd_proc;
    wcx.cbClsExtra = 0;
    wcx.cbWndExtra = sizeof(LONG_PTR);
    wcx.hInstance = khm_hInstance;
    wcx.hIcon = NULL;
    wcx.hCursor = LoadCursor((HINSTANCE) NULL, IDC_ARROW);
    wcx.hbrBackground = (HBRUSH) (COLOR_BTNFACE + 1);
    wcx.lpszMenuName = NULL;
    wcx.lpszClassName = KHUI_PROPERTYWND_CLASS_NAME;
    wcx.hIconSm = NULL;

    khui_propertywnd_cls = RegisterClassEx(&wcx);

    return (khui_propertywnd_cls == 0)?KHM_ERROR_UNKNOWN:KHM_ERROR_SUCCESS;
}

khm_int32 khm_unregister_propertywnd_class(void)
{
    UnregisterClass(MAKEINTATOM(khui_propertywnd_cls), khm_hInstance);

    return KHM_ERROR_SUCCESS;
}
