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

#include<khuidefs.h>
#ifdef DEBUG
#include<assert.h>
#endif

KHMEXP khm_int32 KHMAPI khui_ps_create_sheet(khui_property_sheet ** sheet)
{
    khui_property_sheet * ps;

    ps = malloc(sizeof(*ps));
    ZeroMemory(ps, sizeof(*ps));

    ps->header.dwSize = sizeof(ps->header);
    ps->header.dwFlags = PSH_MODELESS | PSH_PROPTITLE;
    ps->status = KHUI_PS_STATUS_NONE;

    *sheet = ps;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI khui_ps_add_page(
    khui_property_sheet * sheet,
    khm_int32 credtype,
    khm_int32 ordinal,
    LPPROPSHEETPAGE ppage,
    khui_property_page ** page)
{
    khui_property_page * p;

    p = malloc(sizeof(*p));
    ZeroMemory(p, sizeof(*p));

    p->credtype = credtype;
    p->ordinal = ordinal;
    p->p_page = ppage;
    
    QPUT(sheet, p);
    sheet->n_pages++;

    if(page)
        *page = p;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI khui_ps_find_page(
    khui_property_sheet * sheet,
    khm_int32 credtype,
    khui_property_page ** page)
{
    khui_property_page * p;

    p = QTOP(sheet);

    while(p) {
        if(p->credtype == credtype)
            break;
        p = QNEXT(p);
    }

    if(p) {
        *page = p;
        return KHM_ERROR_SUCCESS;
    } else {
        *page = NULL;
        return KHM_ERROR_NOT_FOUND;
    }
}

int __cdecl ps_order_func(const void *l, const void * r) {
  /* l is a ** */
    return 0;
}

KHMEXP HWND KHMAPI khui_ps_show_sheet(HWND parent, khui_property_sheet * s)
{
    khui_property_page * p;
    HPROPSHEETPAGE phpsp[KHUI_PS_MAX_PSP];
    khui_property_page * ppgs[KHUI_PS_MAX_PSP];
    int i;
    INT_PTR prv;
    HWND hw;

    s->header.hwndParent = parent;
    s->header.nPages = s->n_pages;

    p = QTOP(s);
    i = 0;
    while(p) {
        p->h_page = CreatePropertySheetPage(p->p_page);
#ifdef DEBUG
        assert(p->h_page);
#endif
        ppgs[i] = p;
        phpsp[i++] = p->h_page;
        p = QNEXT(p);
    }

    /*TODO: sort property sheets */

    s->header.phpage = phpsp;

    prv = PropertySheet(&s->header);
    if(prv <= 0) {
#ifdef DEBUG
        assert(FALSE);
#endif
        /*TODO: better handling for this */
        hw = NULL;
    } else {
        DWORD dw;

        dw = GetLastError();
        s->status = KHUI_PS_STATUS_RUNNING;

        hw = (HWND) prv;
        s->hwnd = hw;
        s->hwnd_page = PropSheet_GetCurrentPageHwnd(hw);
    }

    return hw;
}

KHMEXP LRESULT KHMAPI khui_ps_check_message(
    khui_property_sheet * sheet, 
    PMSG pmsg)
{
    LRESULT lr;

    if(sheet->hwnd == NULL)
        return FALSE;

    lr = PropSheet_IsDialogMessage(sheet->hwnd, pmsg);
    if(lr) {
        sheet->hwnd_page = PropSheet_GetCurrentPageHwnd(sheet->hwnd);
        if(sheet->hwnd_page == NULL && 
           sheet->status == KHUI_PS_STATUS_RUNNING)

            sheet->status = KHUI_PS_STATUS_DONE;
    }

    return lr;
}

KHMEXP khm_int32 KHMAPI khui_ps_destroy_sheet(khui_property_sheet * sheet)
{
    khui_property_page * p;

    DestroyWindow(sheet->hwnd);
    sheet->hwnd = NULL;

    QGET(sheet, &p);
    while(p) {
        free(p);
        QGET(sheet, &p);
    }

    free(sheet);

    return KHM_ERROR_SUCCESS;
}
